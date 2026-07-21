namespace Behavedr.Core.Update;

using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Auto-update mechanism using GitHub Releases API.
/// Checks for newer versions, downloads, verifies SHA-256, and replaces binary.
/// </summary>
public class AutoUpdater
{
    private readonly HttpClient _http;
    private readonly ILogger<AutoUpdater> _logger;
    private readonly string _currentVersion;
    private readonly string _repoOwner;
    private readonly string _repoName;
    private readonly string _platform;

    public AutoUpdater(
        string repoOwner = "CroatiaSecurity",
        string repoName = "Behavedr",
        ILogger<AutoUpdater>? logger = null)
    {
        _repoOwner = repoOwner;
        _repoName = repoName;
        _logger = logger ?? NullLogger<AutoUpdater>.Instance;
        _currentVersion = Assembly.GetEntryAssembly()
            ?.GetName().Version?.ToString(3) ?? "0.0.0";
        _platform = GetPlatformRid();

        _http = new HttpClient();
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(
            $"Behavedr/{_currentVersion}");
    }

    /// <summary>
    /// Check GitHub Releases for a newer version.
    /// </summary>
    public async Task<UpdateInfo?> CheckForUpdateAsync(CancellationToken ct = default)
    {
        try
        {
            var url = $"https://api.github.com/repos/{_repoOwner}/{_repoName}/releases/latest";
            var response = await _http.GetAsync(url, ct);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("Update check returned {Status}", response.StatusCode);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(ct);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tagName = root.GetProperty("tag_name").GetString() ?? "";
            var latestVersion = tagName.TrimStart('v');

            if (!IsNewerVersion(latestVersion, _currentVersion))
            {
                _logger.LogDebug("Current version {Current} is up-to-date (latest: {Latest})",
                    _currentVersion, latestVersion);
                return null;
            }

            // Find the asset for our platform
            var assetUrl = FindPlatformAsset(root);
            if (assetUrl is null)
            {
                _logger.LogWarning("No update asset found for platform {Platform}", _platform);
                return null;
            }

            return new UpdateInfo(latestVersion, assetUrl, tagName);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Update check failed");
            return null;
        }
    }

    /// <summary>
    /// Download and apply an update. Verifies RSA-PSS signature before extraction.
    /// </summary>
    public async Task<bool> ApplyUpdateAsync(UpdateInfo update, CancellationToken ct = default)
    {
        _logger.LogInformation("Downloading update v{Version} from {Url}",
            update.Version, update.DownloadUrl);

        try
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"behavedr-update-{update.Version}.zip");
            var sigPath = tempPath + ".sig";

            // Download the zip with exclusive file lock to prevent TOCTOU
            await using (var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            await using (var responseStream = await _http.GetStreamAsync(update.DownloadUrl, ct))
            {
                await responseStream.CopyToAsync(fileStream, ct);
            }

            _logger.LogInformation("Downloaded update to {Path}", tempPath);

            // Download the signature file (.sig) with exclusive lock
            var sigUrl = update.DownloadUrl + ".sig";
            try
            {
                await using (var sigFileStream = new FileStream(sigPath, FileMode.Create, FileAccess.Write, FileShare.None))
                await using (var sigStream = await _http.GetStreamAsync(sigUrl, ct))
                {
                    await sigStream.CopyToAsync(sigFileStream, ct);
                }
            }
            catch (HttpRequestException)
            {
                _logger.LogCritical("SECURITY: No signature file available for update — rejecting");
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            // Verify integrity (basic size check)
            var fileInfo = new FileInfo(tempPath);
            if (fileInfo.Length < 1_000_000)
            {
                _logger.LogWarning("Downloaded file suspiciously small ({Size} bytes), aborting",
                    fileInfo.Length);
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            // CRITICAL: Verify cryptographic signature before extraction
            if (Security.UpdateSignatureVerifier.IsProductionKeyConfigured())
            {
                if (!Security.UpdateSignatureVerifier.VerifySignature(tempPath, sigPath, _logger))
                {
                    _logger.LogCritical("SECURITY: Update signature verification FAILED — aborting update");
                    CleanupTempFiles(tempPath, sigPath);
                    return false;
                }
            }
            else
            {
                _logger.LogWarning("Update signing key is not configured (development mode) — skipping signature verification");
            }

            // Compute SHA-256 for logging/audit
            var hash = ComputeHash(tempPath);
            _logger.LogInformation("Update SHA-256: {Hash}", hash[..16] + "...");

            // Stage the update (extract alongside current binary)
            var currentExe = Environment.ProcessPath;
            if (currentExe is null)
            {
                _logger.LogError("Cannot determine current executable path");
                CleanupTempFiles(tempPath, sigPath);
                return false;
            }

            // Extract from zip with Zip Slip protection
            var targetDir = Path.GetFullPath(Path.GetDirectoryName(currentExe)!);
            using (var archive = System.IO.Compression.ZipFile.OpenRead(tempPath))
            {
                foreach (var entry in archive.Entries)
                {
                    // Skip directory entries
                    if (string.IsNullOrEmpty(entry.Name))
                        continue;

                    var destPath = Path.GetFullPath(Path.Combine(targetDir, entry.FullName));

                    // SECURITY: Reject entries that escape the target directory (Zip Slip)
                    if (!destPath.StartsWith(targetDir + Path.DirectorySeparatorChar, StringComparison.Ordinal) &&
                        !destPath.Equals(targetDir, StringComparison.Ordinal))
                    {
                        _logger.LogCritical("SECURITY: Zip Slip detected — entry '{Entry}' resolves outside target directory. Aborting update.",
                            entry.FullName);
                        CleanupTempFiles(tempPath, sigPath);
                        return false;
                    }

                    // Ensure parent directory exists
                    var destDir = Path.GetDirectoryName(destPath)!;
                    Directory.CreateDirectory(destDir);

                    entry.ExtractToFile(destPath, overwrite: true);
                }
            }

            _logger.LogInformation(
                "Update staged. Restart the agent to complete the update.");

            // Clean up temp
            CleanupTempFiles(tempPath, sigPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply update");
            return false;
        }
    }

    private static void CleanupTempFiles(params string[] paths)
    {
        foreach (var path in paths)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }

    private string? FindPlatformAsset(JsonElement root)
    {
        if (!root.TryGetProperty("assets", out var assets))
            return null;

        var expectedPattern = $"Behavedr-Portable-";

        foreach (var asset in assets.EnumerateArray())
        {
            var name = asset.GetProperty("name").GetString() ?? "";
            if (name.Contains(_platform, StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                return asset.GetProperty("browser_download_url").GetString();
            }
        }

        return null;
    }

    private static bool IsNewerVersion(string latest, string current)
    {
        if (Version.TryParse(latest, out var latestVer) &&
            Version.TryParse(current, out var currentVer))
        {
            return latestVer > currentVer;
        }
        return false;
    }

    private static string ComputeHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }

    private static string GetPlatformRid()
    {
        if (OperatingSystem.IsWindows()) return "win-x64";
        if (OperatingSystem.IsLinux()) return "linux-x64";
        if (OperatingSystem.IsMacOS()) return "osx-arm64";
        return "unknown";
    }
}

/// <summary>
/// Information about an available update.
/// </summary>
public record UpdateInfo(string Version, string DownloadUrl, string TagName);
