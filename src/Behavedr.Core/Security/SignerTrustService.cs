namespace Behavedr.Core.Security;

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Authenticode signature verification service with write-time cache invalidation.
/// Being signed does NOT grant trust or immunity — it lowers detection confidence.
/// Used to harden allowlist decisions beyond name-only matching (T1036.005 defense).
/// </summary>
public class SignerTrustService
{
    private readonly ILogger<SignerTrustService> _logger;
    private readonly ConcurrentDictionary<string, (bool IsSigned, DateTime LastWrite)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public SignerTrustService(ILogger<SignerTrustService>? logger = null)
    {
        _logger = logger ?? NullLogger<SignerTrustService>.Instance;
    }

    /// <summary>
    /// Returns true if the file has a valid Authenticode signature.
    /// Does NOT mean the file is trusted — only that it's signed.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsSignedFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return false;

        if (_cache.TryGetValue(filePath, out var cached))
        {
            try
            {
                var currentWrite = File.GetLastWriteTimeUtc(filePath);
                if (currentWrite == cached.LastWrite) return cached.IsSigned;
                _cache.TryRemove(filePath, out _);
            }
            catch { return cached.IsSigned; }
        }

        bool isSigned = VerifyAuthenticode(filePath);
        DateTime writeTime = DateTime.MinValue;
        try { writeTime = File.GetLastWriteTimeUtc(filePath); } catch { }
        _cache[filePath] = (isSigned, writeTime);
        return isSigned;
    }

    /// <summary>
    /// Returns true if the process at the given PID has a valid Authenticode signature.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsSignedProcess(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            var path = proc.MainModule?.FileName;
            return !string.IsNullOrEmpty(path) && IsSignedFile(path);
        }
        catch { return false; }
    }

    /// <summary>
    /// Verify a file is in a trusted system path AND is signed.
    /// This is the proper dual-gate for allowlist verification.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public bool IsTrustedSystemBinary(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        return IsInSystemDirectory(filePath) && IsSignedFile(filePath);
    }

    private static bool IsInSystemDirectory(string path)
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) return false;
        var winDirSlash = winDir.TrimEnd('\\') + "\\";
        return path.StartsWith(winDirSlash, StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyAuthenticode(string filePath)
    {
        try
        {
            // Use WinVerifyTrust via PowerShell Get-AuthenticodeSignature as a simple approach
            // that avoids the obsolete X509Certificate.CreateFromSignedFile API on .NET 10.
            // For production, consider direct WinVerifyTrust P/Invoke.
            using var proc = new System.Diagnostics.Process();
            proc.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -Command \"(Get-AuthenticodeSignature '{filePath.Replace("'", "''")}').Status -eq 'Valid'\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };
            proc.Start();
            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit(5000);
            return output.Equals("True", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
