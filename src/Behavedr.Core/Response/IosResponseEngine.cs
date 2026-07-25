namespace Behavedr.Core.Response;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS response surface under Apple policy (0.2.8 MDM companion SKU).
/// Stock App Store apps cannot kill other apps or install packet filters without
/// Network Extension + MDM. This engine:
/// - Emits durable local quarantine metadata for suspicious files in the app container
/// - Invokes optional platform hooks (MDM signal, NE content filter) when wired by MAUI
/// - Never claims device-wide EDR powers it does not have
/// </summary>
[SupportedOSPlatform("ios")]
public sealed class IosResponseEngine : IResponseAction
{
    private readonly ILogger<IosResponseEngine> _logger;

    /// <summary>
    /// Optional MAUI/MDM hook: (processOrBundle, result, ct) → outcome message.
    /// </summary>
    public static Func<string, DetectionResult, CancellationToken, Task<string?>>? PlatformResponseHook { get; set; }

    public string Name => "IosResponse";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosResponseEngine(ILogger<IosResponseEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<IosResponseEngine>.Instance;
    }

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!IsSupported)
            return ResponseOutcome.Skipped(Name, "Not iOS");

        var parts = new List<string>();
        var bundle = result.Event.ProcessName;

        // Local quarantine of paths embedded in signals (app container only)
        foreach (var signal in result.Signals)
        {
            var path = ExtractPath(signal.Type);
            if (path is null) continue;
            if (!IsWithinSandbox(path))
            {
                parts.Add($"refuse-out-of-sandbox:{Path.GetFileName(path)}");
                continue;
            }

            try
            {
                var qDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "behavedr-quarantine");
                Directory.CreateDirectory(qDir);
                var dest = Path.Combine(qDir, $"{DateTime.UtcNow:yyyyMMddHHmmss}_{Path.GetFileName(path)}");
                if (File.Exists(path))
                {
                    File.Move(path, dest, overwrite: true);
                    File.WriteAllText(dest + ".meta.json",
                        $"{{\"src\":\"{path}\",\"score\":{result.Score},\"at\":\"{DateTime.UtcNow:O}\"}}");
                    parts.Add($"quarantined:{Path.GetFileName(path)}");
                    _logger.LogWarning("[iOS] Quarantined {Path} -> {Dest}", path, dest);
                }
            }
            catch (Exception ex)
            {
                parts.Add($"quarantine-failed:{ex.GetType().Name}");
            }
        }

        if (PlatformResponseHook is not null)
        {
            try
            {
                var msg = await PlatformResponseHook(bundle, result, ct);
                if (!string.IsNullOrEmpty(msg))
                    parts.Add(msg);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[iOS] platform hook failed");
            }
        }

        if (parts.Count == 0)
            return ResponseOutcome.Skipped(Name,
                "No sandbox quarantine targets; MDM/Network Extension hook not configured");

        return ResponseOutcome.Ok(Name, string.Join("; ", parts));
    }

    private static string? ExtractPath(string type)
    {
        foreach (var marker in new[] { "path:", "file:", "ios_file:" })
        {
            var i = type.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            var rest = type[(i + marker.Length)..];
            var end = rest.IndexOfAny(['|', ';', ' ']);
            return end > 0 ? rest[..end] : rest;
        }
        return null;
    }

    private static bool IsWithinSandbox(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return full.StartsWith(home, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(local, StringComparison.OrdinalIgnoreCase)
                || full.Contains("/Containers/Data/", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }
}
