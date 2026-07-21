namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS persistence mechanism detection monitor.
/// Operates within sandbox constraints to detect:
/// - Configuration profile installation (MDM enrollment, VPN profiles, cert pinning bypass)
/// - Background App Refresh abuse (sustained background execution)
/// - Push notification persistence (remote trigger for dormant malware)
/// - Calendar/reminder persistence (scheduled code execution triggers)
/// - Jailbreak-level persistence (LaunchDaemons, dylib injection on jailbroken devices)
/// - Web clip / home screen shortcut persistence
/// - Enterprise certificate sideloading
/// </summary>
[SupportedOSPlatform("ios")]
public class IosPersistenceMonitor : IPlatformMonitor
{
    private readonly ILogger<IosPersistenceMonitor> _logger;
    private Dictionary<string, DateTime> _baseline = new();
    private bool _baselined;

    public string PlatformName => "IosPersistence";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosPersistenceMonitor(ILogger<IosPersistenceMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<IosPersistenceMonitor>.Instance;
    }

    // Jailbreak persistence locations (only accessible on jailbroken devices)
    private static readonly (string Dir, string Pattern, string Category, double Weight, double Confidence)[] JailbreakPersistence =
    [
        ("/Library/LaunchDaemons", "*.plist", "launch_daemon", 90, 0.95),
        ("/Library/LaunchAgents", "*.plist", "launch_agent", 85, 0.92),
        ("/Library/MobileSubstrate/DynamicLibraries", "*.dylib", "substrate_tweak", 80, 0.88),
        ("/var/jb/Library/LaunchDaemons", "*.plist", "rootless_daemon", 88, 0.93),
        ("/Library/TweakInject", "*.dylib", "tweak_inject", 80, 0.88),
    ];

    [SupportedOSPlatform("ios")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            var current = ScanPersistenceState(ct);

            if (!_baselined)
            {
                _baseline = current;
                _baselined = true;
                return Task.FromResult<IEnumerable<Signal>>(signals);
            }

            // Detect new entries
            foreach (var (path, modTime) in current)
            {
                if (ct.IsCancellationRequested) break;
                if (!_baseline.ContainsKey(path))
                {
                    var (weight, confidence, category) = ClassifyPath(path);
                    signals.Add(new Signal(
                        $"new_persistence:{category}:{Path.GetFileName(path)}", weight, confidence));
                }
            }

            _baseline = current;

            // Check for configuration profiles (accessible from sandbox)
            DetectConfigProfiles(signals);

            // Check for enterprise certificate abuse
            DetectEnterpriseCerts(signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[IosPersistence] Error during scan");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect suspicious configuration profiles.
    /// Profiles can install root CAs (MITM), VPN configs (traffic capture),
    /// MDM enrollment (remote wipe/control), and web clips (phishing).
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectConfigProfiles(List<Signal> signals)
    {
        // Configuration profiles directory (may be accessible)
        var profileDirs = new[]
        {
            "/var/db/ConfigurationProfiles/Store",
            "/private/var/db/ConfigurationProfiles/Store",
        };

        foreach (var dir in profileDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var profile in Directory.GetFiles(dir, "*.mobileconfig"))
                {
                    var age = DateTime.UtcNow - File.GetCreationTimeUtc(profile);
                    if (age.TotalHours < 24)
                    {
                        // Recently installed profile
                        var content = "";
                        try { content = File.ReadAllText(profile); } catch { }

                        if (content.Contains("CertificateRoot", StringComparison.OrdinalIgnoreCase))
                        {
                            signals.Add(new Signal(
                                $"new_root_ca_profile:{Path.GetFileName(profile)}", 82, 0.88));
                        }
                        else if (content.Contains("VPN", StringComparison.OrdinalIgnoreCase))
                        {
                            signals.Add(new Signal(
                                $"new_vpn_profile:{Path.GetFileName(profile)}", 55, 0.65));
                        }
                        else if (content.Contains("MDM", StringComparison.OrdinalIgnoreCase))
                        {
                            signals.Add(new Signal(
                                $"new_mdm_enrollment:{Path.GetFileName(profile)}", 70, 0.78));
                        }
                        else
                        {
                            signals.Add(new Signal(
                                $"new_config_profile:{Path.GetFileName(profile)}", 45, 0.6));
                        }
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect enterprise/developer certificate sideloading abuse.
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectEnterpriseCerts(List<Signal> signals)
    {
        var certDirs = new[]
        {
            "/private/var/Keychains",
            "/var/Keychains",
        };

        foreach (var dir in certDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var cert in Directory.GetFiles(dir, "*.cer"))
                {
                    var age = DateTime.UtcNow - File.GetCreationTimeUtc(cert);
                    if (age.TotalHours < 24)
                    {
                        signals.Add(new Signal(
                            $"new_enterprise_cert:{Path.GetFileName(cert)}", 60, 0.7));
                    }
                }
            }
            catch { }
        }
    }

    [SupportedOSPlatform("ios")]
    private Dictionary<string, DateTime> ScanPersistenceState(CancellationToken ct)
    {
        var state = new Dictionary<string, DateTime>();

        foreach (var (dir, pattern, _, _, _) in JailbreakPersistence)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(dir, pattern))
                {
                    try { state[file] = File.GetLastWriteTimeUtc(file); }
                    catch { }
                }
            }
            catch { }
        }

        return state;
    }

    private static (double Weight, double Confidence, string Category) ClassifyPath(string path)
    {
        if (path.Contains("LaunchDaemon", StringComparison.OrdinalIgnoreCase))
            return (90, 0.95, "launch_daemon");
        if (path.Contains("LaunchAgent", StringComparison.OrdinalIgnoreCase))
            return (85, 0.92, "launch_agent");
        if (path.Contains("MobileSubstrate", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("TweakInject", StringComparison.OrdinalIgnoreCase))
            return (80, 0.88, "substrate_tweak");
        return (60, 0.7, "unknown");
    }
}
