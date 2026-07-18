namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// Android behavioral monitor.
/// On Android, actual UsageStats/PackageManager calls require the Android runtime.
/// This monitor provides the cross-platform detection logic and heuristics.
/// The MAUI app must provide platform-specific data via the signal injection API.
/// 
/// When running on Android:
/// - Checks installed packages for known malware signatures
/// - Detects sideloaded apps (non-Play Store installs)
/// - Monitors accessibility service abuse indicators
/// - Detects overlay window attacks
/// </summary>
public class AndroidMonitor : IPlatformMonitor
{
    public string PlatformName => "Android";
    public bool IsSupported => OperatingSystem.IsAndroid();

    // Known malware package prefixes
    private static readonly string[] MalwarePackagePrefixes =
    [
        "com.exploit.", "com.hack.", "com.trojan.", "org.metasploit.",
        "com.termux.tasker", "com.offsec.", "com.android.systemservice",
    ];

    // Sideloaded sources (non-official)
    private static readonly string[] SideloadInstallers =
    [
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
    ];

    private readonly List<Signal> _injectedSignals = new();
    private readonly object _lock = new();

    /// <summary>
    /// Inject signals from the Android platform layer (MAUI/Java interop).
    /// Call this from the Android-specific code that has access to PackageManager, etc.
    /// </summary>
    public void InjectPlatformSignals(IEnumerable<Signal> signals)
    {
        lock (_lock)
        {
            _injectedSignals.Clear();
            _injectedSignals.AddRange(signals);
        }
    }

    [SupportedOSPlatform("android")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        lock (_lock)
        {
            // Return platform-injected signals from the Android layer
            if (_injectedSignals.Count > 0)
            {
                signals.AddRange(_injectedSignals);
            }
            else
            {
                // Fallback: basic heuristic signals when no platform data is available
                signals.Add(new Signal("android_monitoring_active", 5, 0.5));
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Analyze a package name for malware indicators.
    /// Called by the MAUI Android platform layer.
    /// </summary>
    public static IEnumerable<Signal> AnalyzePackage(string packageName, string? installerPackage, bool hasAccessibilityService, bool hasOverlayPermission)
    {
        var signals = new List<Signal>();

        // Check for known malware package prefixes
        foreach (var prefix in MalwarePackagePrefixes)
        {
            if (packageName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal($"malware_package:{packageName}", 90, 0.85));
                break;
            }
        }

        // Sideloaded app detection
        if (installerPackage is null || !installerPackage.Contains("vending", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(new Signal($"sideloaded_app:{packageName}", 35, 0.6));
        }

        // Accessibility service abuse
        if (hasAccessibilityService)
        {
            signals.Add(new Signal($"accessibility_service:{packageName}", 50, 0.7));
        }

        // Overlay permission (potential clickjacking)
        if (hasOverlayPermission)
        {
            signals.Add(new Signal($"overlay_permission:{packageName}", 40, 0.65));
        }

        return signals;
    }
}
