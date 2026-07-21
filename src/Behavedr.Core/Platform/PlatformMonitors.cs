namespace Behavedr.Core.Platform;

using Behavedr.Core.Monitors;

/// <summary>
/// Catalog of all Behavedr platform monitors (desktop + mobile).
/// </summary>
public static class PlatformMonitors
{
    /// <summary>Every known platform monitor (supported or not).</summary>
    public static IReadOnlyList<IPlatformMonitor> All { get; } = BuildMonitorList();

    private static List<IPlatformMonitor> BuildMonitorList()
    {
        var monitors = new List<IPlatformMonitor>
        {
            // Platform-specific process monitors
            new WindowsMonitor(),
            new LinuxMonitor(),
            new MacOSMonitor(),
            new AndroidMonitor(),
            new IosMonitor(),

            // v0.0.7: Cross-platform monitors
            new FileActivityMonitor(),
            new ConnectivityCanaryMonitor(),
        };

        // v0.0.7+: Windows-only behavioral detection & anti-tamper monitors
        if (OperatingSystem.IsWindows())
        {
            monitors.Add(new BehavioralMonitor());
            monitors.Add(new AntiTamperGuard());
            monitors.Add(new NetworkConnectionMonitor());
            monitors.Add(new MemoryAnalyzer());
            monitors.Add(new BeaconingDetector());
            monitors.Add(new CredentialGuardMonitor());
            monitors.Add(new CredentialCanaryMonitor());
            monitors.Add(new RegistryPersistenceMonitor());

            // v0.0.9: New monitors from audit remediation
            monitors.Add(new DnsQueryMonitor());
            monitors.Add(new DataExfiltrationMonitor());
        }

        return monitors;
    }

    /// <summary>Monitors whose <see cref="IPlatformMonitor.IsSupported"/> is true on this OS.</summary>
    public static IEnumerable<IPlatformMonitor> Supported() =>
        All.Where(m => m.IsSupported);

    public static string CurrentPlatformSummary()
    {
        if (OperatingSystem.IsWindows()) return "Windows";
        if (OperatingSystem.IsLinux()) return "Linux";
        if (OperatingSystem.IsMacOS()) return "macOS";
        if (OperatingSystem.IsAndroid()) return "Android";
        if (OperatingSystem.IsIOS()) return "iOS";
        if (OperatingSystem.IsMacCatalyst()) return "Mac Catalyst";
        return "Unknown";
    }
}
