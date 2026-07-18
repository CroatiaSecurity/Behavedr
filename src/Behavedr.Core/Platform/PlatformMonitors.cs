namespace Behavedr.Core.Platform;

using Behavedr.Core.Monitors;

/// <summary>
/// Catalog of all Behavedr platform monitors (desktop + mobile).
/// </summary>
public static class PlatformMonitors
{
    /// <summary>Every known platform monitor (supported or not).</summary>
    public static IReadOnlyList<IPlatformMonitor> All { get; } =
    [
        new WindowsMonitor(),
        new LinuxMonitor(),
        new MacOSMonitor(),
        new AndroidMonitor(),
        new IosMonitor(),
    ];

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
