namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// Android behavioral signals (Accessibility / UsageStats / package install stubs).
/// </summary>
public class AndroidMonitor : IPlatformMonitor
{
    public string PlatformName => "Android";

    public bool IsSupported => OperatingSystem.IsAndroid();

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // Accessibility service abuse, overlay windows, sideloaded packages, SMS/call intercept stubs
        IEnumerable<Signal> signals =
        [
            new Signal("android_accessibility_abuse", 42, 0.75),
            new Signal("android_overlay_window", 38, 0.7),
            new Signal("android_package_install", 35, 0.65),
        ];
        return Task.FromResult(signals);
    }
}
