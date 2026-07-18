namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// iOS behavioral signals (EndpointSecurity-class stubs within sandbox limits).
/// On consumer devices monitoring is constrained; enterprise MDM / NEFilter extend reach.
/// </summary>
public class IosMonitor : IPlatformMonitor
{
    public string PlatformName => "iOS";

    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // Background task abuse, profile install, network filter events (stubs)
        IEnumerable<Signal> signals =
        [
            new Signal("ios_background_task_abuse", 40, 0.7),
            new Signal("ios_config_profile", 45, 0.75),
            new Signal("ios_network_filter_event", 36, 0.65),
        ];
        return Task.FromResult(signals);
    }
}
