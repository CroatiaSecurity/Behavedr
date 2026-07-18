namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;

public class MacOSMonitor : IPlatformMonitor
{
    public string PlatformName => "macOS";

    public bool IsSupported => OperatingSystem.IsMacOS();

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // EndpointSecurity.framework stub
        IEnumerable<Signal> signals = [new Signal("process_exec", 45, 0.75)];
        return Task.FromResult(signals);
    }
}
