namespace Behavedr.MacOS;

using Behavedr.Core.Platform;
using Behavedr.Core.Models;

public class MacOSMonitor : IPlatformMonitor
{
    public bool IsSupported => OperatingSystem.IsMacOS();

    public async Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // EndpointSecurity.framework stub
        return new List<Signal> { new Signal("process_exec", 45, 0.75) };
    }
}
