namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;

public class WindowsMonitor : IPlatformMonitor
{
    public string PlatformName => "Windows";

    public bool IsSupported => OperatingSystem.IsWindows();

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // ETW/WMI stubs - expand with real behavioral hooks
        IEnumerable<Signal> signals = [new Signal("process_injection", 40, 0.8)];
        return Task.FromResult(signals);
    }
}
