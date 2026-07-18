namespace Behavedr.Windows;

using Behavedr.Core.Platform;
using Behavedr.Core.Models;

public class WindowsMonitor : IPlatformMonitor
{
    public bool IsSupported => OperatingSystem.IsWindows();

    public async Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // ETW/WMI stubs - expand with real behavioral hooks
        return new List<Signal> { new Signal("process_injection", 40, 0.8) };
    }
}
