namespace Behavedr.Core.Monitors;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;

public class LinuxMonitor : IPlatformMonitor
{
    public bool IsSupported => OperatingSystem.IsLinux();

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // eBPF / auditd / fanotify stubs
        IEnumerable<Signal> signals = [new Signal("file_access", 35, 0.7)];
        return Task.FromResult(signals);
    }
}
