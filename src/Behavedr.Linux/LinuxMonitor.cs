namespace Behavedr.Linux;

using Behavedr.Core.Platform;
using Behavedr.Core.Models;

public class LinuxMonitor : IPlatformMonitor
{
    public bool IsSupported => OperatingSystem.IsLinux();

    public async Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        // eBPF / auditd / fanotify stubs
        return new List<Signal> { new Signal("file_access", 35, 0.7) };
    }
}
