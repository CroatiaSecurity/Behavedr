namespace Behavedr.Core.Platform;

public interface IPlatformMonitor
{
    Task<IEnumerable<Models.Signal>> GetSignalsAsync(CancellationToken ct = default);
    bool IsSupported { get; }
}
