namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Main behavioral detection with GIDR President authority.
/// </summary>
public class DetectionEngine
{
    private readonly ScoringEngine _scoring = new();
    private readonly List<IPlatformMonitor> _monitors = new();

    public void RegisterMonitor(IPlatformMonitor monitor) => _monitors.Add(monitor);

    public DetectionResult ProcessEvent(DetectionEvent evt)
    {
        var signals = CollectSignals(evt);
        var score = _scoring.CalculateScore(evt, signals);

        bool presidentKill = _scoring.ShouldPresidentKill(score, evt);

        return new DetectionResult(evt, score, presidentKill, signals);
    }

    private List<Signal> CollectSignals(DetectionEvent evt)
    {
        // Platform-specific + correlation
        return new List<Signal>();
    }
}

public interface IPlatformMonitor { Task<IEnumerable<Signal>> MonitorAsync(); }

public record DetectionResult(DetectionEvent Event, double Score, bool PresidentKill, List<Signal> Signals);
