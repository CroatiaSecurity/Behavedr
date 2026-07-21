namespace Behavedr.Core;

using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Main behavioral detection engine.
/// Collects signals from registered platform monitors, scores them, and decides on response.
/// </summary>
public class DetectionEngine
{
    private readonly ScoringEngine _scoring;
    private readonly BehavioralCorrelationEngine _correlation;
    private readonly List<IPlatformMonitor> _monitors = new();
    private readonly ILogger<DetectionEngine> _logger;

    public DetectionEngine(ScoringEngine? scoring = null, BehavioralCorrelationEngine? correlation = null, ILogger<DetectionEngine>? logger = null)
    {
        _scoring = scoring ?? new ScoringEngine();
        _correlation = correlation ?? new BehavioralCorrelationEngine();
        _logger = logger ?? NullLogger<DetectionEngine>.Instance;
    }

    public IReadOnlyList<IPlatformMonitor> RegisteredMonitors => _monitors;

    public void RegisterMonitor(IPlatformMonitor monitor)
    {
        ArgumentNullException.ThrowIfNull(monitor);
        _monitors.Add(monitor);
        _logger.LogInformation("Registered monitor: {MonitorType} ({Platform})", monitor.GetType().Name, monitor.PlatformName);
    }

    /// <summary>
    /// Process a detection event: collect signals from all monitors, score, and determine response.
    /// </summary>
    public async Task<DetectionResult> ProcessEventAsync(DetectionEvent evt, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(evt);

        _logger.LogDebug("Processing event: {ProcessName} ({BehaviorType}) from {Source}",
            evt.ProcessName, evt.BehaviorType, evt.Source);

        var signals = await CollectSignalsAsync(ct);

        // Run behavioral correlation to produce composite signals
        var composites = _correlation.Correlate(signals);
        if (composites.Count > 0)
        {
            signals.AddRange(composites);
            _logger.LogInformation("Correlation engine produced {Count} composite signals", composites.Count);
        }

        var score = _scoring.CalculateScore(evt, signals);
        bool presidentKill = _scoring.ShouldPresidentKill(score, evt);

        var result = new DetectionResult(evt, score, presidentKill, signals);

        if (presidentKill)
        {
            _logger.LogWarning("PRESIDENT KILL triggered for {ProcessName} (score={Score:F1})",
                evt.ProcessName, score);
        }
        else if (score > 50.0)
        {
            _logger.LogInformation("High-score detection: {ProcessName} score={Score:F1}",
                evt.ProcessName, score);
        }

        return result;
    }

    /// <summary>
    /// Synchronous processing (deprecated — use ProcessEventAsync instead).
    /// </summary>
    [Obsolete("Use ProcessEventAsync instead. Sync-over-async can cause deadlocks.")]
    public DetectionResult ProcessEvent(DetectionEvent evt)
    {
        return ProcessEventAsync(evt, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Collect signals from all registered monitors that are supported on this platform.
    /// </summary>
    private async Task<List<Signal>> CollectSignalsAsync(CancellationToken ct)
    {
        var allSignals = new List<Signal>();

        foreach (var monitor in _monitors)
        {
            if (!monitor.IsSupported)
                continue;

            try
            {
                var signals = await monitor.GetSignalsAsync(ct);
                foreach (var signal in signals)
                {
                    allSignals.Add(signal);
                }

                _logger.LogDebug("Collected {Count} signals from {Monitor}",
                    allSignals.Count, monitor.PlatformName);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to collect signals from {Monitor}", monitor.PlatformName);
                // Continue with other monitors — don't let one failure block detection
            }
        }

        return allSignals;
    }
}

public record DetectionResult(DetectionEvent Event, double Score, bool PresidentKill, List<Signal> Signals);
