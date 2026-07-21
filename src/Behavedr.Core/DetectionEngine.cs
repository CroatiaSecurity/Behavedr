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
    private readonly SignalDeduplicator _deduplicator;
    private readonly List<IPlatformMonitor> _monitors = new();
    private readonly ILogger<DetectionEngine> _logger;

    public DetectionEngine(ScoringEngine? scoring = null, BehavioralCorrelationEngine? correlation = null, ILogger<DetectionEngine>? logger = null)
    {
        _scoring = scoring ?? new ScoringEngine();
        _correlation = correlation ?? new BehavioralCorrelationEngine();
        _deduplicator = new SignalDeduplicator();
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

        // Deduplicate signals within this cycle
        signals = _deduplicator.DeduplicateWithinCycle(signals);

        // Run behavioral correlation to produce composite signals
        var composites = _correlation.Correlate(signals);
        if (composites.Count > 0)
        {
            signals.AddRange(composites);
            _logger.LogInformation("Correlation engine produced {Count} composite signals", composites.Count);
        }

        // Apply cross-cycle cooldown suppression
        signals = _deduplicator.ApplyCooldown(signals, evt.ProcessId);

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
    /// Runs monitors concurrently with per-monitor timeout to prevent slow monitors
    /// from blocking the detection cycle.
    /// </summary>
    private async Task<List<Signal>> CollectSignalsAsync(CancellationToken ct)
    {
        var allSignals = new List<Signal>();
        var monitorTimeout = TimeSpan.FromSeconds(10);

        // Run all supported monitors concurrently
        var tasks = _monitors
            .Where(m => m.IsSupported)
            .Select(async monitor =>
            {
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(monitorTimeout);

                    var signals = await monitor.GetSignalsAsync(timeoutCts.Token);
                    return (monitor, signals: signals.ToList(), error: (Exception?)null);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    _logger.LogWarning("Monitor {Monitor} timed out after {Timeout}s",
                        monitor.PlatformName, monitorTimeout.TotalSeconds);
                    return (monitor, signals: new List<Signal>(), error: (Exception?)null);
                }
                catch (OperationCanceledException)
                {
                    throw; // Propagate real cancellation
                }
                catch (Exception ex)
                {
                    return (monitor, signals: new List<Signal>(), error: ex);
                }
            })
            .ToList();

        var results = await Task.WhenAll(tasks);

        foreach (var (monitor, signals, error) in results)
        {
            if (error is not null)
            {
                _logger.LogError(error, "Failed to collect signals from {Monitor}", monitor.PlatformName);
                continue;
            }

            allSignals.AddRange(signals);
            _logger.LogDebug("Collected {Count} signals from {Monitor}",
                signals.Count, monitor.PlatformName);
        }

        return allSignals;
    }
}

public record DetectionResult(DetectionEvent Event, double Score, bool PresidentKill, List<Signal> Signals);
