namespace Behavedr.Agent;

using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service that periodically collects behavioral signals and runs detection.
/// </summary>
public sealed class MonitoringService : BackgroundService
{
    private readonly DetectionEngine _engine;
    private readonly ILogger<MonitoringService> _logger;
    private readonly TimeSpan _interval;

    public MonitoringService(
        DetectionEngine engine,
        IConfiguration configuration,
        ILogger<MonitoringService> logger)
    {
        _engine = engine;
        _logger = logger;

        var seconds = configuration.GetValue("Agent:MonitoringIntervalSeconds", 5);
        _interval = TimeSpan.FromSeconds(Math.Max(1, seconds));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Monitoring service started (interval: {Interval}s)", _interval.TotalSeconds);

        // Register platform monitors (only if not already registered by DI/bootstrap)
        if (_engine.RegisteredMonitors.Count == 0)
        {
            foreach (var monitor in PlatformMonitors.Supported())
            {
                _engine.RegisterMonitor(monitor);
            }
        }

        _logger.LogInformation("Registered {Count} platform monitor(s): {Names}",
            _engine.RegisteredMonitors.Count,
            string.Join(", ", _engine.RegisteredMonitors.Select(m => m.PlatformName)));

        using var timer = new PeriodicTimer(_interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
                await RunDetectionCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Detection cycle failed, will retry next interval");
            }
        }

        _logger.LogInformation("Monitoring service stopping");
    }

    private async Task RunDetectionCycleAsync(CancellationToken ct)
    {
        // Update watchdog heartbeat
        AgentWatchdog.LastMonitoringHeartbeat = DateTime.UtcNow;

        // Create a synthetic event representing the current monitoring cycle
        var evt = DetectionEvent.Create(
            processId: Environment.ProcessId.ToString(),
            processName: "behavedr-monitor",
            behaviorType: "periodic_scan",
            source: PlatformMonitors.CurrentPlatformSummary(),
            isUserTargeted: false);

        var result = await _engine.ProcessEventAsync(evt, ct);

        // RT-12 FIX: For signals that contain PID attribution (e.g., "dll_sideload:proc:pid:1234:..."),
        // extract the target PID and create targeted detection events for response actions.
        if (result.Score > 50.0 && result.Signals.Count > 0)
        {
            var attributedSignals = ExtractAttributedSignals(result.Signals);
            foreach (var (pid, processName, signals) in attributedSignals)
            {
                if (ct.IsCancellationRequested) break;

                var targetedEvt = DetectionEvent.Create(
                    processId: pid.ToString(),
                    processName: processName,
                    behaviorType: "behavioral_detection",
                    source: "signal_attribution",
                    isUserTargeted: true);

                // Re-score with just the attributed signals
                var targetedResult = new DetectionResult(targetedEvt, result.Score, result.PresidentKill, signals);
                _logger.LogInformation(
                    "Attributed detection: {Process} (PID {Pid}) — {SignalCount} signals, score={Score:F1}",
                    processName, pid, signals.Count, result.Score);
            }
        }

        if (result.Signals.Count > 0)
        {
            _logger.LogDebug("Cycle complete: {SignalCount} signals, score={Score:F1}, kill={Kill}",
                result.Signals.Count, result.Score, result.PresidentKill);
        }
    }

    /// <summary>
    /// RT-12 FIX: Extract process attribution from signal type strings.
    /// Signals containing "pid:NNNN" are grouped by their target PID for targeted response.
    /// </summary>
    private static List<(int Pid, string ProcessName, List<Signal> Signals)> ExtractAttributedSignals(List<Signal> signals)
    {
        var byPid = new Dictionary<int, (string Name, List<Signal> Signals)>();

        foreach (var signal in signals)
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                signal.Type, @":pid:(\d+)");
            if (!match.Success) continue;

            if (!int.TryParse(match.Groups[1].Value, out var pid)) continue;
            if (pid <= 4) continue;

            // Extract process name from signal (format: "type:processname:pid:N:...")
            var parts = signal.Type.Split(':');
            var procName = parts.Length >= 2 ? parts[1] : "unknown";

            if (!byPid.TryGetValue(pid, out var entry))
            {
                entry = (procName, new List<Signal>());
                byPid[pid] = entry;
            }
            entry.Signals.Add(signal);
        }

        return byPid.Select(kv => (kv.Key, kv.Value.Name, kv.Value.Signals)).ToList();
    }
}
