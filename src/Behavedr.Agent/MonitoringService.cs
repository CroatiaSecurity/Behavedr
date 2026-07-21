namespace Behavedr.Agent;

using Behavedr.Core;
using Behavedr.Core.Communication;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service that periodically collects behavioral signals and runs detection.
/// v0.1.3: Now wires ResponseEngine and Communication (C-1, H-5 fix).
/// </summary>
public sealed class MonitoringService : BackgroundService
{
    private readonly DetectionEngine _engine;
    private readonly ResponseEngine _responseEngine;
    private readonly IBehavedrClient _client;
    private readonly OfflineBuffer _offlineBuffer;
    private readonly CommunicationConfig _commConfig;
    private readonly ILogger<MonitoringService> _logger;
    private readonly TimeSpan _interval;

    public MonitoringService(
        DetectionEngine engine,
        ResponseEngine responseEngine,
        IBehavedrClient client,
        OfflineBuffer offlineBuffer,
        CommunicationConfig commConfig,
        IConfiguration configuration,
        ILogger<MonitoringService> logger)
    {
        _engine = engine;
        _responseEngine = responseEngine;
        _client = client;
        _offlineBuffer = offlineBuffer;
        _commConfig = commConfig;
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

        // v0.1.3 (C-1 fix): Execute response actions when score warrants it
        var responses = await _responseEngine.RespondAsync(result, ct);

        // v0.1.3 (H-5 fix): For signals with PID attribution, create targeted detection events
        // and execute response actions against the specific malicious process.
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

                // Execute response actions against the attributed process
                var targetedResponses = await _responseEngine.RespondAsync(targetedResult, ct);
                responses.AddRange(targetedResponses);
            }
        }

        // v0.1.3 (C-3 fix): Report detection to server if score warrants it
        if (result.Score > _responseEngine.Policy.AlertThreshold && _commConfig.Enabled)
        {
            var report = DetectionReport.FromResult(_commConfig.AgentId, result, responses);
            try
            {
                await _client.ReportDetectionAsync(report, ct);
            }
            catch
            {
                // Server unreachable — buffer for later replay
                await _offlineBuffer.EnqueueAsync(report, ct);
            }
        }

        if (result.Signals.Count > 0)
        {
            _logger.LogDebug("Cycle complete: {SignalCount} signals, score={Score:F1}, kill={Kill}, responses={ResponseCount}",
                result.Signals.Count, result.Score, result.PresidentKill, responses.Count);
        }
    }

    /// <summary>
    /// Extract process attribution from signal type strings.
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
