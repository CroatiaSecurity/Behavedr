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

        if (result.Signals.Count > 0)
        {
            _logger.LogDebug("Cycle complete: {SignalCount} signals, score={Score:F1}, kill={Kill}",
                result.Signals.Count, result.Score, result.PresidentKill);
        }
    }
}
