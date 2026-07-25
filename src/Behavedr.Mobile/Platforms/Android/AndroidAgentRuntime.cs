#if ANDROID
using Behavedr.Core;
using Behavedr.Core.Monitors;
using Behavedr.Core.Models;
using Behavedr.Core.Response;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Behavedr.Mobile;

/// <summary>
/// Process-wide Android agent runtime. Ensures the foreground service, MainActivity,
/// platform signal providers, and response engine share one DetectionEngine and one
/// authenticated AndroidMonitor injection token.
///
/// v0.2.2 fix: previously MainActivity built an AndroidPlatformSignalProvider with
/// androidMonitor=null (signals never injected), and BehavedrForegroundService only
/// called GetSignalsAsync without scoring/response — a silent production sabotage of
/// the entire Android EDR pipeline.
/// </summary>
public static class AndroidAgentRuntime
{
    private static readonly object Gate = new();
    private static bool _initialized;
    private static DetectionEngine? _engine;
    private static ResponseEngine? _responseEngine;
    private static AndroidMonitor? _androidMonitor;
    private static string? _injectionToken;
    private static ILogger _logger = NullLogger.Instance;

    public static bool IsInitialized
    {
        get { lock (Gate) return _initialized; }
    }

    public static DetectionEngine Engine
    {
        get
        {
            EnsureInitialized();
            return _engine!;
        }
    }

    public static ResponseEngine ResponseEngine
    {
        get
        {
            EnsureInitialized();
            return _responseEngine!;
        }
    }

    public static AndroidMonitor? AndroidMonitor
    {
        get
        {
            EnsureInitialized();
            return _androidMonitor;
        }
    }

    public static string InjectionToken
    {
        get
        {
            EnsureInitialized();
            return _injectionToken!;
        }
    }

    /// <summary>
    /// Idempotent initialization. Safe to call from Application, Activity, or Service.
    /// </summary>
    public static void EnsureInitialized(ILogger? logger = null)
    {
        lock (Gate)
        {
            if (_initialized) return;

            if (logger is not null)
                _logger = logger;

            _engine = AgentBootstrap.CreateEngine();
            _androidMonitor = _engine.RegisteredMonitors.OfType<AndroidMonitor>().FirstOrDefault();

            _injectionToken = Guid.NewGuid().ToString("N");
            _androidMonitor?.SetInjectionToken(_injectionToken);

            // Production mobile default: AlertOnly unless device is Device Owner (can be upgraded later).
            // Pipeline still scores and logs; Active mode can be enabled via future config.
            var policy = new ResponsePolicy
            {
                Mode = ResponseMode.Active,
                AlertThreshold = 50.0,
                ResponseThreshold = 75.0,
                EnableQuarantine = false,
                EnableProcessKill = true,
            };

            _responseEngine = new ResponseEngine(policy);
            _responseEngine.RegisterAction(new AndroidResponseEngine());

            _initialized = true;
            _logger.LogInformation(
                "[AndroidAgentRuntime] Initialized: {MonitorCount} monitors, injection={HasInjection}, response=Active",
                _engine.RegisteredMonitors.Count,
                _androidMonitor is not null);
        }
    }

    /// <summary>
    /// Inject platform signals into the shared AndroidMonitor (authenticated).
    /// No-op if runtime not ready or monitor missing.
    /// </summary>
    public static void InjectSignals(IEnumerable<Signal> signals)
    {
        EnsureInitialized();
        if (_androidMonitor is null || _injectionToken is null) return;

        var list = signals as IList<Signal> ?? signals.ToList();
        if (list.Count == 0) return;

        try
        {
            _androidMonitor.InjectPlatformSignals(list, _injectionToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[AndroidAgentRuntime] Signal injection failed");
        }
    }

    /// <summary>
    /// Full detection cycle: collect → score → respond. Used by the foreground service.
    /// </summary>
    public static async Task<DetectionResult> RunDetectionCycleAsync(CancellationToken ct = default)
    {
        EnsureInitialized();

        var evt = DetectionEvent.Create(
            processId: Environment.ProcessId.ToString(),
            processName: "behavedr-android",
            behaviorType: "periodic_scan",
            source: "Android",
            isUserTargeted: false);

        var result = await _engine!.ProcessEventAsync(evt, ct);
        var responses = await _responseEngine!.RespondAsync(result, ct);

        // Attribute high-score signals to PIDs for targeted response
        if (result.Score > 50.0 && result.Signals.Count > 0)
        {
            foreach (var (pid, processName, signals) in ExtractAttributedSignals(result.Signals))
            {
                if (ct.IsCancellationRequested) break;

                var targetedEvt = DetectionEvent.Create(
                    processId: pid.ToString(),
                    processName: processName,
                    behaviorType: "behavioral_detection",
                    source: "signal_attribution",
                    isUserTargeted: true);

                var targetedResult = new DetectionResult(targetedEvt, result.Score, result.PresidentKill, signals);
                await _responseEngine.RespondAsync(targetedResult, ct);
            }
        }

        if (result.Signals.Count > 0)
        {
            _logger.LogInformation(
                "[AndroidAgentRuntime] Cycle: {Signals} signals, score={Score:F1}, kill={Kill}, responses={Resp}",
                result.Signals.Count, result.Score, result.PresidentKill, responses.Count);
        }

        return result;
    }

    private static List<(int Pid, string ProcessName, List<Signal> Signals)> ExtractAttributedSignals(
        List<Signal> signals)
    {
        var byPid = new Dictionary<int, (string Name, List<Signal> Signals)>();

        foreach (var signal in signals)
        {
            var match = System.Text.RegularExpressions.Regex.Match(signal.Type, @":pid:(\d+)");
            if (!match.Success) continue;
            if (!int.TryParse(match.Groups[1].Value, out var pid) || pid <= 4) continue;

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
#endif
