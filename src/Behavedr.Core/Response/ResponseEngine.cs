namespace Behavedr.Core.Response;

using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Orchestrates response actions based on detection results and configured policy.
/// Supports alert-only mode (default) and active response mode.
/// </summary>
public class ResponseEngine
{
    private readonly List<IResponseAction> _actions = new();
    private readonly ILogger<ResponseEngine> _logger;
    private readonly ResponsePolicy _policy;

    // Rate limiting: track recent response targets to prevent re-executing on same PID/path
    private readonly Dictionary<string, DateTime> _recentTargets = new();
    private readonly TimeSpan _cooldownPeriod = TimeSpan.FromSeconds(60);
    private readonly object _rateLimitLock = new();

    public ResponseEngine(ResponsePolicy? policy = null, ILogger<ResponseEngine>? logger = null)
    {
        _policy = policy ?? ResponsePolicy.Default;
        _logger = logger ?? NullLogger<ResponseEngine>.Instance;
    }

    public IReadOnlyList<IResponseAction> RegisteredActions => _actions;
    public ResponsePolicy Policy => _policy;

    /// <summary>Register a response action.</summary>
    public void RegisterAction(IResponseAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        _actions.Add(action);
        _logger.LogInformation("Registered response action: {Action} (supported: {Supported})",
            action.Name, action.IsSupported);
    }

    /// <summary>
    /// Evaluate a detection result and execute appropriate response actions.
    /// </summary>
    public async Task<List<ResponseOutcome>> RespondAsync(DetectionResult result, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var outcomes = new List<ResponseOutcome>();

        // Determine response level based on score and policy
        var level = DetermineResponseLevel(result);

        _logger.LogDebug("Detection score={Score:F1}, level={Level}, policy={PolicyMode}",
            result.Score, level, _policy.Mode);

        // Alert-only mode: log but don't act
        if (_policy.Mode == ResponseMode.AlertOnly)
        {
            if (level >= ResponseLevel.Respond)
            {
                _logger.LogWarning("ALERT (alert-only mode): {ProcessName} scored {Score:F1} — would trigger {Level}",
                    result.Event.ProcessName, result.Score, level);
                outcomes.Add(ResponseOutcome.Skipped("policy", $"Alert-only mode active. Score={result.Score:F1}, level={level}"));
            }
            return outcomes;
        }

        // Active mode: execute response actions based on level
        if (level < ResponseLevel.Respond)
            return outcomes;

        // Rate limiting: don't re-execute actions against the same target within cooldown
        var targetKey = $"{result.Event.ProcessId}:{result.Event.ProcessName}";
        lock (_rateLimitLock)
        {
            // Prune expired entries
            var expired = _recentTargets.Where(kv => DateTime.UtcNow - kv.Value > _cooldownPeriod).Select(kv => kv.Key).ToList();
            foreach (var key in expired) _recentTargets.Remove(key);

            if (_recentTargets.ContainsKey(targetKey))
            {
                _logger.LogDebug("Rate-limited: already responded to {Target} within cooldown", targetKey);
                outcomes.Add(ResponseOutcome.Skipped("rate-limit", $"Cooldown active for {targetKey}"));
                return outcomes;
            }

            _recentTargets[targetKey] = DateTime.UtcNow;
        }

        foreach (var action in _actions)
        {
            if (ct.IsCancellationRequested) break;
            if (!action.IsSupported) continue;

            // President Kill: execute all actions
            // High: execute non-destructive actions only
            if (level < ResponseLevel.PresidentKill && action is ProcessKillAction)
            {
                outcomes.Add(ResponseOutcome.Skipped(action.Name, "Score below president-kill threshold"));
                continue;
            }

            try
            {
                _logger.LogInformation("Executing response action: {Action} against {Process}",
                    action.Name, result.Event.ProcessName);

                var outcome = await action.ExecuteAsync(result, ct);
                outcomes.Add(outcome);

                _logger.LogInformation("Response action {Action}: {Success} — {Message}",
                    action.Name, outcome.Success ? "SUCCESS" : "FAILED", outcome.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Response action {Action} threw exception", action.Name);
                outcomes.Add(ResponseOutcome.Failed(action.Name, ex.Message));
            }
        }

        return outcomes;
    }

    private ResponseLevel DetermineResponseLevel(DetectionResult result)
    {
        if (result.PresidentKill)
            return ResponseLevel.PresidentKill;
        if (result.Score >= _policy.ResponseThreshold)
            return ResponseLevel.Respond;
        if (result.Score >= _policy.AlertThreshold)
            return ResponseLevel.Alert;
        return ResponseLevel.None;
    }
}

/// <summary>
/// Response policy configuration.
/// </summary>
public record ResponsePolicy
{
    /// <summary>Operating mode: AlertOnly (log only) or Active (take actions).</summary>
    public ResponseMode Mode { get; init; } = ResponseMode.AlertOnly;

    /// <summary>Minimum score to trigger an alert.</summary>
    public double AlertThreshold { get; init; } = 50.0;

    /// <summary>Minimum score to trigger active response.</summary>
    public double ResponseThreshold { get; init; } = 75.0;

    /// <summary>Whether to quarantine files found in suspicious locations.</summary>
    public bool EnableQuarantine { get; init; } = true;

    /// <summary>Whether to kill processes flagged by president-kill.</summary>
    public bool EnableProcessKill { get; init; } = true;

    /// <summary>Path for quarantined files.</summary>
    public string QuarantinePath { get; init; } = "quarantine";

    public static ResponsePolicy Default => new();

    public bool IsValid() =>
        AlertThreshold > 0.0 && AlertThreshold <= 100.0 &&
        ResponseThreshold > AlertThreshold && ResponseThreshold <= 100.0;
}

public enum ResponseMode
{
    /// <summary>Log detections but take no automated action.</summary>
    AlertOnly,

    /// <summary>Take automated response actions based on thresholds.</summary>
    Active,
}

public enum ResponseLevel
{
    None,
    Alert,
    Respond,
    PresidentKill,
}
