namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Council of Elders weighted scoring engine.
/// Calculates composite behavioral risk scores with configurable thresholds.
/// </summary>
public class ScoringEngine
{
    private readonly ScoringConfig _config;

    public ScoringEngine(ScoringConfig? config = null)
    {
        _config = config ?? ScoringConfig.Default;
    }

    public double PresidentKillThreshold => _config.PresidentKillThreshold;
    public double UserTargetedMultiplier => _config.UserTargetedMultiplier;

    public double CalculateScore(DetectionEvent evt, List<Signal> signals)
    {
        ArgumentNullException.ThrowIfNull(evt);
        ArgumentNullException.ThrowIfNull(signals);

        if (signals.Count == 0)
            return 0.0;

        double baseScore = 0.0;
        foreach (var signal in signals)
        {
            // Clamp confidence to [0, 1] and weight to [0, 100]
            var confidence = Math.Clamp(signal.Confidence, 0.0, 1.0);
            var weight = Math.Clamp(signal.Weight, 0.0, 100.0);
            baseScore += weight * confidence;
        }

        if (evt.IsUserTargeted)
            baseScore *= _config.UserTargetedMultiplier;

        return Math.Clamp(baseScore, 0.0, 100.0);
    }

    public bool ShouldPresidentKill(double score, DetectionEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        return score > _config.PresidentKillThreshold && evt.IsUserTargeted;
    }
}

/// <summary>
/// Externalized scoring configuration. Loaded from appsettings.json or defaults.
/// </summary>
public record ScoringConfig
{
    public double UserTargetedMultiplier { get; init; } = 2.0;
    public double PresidentKillThreshold { get; init; } = 95.0;
    public double HighScoreAlertThreshold { get; init; } = 50.0;

    public static ScoringConfig Default => new();

    /// <summary>
    /// Validates thresholds are within acceptable bounds.
    /// </summary>
    public bool IsValid() =>
        UserTargetedMultiplier is > 0.0 and <= 10.0 &&
        PresidentKillThreshold is > 0.0 and <= 100.0 &&
        HighScoreAlertThreshold > 0.0 && HighScoreAlertThreshold < PresidentKillThreshold;
}
