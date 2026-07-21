namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Council of Elders weighted scoring engine.
/// Calculates composite behavioral risk scores with configurable thresholds.
/// Preserves raw score fidelity and maps to severity tiers for response decisions.
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

        // Do NOT hard-clamp to 100. Preserve raw score for fidelity — higher scores
        // indicate more concurrent threat signals and allow differentiation between
        // "barely over threshold" and "overwhelming evidence".
        // Floor at 0 only (negative scores are meaningless).
        return Math.Max(0.0, baseScore);
    }

    /// <summary>
    /// Get the normalized display score (clamped to 0-100 for UI/reporting).
    /// Use this for human-facing displays, not for internal decision-making.
    /// </summary>
    public static double NormalizeForDisplay(double rawScore) =>
        Math.Clamp(rawScore, 0.0, 100.0);

    /// <summary>
    /// Determine the severity tier for a given raw score.
    /// Tiers preserve the information that hard-clamping destroys.
    /// </summary>
    public SeverityTier GetSeverityTier(double score) => score switch
    {
        > 200.0 => SeverityTier.Extreme,
        > 95.0 => SeverityTier.Critical,
        > 75.0 => SeverityTier.High,
        > 50.0 => SeverityTier.Medium,
        > 25.0 => SeverityTier.Low,
        _ => SeverityTier.Info,
    };

    public bool ShouldPresidentKill(double score, DetectionEvent evt)
    {
        ArgumentNullException.ThrowIfNull(evt);
        return score > _config.PresidentKillThreshold && evt.IsUserTargeted;
    }
}

/// <summary>
/// Severity classification preserving raw score fidelity.
/// </summary>
public enum SeverityTier
{
    Info,
    Low,
    Medium,
    High,
    Critical,
    Extreme,
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
