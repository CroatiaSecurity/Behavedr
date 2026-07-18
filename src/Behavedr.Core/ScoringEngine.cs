namespace Behavedr.Core;

using Behavedr.Core.Models;

/// <summary>
/// Council of Elders weighted scoring.
/// </summary>
public class ScoringEngine
{
    private const double UserTargetedMultiplier = 2.0;
    private const double PresidentKillThreshold = 95.0;

    public double CalculateScore(DetectionEvent evt, List<Signal> signals)
    {
        double baseScore = signals.Sum(s => s.Weight * s.Confidence);
        
        if (evt.IsUserTargeted)
            baseScore *= UserTargetedMultiplier;

        return Math.Min(baseScore, 100.0);
    }

    public bool ShouldPresidentKill(double score, DetectionEvent evt)
    {
        return score > PresidentKillThreshold && evt.IsUserTargeted;
        // Closed list per President's Law
    }
}
