namespace Behavedr.Core.Models;

/// <summary>
/// Represents a behavioral event to be analyzed by the detection engine.
/// </summary>
public record DetectionEvent(
    string ProcessId,
    string ProcessName,
    string BehaviorType,
    DateTime Timestamp,
    double Score,
    bool IsUserTargeted,
    string Source
)
{
    /// <summary>Create a detection event with current timestamp.</summary>
    public static DetectionEvent Create(string processId, string processName, string behaviorType, string source, bool isUserTargeted = false) =>
        new(processId, processName, behaviorType, DateTime.UtcNow, 0.0, isUserTargeted, source);
}
