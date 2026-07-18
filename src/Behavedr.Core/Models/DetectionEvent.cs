namespace Behavedr.Core.Models;

public record DetectionEvent(
    string ProcessId,
    string ProcessName,
    string BehaviorType,
    DateTime Timestamp,
    double Score,
    bool IsUserTargeted,
    string Source
);
