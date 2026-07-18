namespace Behavedr.Core.Communication;

using Behavedr.Core.Models;
using Behavedr.Core.Response;

/// <summary>
/// Abstraction for the agent-to-server communication channel.
/// </summary>
public interface IBehavedrClient : IAsyncDisposable
{
    /// <summary>Whether the client is currently connected to the server.</summary>
    bool IsConnected { get; }

    /// <summary>Connect to the server.</summary>
    Task ConnectAsync(CancellationToken ct = default);

    /// <summary>Report a detection event to the server.</summary>
    Task ReportDetectionAsync(DetectionReport report, CancellationToken ct = default);

    /// <summary>Send an agent heartbeat with status information.</summary>
    Task SendHeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct = default);

    /// <summary>Fetch updated policy from the server (if available).</summary>
    Task<PolicyUpdate?> FetchPolicyAsync(CancellationToken ct = default);
}

/// <summary>
/// A detection report to send to the server.
/// </summary>
public record DetectionReport(
    string AgentId,
    DetectionEvent Event,
    double Score,
    bool PresidentKill,
    List<SignalReport> Signals,
    List<ResponseOutcome> ResponsesTaken,
    DateTime ReportedAt)
{
    public static DetectionReport FromResult(string agentId, DetectionResult result, List<ResponseOutcome> responses) =>
        new(
            agentId,
            result.Event,
            result.Score,
            result.PresidentKill,
            result.Signals.Select(s => new SignalReport(s.Type, s.Weight, s.Confidence)).ToList(),
            responses,
            DateTime.UtcNow);
}

public record SignalReport(string Type, double Weight, double Confidence);

/// <summary>
/// Periodic heartbeat from agent to server.
/// </summary>
public record AgentHeartbeat(
    string AgentId,
    string Platform,
    string Version,
    int MonitorCount,
    long UptimeSeconds,
    DateTime SentAt);

/// <summary>
/// Policy update received from server.
/// </summary>
public record PolicyUpdate(
    ResponsePolicy? ResponsePolicy,
    ScoringConfig? ScoringConfig,
    int? MonitoringIntervalSeconds,
    DateTime IssuedAt);
