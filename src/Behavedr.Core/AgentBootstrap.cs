namespace Behavedr.Core;

using Behavedr.Core.Platform;

/// <summary>
/// Shared startup for desktop and mobile agents.
/// </summary>
public static class AgentBootstrap
{
    public static DetectionEngine CreateEngine()
    {
        var engine = new DetectionEngine();
        foreach (var monitor in PlatformMonitors.Supported())
            engine.RegisterMonitor(monitor);
        return engine;
    }

    public static IReadOnlyList<string> RegisteredMonitorNames(DetectionEngine engine) =>
        engine.RegisteredMonitors.Select(m => m.GetType().Name).ToList();
}
