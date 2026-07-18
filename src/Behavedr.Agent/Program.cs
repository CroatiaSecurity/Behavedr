using Behavedr.Core;
using Behavedr.Core.Platform;

var engine = AgentBootstrap.CreateEngine();

Console.WriteLine($"Behavedr Agent started on {PlatformMonitors.CurrentPlatformSummary()}.");
foreach (var name in AgentBootstrap.RegisteredMonitorNames(engine))
    Console.WriteLine($"  Registered monitor: {name}");

Console.WriteLine("Behavioral monitoring active (desktop + mobile cores share detection).");
// TODO: tray (Windows), systemd (Linux), launchd (macOS), response engine loop
