using Behavedr.Core;
using Behavedr.Core.Monitors;
using Behavedr.Core.Platform;

var engine = new DetectionEngine();

IPlatformMonitor[] monitors =
[
    new WindowsMonitor(),
    new LinuxMonitor(),
    new MacOSMonitor(),
];

foreach (var monitor in monitors.Where(m => m.IsSupported))
{
    engine.RegisterMonitor(monitor);
    Console.WriteLine($"Registered monitor: {monitor.GetType().Name}");
}

Console.WriteLine("Behavedr Agent started. Behavioral monitoring active.");
Console.WriteLine($"OS: {Environment.OSVersion}");
// TODO: tray (Windows), systemd (Linux), launchd (macOS), response engine loop
