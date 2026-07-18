using Behavedr.Core;
using Behavedr.Windows;
using Behavedr.Linux;
using Behavedr.MacOS;

var engine = new DetectionEngine();
engine.RegisterMonitor(new WindowsMonitor());
engine.RegisterMonitor(new LinuxMonitor());
engine.RegisterMonitor(new MacOSMonitor());

Console.WriteLine("Behavedr Agent started. Behavioral monitoring active.");
// TODO: tray/systemd loop + response engine
