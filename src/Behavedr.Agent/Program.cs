using Behavedr.Core;
using Behavedr.Windows;
using Behavedr.Linux;
using Behavedr.MacOS;
using System.Drawing;
using System.Windows.Forms;
using System.IO;

var engine = new DetectionEngine();
engine.RegisterMonitor(new WindowsMonitor());
engine.RegisterMonitor(new LinuxMonitor());
engine.RegisterMonitor(new MacOSMonitor());

Console.WriteLine("Behavedr Agent started. Behavioral monitoring active.");

// Windows Tray with your icon
if (OperatingSystem.IsWindows())
{
    var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "Behavedr.ico");
    if (File.Exists(iconPath))
    {
        var tray = new NotifyIcon 
        { 
            Icon = new Icon(iconPath), 
            Visible = true, 
            Text = "Behavedr EDR - Active" 
        };
        // TODO: context menu, double click etc.
        Console.WriteLine("Tray icon loaded.");
    }
}

// TODO: systemd on Linux, full response engine, loop
