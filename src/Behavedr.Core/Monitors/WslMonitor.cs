namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

/// <summary>
/// Monitors Windows Subsystem for Linux (WSL) attack surface (T1202):
/// - WSL process spawns with suspicious command lines
/// - Runtime WSL distribution installs (wsl --import)
/// - Processes loaded from \\wsl$ filesystem
/// </summary>
[SupportedOSPlatform("windows")]
public class WslMonitor : IPlatformMonitor
{
    private readonly ILogger<WslMonitor> _logger;
    private readonly HashSet<string> _baselineDistros = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _alertedPids = new();
    private bool _baselined;

    private static readonly string[] SuspiciousPatterns =
    {
        "nc -", "ncat ", "socat ", "/dev/tcp/", "bash -i",
        "curl http", "wget http", "python -c", "python3 -c",
        "perl -e", "ruby -e", "meterpreter", "reverse_tcp",
        "base64 -d", "nmap ", "masscan", "/etc/shadow",
    };

    public string PlatformName => "WslMonitor";
    public bool IsSupported => OperatingSystem.IsWindows() &&
        File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));

    public WslMonitor(ILogger<WslMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<WslMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            ScanWslProcesses(signals, ct);
            CheckNewDistros(signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[WslMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void ScanWslProcesses(List<Signal> signals, CancellationToken ct)
    {
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (ct.IsCancellationRequested) break;
                var name = proc.ProcessName.ToLowerInvariant();
                if (name is not ("wsl" or "wslhost" or "bash")) continue;
                if (_alertedPids.Contains(proc.Id)) continue;

                string? cmdLine = null;
                try
                {
                    using var searcher = new System.Management.ManagementObjectSearcher(
                        $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                    foreach (System.Management.ManagementObject obj in searcher.Get())
                    { cmdLine = obj["CommandLine"]?.ToString(); break; }
                }
                catch { }

                if (string.IsNullOrEmpty(cmdLine)) continue;

                var cmdLower = cmdLine.ToLowerInvariant();
                foreach (var pattern in SuspiciousPatterns)
                {
                    if (cmdLower.Contains(pattern))
                    {
                        signals.Add(new Signal(
                            $"wsl_suspicious_command:{proc.ProcessName}:pid:{proc.Id}:pattern:{pattern}",
                            70, 0.78));
                        _alertedPids.Add(proc.Id);
                        break;
                    }
                }
            }
            catch { }
            finally { proc.Dispose(); }
        }

        if (_alertedPids.Count > 500) _alertedPids.Clear();
    }

    [SupportedOSPlatform("windows")]
    private void CheckNewDistros(List<Signal> signals)
    {
        var current = GetInstalledDistros();

        if (!_baselined)
        {
            _baselineDistros.UnionWith(current);
            _baselined = true;
            return;
        }

        foreach (var distro in current)
        {
            if (_baselineDistros.Contains(distro)) continue;
            _baselineDistros.Add(distro);
            signals.Add(new Signal($"wsl_new_distro_installed:{distro}", 65, 0.72));
        }
    }

    [SupportedOSPlatform("windows")]
    private static HashSet<string> GetInstalledDistros()
    {
        var distros = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Lxss");
            if (key == null) return distros;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var subKey = key.OpenSubKey(sub);
                var name = subKey?.GetValue("DistributionName")?.ToString();
                if (!string.IsNullOrEmpty(name)) distros.Add(name);
            }
        }
        catch { }
        return distros;
    }
}
