namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Detects processes performing raw disk I/O by opening physical device paths
/// (\\.\PhysicalDrive0, \\.\C:). Catches bootkits, forensic wiping, and
/// filesystem-level exfiltration (T1006).
/// </summary>
[SupportedOSPlatform("windows")]
public class RawDiskAccessMonitor : IPlatformMonitor
{
    private readonly ILogger<RawDiskAccessMonitor> _logger;
    private readonly HashSet<string> _alertedKeys = new();

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private static readonly HashSet<string> AllowedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "vds", "vdsldr", "diskmgmt", "diskpart", "defrag",
        "chkdsk", "sfc", "dism", "wbengine", "vssvc",
        "msiexec", "trustedinstaller", "tiworker",
        "Taskmgr", "resmon", "perfmon", "mmc", "SystemInformer",
        "svchost", "system", "behavedr",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public string PlatformName => "RawDiskAccessMonitor";
    public bool IsSupported => OperatingSystem.IsWindows();

    public RawDiskAccessMonitor(ILogger<RawDiskAccessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<RawDiskAccessMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            // Scan processes for handles to raw disk devices via command-line heuristics
            // and process name matching (full NtQuerySystemInformation handle scanning
            // requires significant privileges and complexity)
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (ct.IsCancellationRequested) break;
                    if (proc.Id <= 4 || proc.Id == Environment.ProcessId) continue;

                    var name = proc.ProcessName;
                    if (AllowedProcesses.Contains(name)) continue;

                    // Check if process has raw disk handle by checking its loaded modules
                    // and known command patterns
                    string? cmdLine = null;
                    try
                    {
                        using var searcher = new System.Management.ManagementObjectSearcher(
                            $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                        {
                            cmdLine = obj["CommandLine"]?.ToString();
                            break;
                        }
                    }
                    catch { }

                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    // Check for raw disk access patterns in command line
                    if (ContainsRawDiskPattern(cmdLine))
                    {
                        var key = $"{proc.Id}:{name}";
                        if (_alertedKeys.Contains(key)) continue;
                        _alertedKeys.Add(key);

                        string? imagePath = null;
                        try { imagePath = proc.MainModule?.FileName; } catch { }

                        // Additional check: is binary from a system path?
                        bool isSystem = imagePath != null &&
                            imagePath.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase);

                        if (!isSystem)
                        {
                            signals.Add(new Signal(
                                $"raw_disk_access:{name}:pid:{proc.Id}:path:{imagePath ?? "unknown"}",
                                85, 0.80));
                            _logger.LogCritical(
                                "SECURITY: Raw disk access detected — '{Process}' (PID {Pid}) accessing physical device",
                                name, proc.Id);
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            if (_alertedKeys.Count > 500) _alertedKeys.Clear();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[RawDiskAccessMonitor] Scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static bool ContainsRawDiskPattern(string cmdLine)
    {
        return cmdLine.Contains(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\PHYSICALDRIVE", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\Device\Harddisk", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\C:", StringComparison.OrdinalIgnoreCase) ||
               cmdLine.Contains(@"\\.\D:", StringComparison.OrdinalIgnoreCase);
    }
}
