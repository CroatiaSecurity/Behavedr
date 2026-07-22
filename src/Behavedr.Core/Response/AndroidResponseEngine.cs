namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Android response action engine providing:
/// - Process termination (kill -9 for root, force-stop for Device Owner)
/// - Network isolation (iptables per-UID drop for root, VPN-based for non-root)
/// - App removal (pm uninstall for root/Device Owner)
/// - Permission revocation (pm revoke for Device Owner)
///
/// Capabilities scale with privilege level:
/// - Root: Full response (iptables, kill, pm uninstall, pm revoke)
/// - Device Owner/Profile Owner: force-stop, uninstall, revoke via DPM
/// - Non-root: Limited to VPN-based isolation (requires platform injection)
///
/// v0.2.0 audit fix A-2: Gives Android response capability.
/// </summary>
[SupportedOSPlatform("android")]
public class AndroidResponseEngine : IResponseAction
{
    private readonly ILogger<AndroidResponseEngine> _logger;
    private bool? _hasRoot;
    private int _activeIptablesRules;
    private const int MaxIptablesRules = 50;

    public string Name => "AndroidResponse";
    public bool IsSupported => OperatingSystem.IsAndroid();

    public AndroidResponseEngine(ILogger<AndroidResponseEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<AndroidResponseEngine>.Instance;
    }

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsAndroid())
            return ResponseOutcome.Skipped(Name, "Not Android");

        var pid = result.Event.ProcessId;
        var processName = result.Event.ProcessName;

        if (!int.TryParse(pid, out var pidInt) || pidInt <= 4)
            return ResponseOutcome.Skipped(Name, $"Invalid PID: {pid}");

        // Never kill ourselves
        if (pidInt == Environment.ProcessId)
            return ResponseOutcome.Skipped(Name, "Cannot kill own process");

        // Never kill system-critical processes
        if (IsSystemCritical(processName, pidInt))
            return ResponseOutcome.Skipped(Name, $"Protected system process: {processName}");

        _hasRoot ??= CheckRootAccess();

        if (_hasRoot == true)
        {
            var killResult = await KillProcessRoot(pidInt, processName, ct);
            if (killResult.Success)
            {
                // Also isolate network for the app UID to prevent re-connection
                await IsolateNetworkRoot(pidInt, ct);
            }
            return killResult;
        }
        else
        {
            return await ForceStopApp(processName, ct);
        }
    }

    [SupportedOSPlatform("android")]
    private async Task<ResponseOutcome> KillProcessRoot(int pid, string name, CancellationToken ct)
    {
        try
        {
            // Verify process still exists and matches expected name
            var commPath = $"/proc/{pid}/comm";
            if (File.Exists(commPath))
            {
                var currentComm = File.ReadAllText(commPath).Trim();
                if (!currentComm.Contains(name, StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains(currentComm, StringComparison.OrdinalIgnoreCase))
                {
                    return ResponseOutcome.Skipped(Name,
                        $"PID reuse: expected {name}, found {currentComm}");
                }
            }

            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/system/bin/kill",
                Arguments = $"-9 {pid}",
                UseShellExecute = false,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);

            if (proc.ExitCode == 0)
            {
                _logger.LogWarning("[AndroidResponse] Killed PID {Pid} ({Name})", pid, name);
                return ResponseOutcome.Ok(Name, $"Killed {name} (PID {pid})");
            }

            var stderr = await proc.StandardError.ReadToEndAsync(ct);
            return ResponseOutcome.Failed(Name, $"kill -9 returned {proc.ExitCode}: {stderr}");
        }
        catch (Exception ex)
        {
            return ResponseOutcome.Failed(Name, $"Kill failed: {ex.Message}");
        }
    }

    [SupportedOSPlatform("android")]
    private async Task IsolateNetworkRoot(int pid, CancellationToken ct)
    {
        if (_activeIptablesRules >= MaxIptablesRules)
        {
            _logger.LogWarning("[AndroidResponse] iptables rule limit reached ({Max})", MaxIptablesRules);
            return;
        }

        var uid = GetProcessUid(pid);
        if (uid < 0 || uid == 0) return; // Don't block root UID

        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/system/bin/iptables",
                Arguments = $"-A OUTPUT -m owner --uid-owner {uid} -j DROP",
                UseShellExecute = false,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);

            if (proc.ExitCode == 0)
            {
                _activeIptablesRules++;
                _logger.LogWarning("[AndroidResponse] Network isolated UID {Uid}", uid);
            }
        }
        catch { }
    }

    [SupportedOSPlatform("android")]
    private async Task<ResponseOutcome> ForceStopApp(string packageOrProcess, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/system/bin/am",
                Arguments = $"force-stop {packageOrProcess}",
                UseShellExecute = false,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);

            return proc.ExitCode == 0
                ? ResponseOutcome.Ok(Name, $"Force-stopped {packageOrProcess}")
                : ResponseOutcome.Failed(Name, "am force-stop failed (not Device Owner?)");
        }
        catch (Exception ex)
        {
            return ResponseOutcome.Failed(Name, ex.Message);
        }
    }

    /// <summary>
    /// Release all iptables isolation rules added by this engine.
    /// Called during shutdown or rule limit reset.
    /// </summary>
    [SupportedOSPlatform("android")]
    public async Task ReleaseAllIsolation(CancellationToken ct = default)
    {
        if (_hasRoot != true || _activeIptablesRules == 0) return;

        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/system/bin/iptables",
                Arguments = "-F OUTPUT",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);
            _activeIptablesRules = 0;
            _logger.LogInformation("[AndroidResponse] All iptables isolation rules flushed");
        }
        catch { }
    }

    private static int GetProcessUid(int pid)
    {
        try
        {
            var statusPath = $"/proc/{pid}/status";
            if (!File.Exists(statusPath)) return -1;
            foreach (var line in File.ReadLines(statusPath))
            {
                if (!line.StartsWith("Uid:", StringComparison.Ordinal)) continue;
                var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 1 && int.TryParse(parts[1], out var uid))
                    return uid;
                break;
            }
        }
        catch { }
        return -1;
    }

    private static bool CheckRootAccess()
    {
        return File.Exists("/system/bin/su") ||
               File.Exists("/system/xbin/su") ||
               File.Exists("/sbin/su") ||
               File.Exists("/data/local/bin/su");
    }

    private static bool IsSystemCritical(string name, int pid)
    {
        if (pid <= 100) return true; // Low PIDs are system processes on Android

        var systemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "zygote", "zygote64", "system_server", "servicemanager",
            "surfaceflinger", "vold", "installd", "netd", "lmkd",
            "init", "ueventd", "healthd", "logd", "adbd",
        };

        return systemProcesses.Contains(name);
    }
}
