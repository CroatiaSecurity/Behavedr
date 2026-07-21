namespace Behavedr.Core.Response;

using System.Diagnostics;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Response action that terminates a malicious process.
/// Only executes when the detection result meets president-kill criteria.
/// </summary>
public class ProcessKillAction : IResponseAction
{
    private readonly ILogger<ProcessKillAction> _logger;

    // Processes that must NEVER be killed (system stability)
    private static readonly HashSet<string> ProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "csrss", "wininit", "winlogon", "lsass", "services",
        "smss", "svchost", "dwm", "explorer", "init", "systemd", "launchd",
        "kernel_task", "loginwindow", "behavedr",
    };

    // SECURITY: Protected process check is path-verified. An attacker naming malware
    // "explorer.exe" in a temp directory will NOT be protected from kill.
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    public ProcessKillAction(ILogger<ProcessKillAction>? logger = null)
    {
        _logger = logger ?? NullLogger<ProcessKillAction>.Instance;
    }

    public string Name => "ProcessKill";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        var processName = result.Event.ProcessName;
        var processId = result.Event.ProcessId;

        // Safety check: never kill protected system processes (path-verified)
        if (ProtectedProcesses.Contains(processName))
        {
            // HARDENING: Only protect if the binary is actually from a system path.
            // An attacker naming malware "explorer.exe" in Temp will NOT be protected.
            bool isLegitimateSystemProcess = false;
            if (int.TryParse(processId, out var checkPid))
            {
                try
                {
                    using var checkProc = Process.GetProcessById(checkPid);
                    var imagePath = checkProc.MainModule?.FileName;
                    isLegitimateSystemProcess = imagePath != null &&
                        (imagePath.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase) ||
                         imagePath.Contains("Behavedr", StringComparison.OrdinalIgnoreCase));
                }
                catch { isLegitimateSystemProcess = true; } // Can't verify — err on safety
            }
            else
            {
                isLegitimateSystemProcess = true;
            }

            if (isLegitimateSystemProcess)
            {
                _logger.LogWarning("Refusing to kill protected process: {Process}", processName);
                return Task.FromResult(ResponseOutcome.Skipped(Name, $"Protected process: {processName}"));
            }
            // Not from system path — fall through to kill
            _logger.LogWarning("Process '{Process}' matches protected name but is NOT from system path — allowing kill", processName);
        }

        // Safety check: never kill our own process
        if (processId == Environment.ProcessId.ToString())
        {
            return Task.FromResult(ResponseOutcome.Skipped(Name, "Cannot kill own process"));
        }

        // Attempt to find and kill the process
        if (!int.TryParse(processId, out var pid))
        {
            return Task.FromResult(ResponseOutcome.Failed(Name, $"Invalid process ID: {processId}"));
        }

        try
        {
            var process = Process.GetProcessById(pid);

            // Double-check the process name matches what we detected
            if (!process.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("PID {Pid} no longer matches expected process {Expected}, now {Actual}",
                    pid, processName, process.ProcessName);
                return Task.FromResult(ResponseOutcome.Skipped(Name,
                    $"PID reused: expected {processName}, found {process.ProcessName}"));
            }

            _logger.LogWarning("KILLING process: {Process} (PID {Pid}) — score={Score:F1}",
                processName, pid, result.Score);

            process.Kill(entireProcessTree: true);

            // Wait briefly for process to exit
            if (process.WaitForExit(3000))
            {
                return Task.FromResult(ResponseOutcome.Ok(Name,
                    $"Killed {processName} (PID {pid})"));
            }
            else
            {
                return Task.FromResult(ResponseOutcome.Ok(Name,
                    $"Kill signal sent to {processName} (PID {pid}), still exiting"));
            }
        }
        catch (ArgumentException)
        {
            return Task.FromResult(ResponseOutcome.Ok(Name,
                $"Process {processName} (PID {pid}) already exited"));
        }
        catch (InvalidOperationException ex)
        {
            return Task.FromResult(ResponseOutcome.Failed(Name,
                $"Cannot kill {processName}: {ex.Message}"));
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return Task.FromResult(ResponseOutcome.Failed(Name,
                $"Access denied killing {processName}: {ex.Message}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error killing {Process}", processName);
            return Task.FromResult(ResponseOutcome.Failed(Name, ex.Message));
        }
    }
}
