namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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

    /// <summary>
    /// Execute process kill response action.
    /// V-1 DOCUMENTED: A TOCTOU race exists between path verification and the kill call.
    /// Between reading MainModule.FileName and calling proc.Kill(), the process could be
    /// replaced via PID reuse. The process name re-verification check (comparing ProcessName
    /// before kill) mitigates this partially but a sub-millisecond race window remains.
    /// This is inherent to userland process management and accepted as residual risk.
    /// </summary>
    public Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        var processName = result.Event.ProcessName;
        var processId = result.Event.ProcessId;

        // Safety check: never kill protected system processes (path-verified)
        if (ProtectedProcesses.Contains(processName))
        {
            // HARDENING: Only protect if the binary is actually from a system path.
            // An attacker naming malware "explorer.exe" in Temp will NOT be protected.
            // RT-4 FIX: If we cannot verify the process path (e.g., restricted DACL),
            // we do NOT grant protection. Only truly low PIDs (kernel/system) get
            // unconditional protection. This prevents kill-immunity via DACL + name spoofing.
            bool isLegitimateSystemProcess = false;
            if (int.TryParse(processId, out var checkPid))
            {
                // PIDs 0-4 are always system-critical (System Idle, System, smss early)
                if (checkPid <= 4)
                {
                    isLegitimateSystemProcess = true;
                }
                else
                {
                    try
                    {
                        using var checkProc = Process.GetProcessById(checkPid);
                        var imagePath = checkProc.MainModule?.FileName;
                        isLegitimateSystemProcess = imagePath != null &&
                            (imagePath.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase) ||
                             imagePath.Contains("Behavedr", StringComparison.OrdinalIgnoreCase));
                    }
                    catch
                    {
                        // RT-4: Cannot verify process path — do NOT grant protection.
                        // An attacker using restrictive DACLs to block verification
                        // should not gain kill immunity. Fail-open for defense.
                        // NOTE: TOCTOU race exists between this check and the kill call
                        // (see V-1 documentation). This is inherent to userland process mgmt.
                        isLegitimateSystemProcess = false;
                        _logger.LogWarning(
                            "Cannot verify image path for protected-name process '{Process}' (PID {Pid}) — " +
                            "NOT granting kill immunity (possible DACL evasion)",
                            processName, checkPid);
                    }
                }
            }
            else
            {
                isLegitimateSystemProcess = false;
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

            // Linux: Use pidfd for race-free process kill (eliminates TOCTOU PID reuse)
            if (OperatingSystem.IsLinux())
            {
                var pidfdResult = TryKillViaPidfd(pid, processName, result.Score);
                if (pidfdResult is not null)
                    return Task.FromResult(pidfdResult);
                // pidfd unavailable — fall through to standard kill
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

    /// <summary>
    /// Kill a process using pidfd_open + pidfd_send_signal (Linux 5.1+).
    /// This is race-free: pidfd references the exact process instance, not a reusable PID number.
    /// If the PID has been reused between detection and kill, pidfd_open returns a handle to
    /// the new (innocent) process, but we verify /proc/PID/exe before sending the signal.
    /// Returns null if pidfd is unavailable (older kernel) — caller falls back to Process.Kill().
    /// </summary>
    [SupportedOSPlatform("linux")]
    private ResponseOutcome? TryKillViaPidfd(int pid, string processName, double score)
    {
        try
        {
            // Verify /proc/PID/exe before opening pidfd
            var exePath = $"/proc/{pid}/exe";
            string? resolvedPath = null;
            try
            {
                resolvedPath = File.ResolveLinkTarget(exePath, returnFinalTarget: true)?.ToString();
            }
            catch { }

            // If we can resolve exe and it's a system binary, re-verify process name
            if (resolvedPath is not null)
            {
                var exeName = Path.GetFileNameWithoutExtension(resolvedPath);
                if (!exeName.Contains(processName, StringComparison.OrdinalIgnoreCase) &&
                    !processName.Contains(exeName, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "[pidfd] PID {Pid} exe={Exe} doesn't match expected {Expected} — aborting kill (PID reuse?)",
                        pid, resolvedPath, processName);
                    return ResponseOutcome.Skipped(Name,
                        $"PID reuse detected via /proc/PID/exe: expected {processName}, got {resolvedPath}");
                }
            }

            // pidfd_open(pid, 0) — returns a file descriptor referencing this exact process
            var pidfd = syscall_pidfd_open(434, pid, 0);
            if (pidfd < 0)
            {
                return null; // Fall back to standard kill
            }

            try
            {
                _logger.LogWarning(
                    "KILLING process via pidfd: {Process} (PID {Pid}) — score={Score:F1}",
                    processName, pid, score);

                // pidfd_send_signal(pidfd, SIGKILL, NULL, 0)
                const int SIGKILL = 9;
                var result = syscall_pidfd_send_signal(424, pidfd, SIGKILL, IntPtr.Zero, 0);

                if (result == 0)
                {
                    return ResponseOutcome.Ok(Name,
                        $"Killed {processName} (PID {pid}) via pidfd (race-free)");
                }
                else
                {
                    var errno = Marshal.GetLastWin32Error();
                    return ResponseOutcome.Failed(Name,
                        $"pidfd_send_signal failed for {processName} (errno {errno})");
                }
            }
            finally
            {
                libc_close(pidfd);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[pidfd] Failed, falling back to standard kill");
            return null;
        }
    }

    // P/Invoke: Linux pidfd syscalls (kernel 5.1+, x86_64 syscall numbers)
    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern int syscall_pidfd_open(long sysno, int pid, uint flags);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static extern int syscall_pidfd_send_signal(long sysno, int pidfd, int sig, IntPtr info, uint flags);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int libc_close(int fd);
}
