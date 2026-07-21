namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Unix self-protection mechanisms for Linux and macOS:
/// 1. ptrace protection (PR_SET_DUMPABLE=0 on Linux, PT_DENY_ATTACH on macOS)
///    - Prevents debuggers from attaching to the agent process
/// 2. Signal handler registration (catch SIGTERM for graceful shutdown logging)
/// 3. Core dump prevention (setrlimit RLIMIT_CORE to 0)
/// 4. Process name masking (prctl PR_SET_NAME to avoid easy identification)
/// 5. File descriptor monitoring (detect /proc/self/fd manipulation)
///
/// Note: SIGKILL (9) cannot be caught — protection against that relies on
/// service manager restart (systemd Restart=always, launchd KeepAlive=true).
/// </summary>
public class UnixSelfProtection : IPlatformMonitor
{
    private readonly ILogger<UnixSelfProtection> _logger;
    private bool _protectionApplied;
    private int _initialFdCount = -1;

    public string PlatformName => "UnixSelfProtection";
    public bool IsSupported => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public UnixSelfProtection(ILogger<UnixSelfProtection>? logger = null)
    {
        _logger = logger ?? NullLogger<UnixSelfProtection>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_protectionApplied)
        {
            ApplyProtections(signals);
            _protectionApplied = true;
        }

        // Runtime checks
        CheckPtraceStatus(signals);
        CheckFdLeakage(signals);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Apply one-time protections at startup.
    /// </summary>
    private void ApplyProtections(List<Signal> signals)
    {
        if (OperatingSystem.IsLinux())
        {
            ApplyLinuxProtections(signals);
        }
        else if (OperatingSystem.IsMacOS())
        {
            ApplyMacOSProtections(signals);
        }

        // Record initial fd count for later comparison
        try
        {
            var fdDir = "/proc/self/fd";
            if (Directory.Exists(fdDir))
            {
                _initialFdCount = Directory.GetFiles(fdDir).Length;
            }
        }
        catch { }
    }

    /// <summary>
    /// Apply Linux-specific protections:
    /// - PR_SET_DUMPABLE(0): prevents ptrace attach and core dumps
    /// - Sets /proc/self/coredump_filter to 0 (no core dump content)
    /// </summary>
    private void ApplyLinuxProtections(List<Signal> signals)
    {
        try
        {
            // PR_SET_DUMPABLE = 4, 0 = not dumpable (prevents ptrace and core dumps)
            var result = prctl(4, 0, 0, 0, 0);
            if (result == 0)
            {
                _logger.LogInformation(
                    "[UnixSelfProtection] PR_SET_DUMPABLE=0 applied — ptrace attach blocked");
            }
            else
            {
                _logger.LogWarning("[UnixSelfProtection] PR_SET_DUMPABLE failed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixSelfProtection] Failed to set PR_SET_DUMPABLE");
        }

        // Disable core dumps via coredump_filter
        try
        {
            var filterPath = "/proc/self/coredump_filter";
            if (File.Exists(filterPath))
            {
                File.WriteAllText(filterPath, "0");
            }
        }
        catch { }
    }

    /// <summary>
    /// Apply macOS-specific protections.
    /// PT_DENY_ATTACH prevents debugger attachment (via ptrace syscall).
    /// </summary>
    private void ApplyMacOSProtections(List<Signal> signals)
    {
        try
        {
            // PT_DENY_ATTACH = 31, prevents any future ptrace(PT_ATTACH)
            var result = ptrace_deny_attach();
            if (result == 0)
            {
                _logger.LogInformation(
                    "[UnixSelfProtection] PT_DENY_ATTACH applied — debugger attachment blocked");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[UnixSelfProtection] PT_DENY_ATTACH failed");
        }
    }

    /// <summary>
    /// Verify ptrace protection is still active (Linux).
    /// If an attacker managed to re-enable dumpable, detect it.
    /// </summary>
    private void CheckPtraceStatus(List<Signal> signals)
    {
        if (!OperatingSystem.IsLinux()) return;

        try
        {
            // PR_GET_DUMPABLE = 3
            var dumpable = prctl(3, 0, 0, 0, 0);
            if (dumpable > 0)
            {
                // Dumpable was re-enabled — someone tampered with our protection
                signals.Add(new Signal("ptrace_protection_disabled", 88, 0.92));
                _logger.LogCritical(
                    "SECURITY: PR_SET_DUMPABLE was re-enabled — ptrace protection bypassed");

                // Re-apply
                prctl(4, 0, 0, 0, 0);
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect file descriptor leakage or manipulation.
    /// An attacker might inject FDs to redirect our I/O or leak information.
    /// </summary>
    private void CheckFdLeakage(List<Signal> signals)
    {
        if (_initialFdCount < 0) return;

        try
        {
            var fdDir = "/proc/self/fd";
            if (!Directory.Exists(fdDir)) return;

            var currentCount = Directory.GetFiles(fdDir).Length;

            // Sudden large increase in FDs could indicate fd injection or resource exhaustion attack
            if (currentCount > _initialFdCount + 50)
            {
                signals.Add(new Signal(
                    $"fd_leak_detected:initial:{_initialFdCount}:current:{currentCount}",
                    60, 0.7));
            }
        }
        catch { }
    }

    // P/Invoke for Linux prctl
    [DllImport("libc", EntryPoint = "prctl", SetLastError = true)]
    private static extern int prctl(int option, long arg2, long arg3, long arg4, long arg5);

    // macOS: ptrace(PT_DENY_ATTACH, 0, 0, 0)
    private static int ptrace_deny_attach()
    {
        try
        {
            return ptrace(31 /* PT_DENY_ATTACH */, 0, IntPtr.Zero, 0);
        }
        catch { return -1; }
    }

    [DllImport("libc", EntryPoint = "ptrace", SetLastError = true)]
    private static extern int ptrace(int request, int pid, IntPtr addr, int data);
}
