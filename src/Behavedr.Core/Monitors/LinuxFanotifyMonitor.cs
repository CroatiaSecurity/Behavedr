namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Real-time file execution and access monitoring via Linux fanotify.
/// Uses FAN_OPEN_EXEC for notification of every binary execution system-wide.
///
/// Fanotify operates at the VFS layer in the kernel, providing:
/// - Real-time notification of file opens for execution (eliminating polling gaps)
/// - File path attribution via /proc/self/fd resolution
/// - System-wide coverage (all mount points)
///
/// This is a NOTIFY-only monitor (not using FAN_OPEN_EXEC_PERM which would block).
/// Blocking execution requires additional policy configuration and is not appropriate
/// for an EDR that lacks code-signing infrastructure.
///
/// Requires: CAP_SYS_ADMIN or CAP_AUDIT_READ (depending on kernel version).
/// Available since: Linux 5.1+ (FAN_OPEN_EXEC), Linux 2.6.37 (base fanotify).
/// No kernel module, no code signing required — pure userland via syscall.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxFanotifyMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxFanotifyMonitor> _logger;
    private int _fanotifyFd = -1;
    private bool _initialized;
    private readonly Queue<FanotifyExecEvent> _events = new();
    private readonly object _lock = new();
    private const int MaxBufferedEvents = 300;

    // Suspicious execution locations (binaries executed from here are noteworthy)
    private static readonly string[] SuspiciousExecPaths =
    [
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
        "/home/", "/root/",
    ];

    // Known-good execution paths (suppress noise)
    private static readonly string[] TrustedExecPaths =
    [
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/lib/", "/lib/", "/opt/behavedr/",
        "/usr/libexec/", "/snap/",
    ];

    public string PlatformName => "LinuxFanotify";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxFanotifyMonitor(ILogger<LinuxFanotifyMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxFanotifyMonitor>.Instance;
    }

    /// <summary>
    /// Initialize fanotify file descriptor and mark the root filesystem for exec events.
    /// </summary>
    [SupportedOSPlatform("linux")]
    public bool TryInitialize()
    {
        if (_initialized) return _fanotifyFd >= 0;

        _initialized = true;

        try
        {
            // fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE)
            const uint FAN_CLASS_NOTIF = 0x00000000;
            const uint FAN_NONBLOCK = 0x00000002;
            const int O_RDONLY = 0;
            const int O_LARGEFILE = 0x8000;

            _fanotifyFd = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
            if (_fanotifyFd < 0)
            {
                _logger.LogWarning(
                    "[LinuxFanotify] fanotify_init failed (errno {Errno}). " +
                    "Requires CAP_SYS_ADMIN. Falling back to polling.",
                    Marshal.GetLastWin32Error());
                return false;
            }

            // Mark root filesystem for FAN_OPEN_EXEC events
            const ulong FAN_OPEN_EXEC = 0x00001000;
            const uint FAN_MARK_ADD = 0x00000001;
            const uint FAN_MARK_MOUNT = 0x00000010;
            const int AT_FDCWD = -100;

            var result = fanotify_mark(_fanotifyFd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                FAN_OPEN_EXEC, AT_FDCWD, "/");

            if (result < 0)
            {
                _logger.LogWarning(
                    "[LinuxFanotify] fanotify_mark failed for / (errno {Errno}). " +
                    "FAN_OPEN_EXEC requires kernel 5.1+.",
                    Marshal.GetLastWin32Error());
                close(_fanotifyFd);
                _fanotifyFd = -1;
                return false;
            }

            _logger.LogInformation(
                "[LinuxFanotify] Initialized — real-time file execution monitoring active on /");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[LinuxFanotify] Initialization failed");
            return false;
        }
    }

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_initialized)
            TryInitialize();

        if (_fanotifyFd < 0)
            return Task.FromResult<IEnumerable<Signal>>(signals);

        // Read pending fanotify events
        DrainFanotifyEvents(ct);

        // Process buffered events into signals
        lock (_lock)
        {
            while (_events.Count > 0)
            {
                if (ct.IsCancellationRequested) break;
                var evt = _events.Dequeue();
                AnalyzeExecEvent(evt, signals);
            }
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Read fanotify events from the fd. Each event is a fanotify_event_metadata struct.
    /// We resolve the file path from the event's fd via /proc/self/fd/N readlink.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private void DrainFanotifyEvents(CancellationToken ct)
    {
        // fanotify_event_metadata is 24 bytes on x86_64
        var buffer = new byte[4096]; // Room for ~170 events per read
        var iterations = 0;

        while (!ct.IsCancellationRequested && iterations++ < 50)
        {
            var bytesRead = read(_fanotifyFd, buffer, buffer.Length);
            if (bytesRead <= 0) break;

            var offset = 0;
            while (offset + 24 <= bytesRead)
            {
                // Parse fanotify_event_metadata
                var eventLen = BitConverter.ToUInt32(buffer, offset);
                // var vers = buffer[offset + 4];
                // var reserved = buffer[offset + 5];
                // var metadataLen = BitConverter.ToUInt16(buffer, offset + 6);
                var mask = BitConverter.ToUInt64(buffer, offset + 8);
                var fd = BitConverter.ToInt32(buffer, offset + 16);
                var pid = BitConverter.ToInt32(buffer, offset + 20);

                if (fd >= 0)
                {
                    var filePath = ResolveFdPath(fd);
                    close(fd); // Must close the event fd

                    if (filePath is not null)
                    {
                        lock (_lock)
                        {
                            if (_events.Count >= MaxBufferedEvents)
                                _events.Dequeue();
                            _events.Enqueue(new FanotifyExecEvent(pid, filePath,
                                Environment.TickCount64));
                        }
                    }
                }

                offset += (int)(eventLen > 0 ? eventLen : 24);
            }
        }
    }

    private void AnalyzeExecEvent(FanotifyExecEvent evt, List<Signal> signals)
    {
        // Skip our own process and trusted paths
        if (evt.Pid == Environment.ProcessId) return;
        if (TrustedExecPaths.Any(p => evt.FilePath.StartsWith(p, StringComparison.Ordinal)))
            return;

        // Execution from suspicious paths
        if (SuspiciousExecPaths.Any(p => evt.FilePath.StartsWith(p, StringComparison.Ordinal)))
        {
            var fileName = Path.GetFileName(evt.FilePath);
            signals.Add(new Signal(
                $"exec_from_suspicious_path:{fileName}:{evt.FilePath}:pid:{evt.Pid}",
                62, 0.72));
        }

        // Execution of hidden files (dotfiles)
        var name = Path.GetFileName(evt.FilePath);
        if (name.StartsWith('.') && !name.StartsWith("..", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"hidden_file_execution:{name}:pid:{evt.Pid}", 58, 0.68));
        }

        // Execution from deleted path (memfd_create or unlinked binary)
        if (evt.FilePath.Contains("(deleted)", StringComparison.Ordinal) ||
            evt.FilePath.Contains("memfd:", StringComparison.Ordinal))
        {
            signals.Add(new Signal(
                $"fileless_execution_fanotify:{Path.GetFileName(evt.FilePath)}:pid:{evt.Pid}",
                88, 0.9));
        }
    }

    private static string? ResolveFdPath(int fd)
    {
        try
        {
            var linkPath = $"/proc/self/fd/{fd}";
            return File.ResolveLinkTarget(linkPath, returnFinalTarget: true)?.ToString();
        }
        catch { return null; }
    }

    // P/Invoke for fanotify syscalls
    [DllImport("libc", EntryPoint = "fanotify_init", SetLastError = true)]
    private static extern int fanotify_init(uint flags, int event_f_flags);

    [DllImport("libc", EntryPoint = "fanotify_mark", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int fanotify_mark(int fanotify_fd, uint flags, ulong mask, int dirfd, string pathname);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern int read(int fd, byte[] buf, int count);

    [DllImport("libc", EntryPoint = "close")]
    private static extern int close(int fd);

    private record FanotifyExecEvent(int Pid, string FilePath, long TimestampMs);
}
