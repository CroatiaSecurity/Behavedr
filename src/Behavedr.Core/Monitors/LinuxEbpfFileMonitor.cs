namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux sensitive-file open monitor (0.2.8 eBPF suite companion).
/// Uses fanotify-compatible path polling of high-value inodes via /proc/self/mountinfo
/// and recent /proc/*/fd resolution sampling — bridges until full BPF LSM/file hooks ship.
/// Correlates with <see cref="LinuxFanotifyMonitor"/> for EXEC; this focuses on credential paths.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfFileMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxEbpfFileMonitor> _logger;
    private DateTime _last = DateTime.MinValue;
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly TimeSpan _interval = TimeSpan.FromSeconds(3);

    private static readonly string[] SensitivePaths =
    [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
        "/etc/crontab", "/var/spool/cron",
        "/etc/ld.so.preload",
    ];

    public string PlatformName => "LinuxEbpfFile";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxEbpfFileMonitor(ILogger<LinuxEbpfFileMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEbpfFileMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if ((DateTime.UtcNow - _last) < _interval)
            return Task.FromResult<IEnumerable<Signal>>(signals);
        _last = DateTime.UtcNow;

        try
        {
            // Sample open FDs across processes (bounded)
            int scanned = 0;
            foreach (var procDir in Directory.EnumerateDirectories("/proc"))
            {
                if (scanned > 80) break;
                var name = Path.GetFileName(procDir);
                if (!int.TryParse(name, out var pid) || pid <= 1) continue;
                scanned++;

                var fdDir = Path.Combine(procDir, "fd");
                if (!Directory.Exists(fdDir)) continue;

                try
                {
                    foreach (var fd in Directory.EnumerateFileSystemEntries(fdDir).Take(32))
                    {
                        string? target = null;
                        try { target = File.ResolveLinkTarget(fd, returnFinalTarget: true)?.FullName; }
                        catch { continue; }
                        if (string.IsNullOrEmpty(target)) continue;

                        foreach (var sens in SensitivePaths)
                        {
                            if (!target.StartsWith(sens, StringComparison.Ordinal) &&
                                !string.Equals(target, sens, StringComparison.Ordinal))
                                continue;

                            var key = $"{pid}:{target}";
                            if (!_seen.Add(key)) continue;
                            if (_seen.Count > 5000) _seen.Clear();

                            signals.Add(new Signal(
                                $"ebpf_file_sensitive_open:pid:{pid}:{Path.GetFileName(target)}",
                                85, 0.9));
                        }
                    }
                }
                catch { /* permission */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[eBPF-file] scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
