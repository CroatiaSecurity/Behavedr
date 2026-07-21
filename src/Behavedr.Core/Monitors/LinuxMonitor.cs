namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;

/// <summary>
/// Linux behavioral monitor using /proc filesystem and audit logs.
/// Provides real-time process enumeration, suspicious file access detection,
/// and audit log analysis without requiring root (reads what's accessible).
/// </summary>
public class LinuxMonitor : IPlatformMonitor
{
    public string PlatformName => "Linux";
    public bool IsSupported => OperatingSystem.IsLinux();

    private static readonly HashSet<string> SuspiciousProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz", "meterpreter", "empire", "covenant", "sliver",
        "chisel", "ligolo", "socat", "ncat", "reverse",
        "linpeas", "linenum", "pspy", "dirtycow",
    };

    private static readonly string[] SensitivePaths =
    [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/root/.ssh",
        "/proc/kcore",
    ];

    // Track audit log size for truncation detection
    private static long _lastAuditLogSize = -1;

    [SupportedOSPlatform("linux")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        try
        {
            ScanProcFilesystem(signals, ct);
            ScanAuditLog(signals, ct);
            DetectPrivilegeEscalation(signals, ct);
        }
        catch (Exception)
        {
            // Best-effort — may not have permissions for all checks
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("linux")]
    private static void ScanProcFilesystem(List<Signal> signals, CancellationToken ct)
    {
        if (!Directory.Exists("/proc")) return;

        try
        {
            var procDirs = Directory.GetDirectories("/proc")
                .Where(d => int.TryParse(Path.GetFileName(d), out _));

            foreach (var procDir in procDirs)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var commPath = Path.Combine(procDir, "comm");
                    if (!File.Exists(commPath)) continue;

                    var processName = File.ReadAllText(commPath).Trim().ToLowerInvariant();

                    // Check for known offensive tools
                    if (SuspiciousProcessNames.Any(s => processName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        signals.Add(new Signal($"suspicious_process:{processName}", 85, 0.9));
                    }

                    // Check for processes running as root that shouldn't be
                    var statusPath = Path.Combine(procDir, "status");
                    if (File.Exists(statusPath))
                    {
                        var statusLines = File.ReadLines(statusPath);
                        foreach (var line in statusLines)
                        {
                            if (line.StartsWith("Uid:", StringComparison.Ordinal))
                            {
                                var parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length > 1 && parts[1] == "0" && IsUnexpectedRootProcess(processName))
                                {
                                    signals.Add(new Signal($"unexpected_root_process:{processName}", 50, 0.6));
                                }
                                break;
                            }
                        }
                    }

                    // Check cmdline for suspicious arguments
                    var cmdlinePath = Path.Combine(procDir, "cmdline");
                    if (File.Exists(cmdlinePath))
                    {
                        var cmdline = File.ReadAllText(cmdlinePath).Replace('\0', ' ').ToLowerInvariant();

                        // Reverse shells
                        if (cmdline.Contains("/dev/tcp/") || cmdline.Contains("bash -i") ||
                            cmdline.Contains("nc -e") || cmdline.Contains("ncat -e"))
                        {
                            signals.Add(new Signal($"reverse_shell_indicator:{processName}", 90, 0.85));
                        }

                        // Base64 encoded commands
                        if (cmdline.Contains("base64 -d") || cmdline.Contains("| bash") ||
                            cmdline.Contains("| sh"))
                        {
                            signals.Add(new Signal($"encoded_execution:{processName}", 60, 0.7));
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (Exception) { }
    }

    [SupportedOSPlatform("linux")]
    private static void ScanAuditLog(List<Signal> signals, CancellationToken ct)
    {
        // Read the last N lines of audit log if accessible
        const string auditLogPath = "/var/log/audit/audit.log";
        if (!File.Exists(auditLogPath)) return;

        // RT-10: Detect audit log truncation (attacker clearing evidence)
        DetectAuditLogTruncation(signals, auditLogPath);

        try
        {
            using var stream = new FileStream(auditLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            // Seek to last 8KB to get recent events
            var seekPos = Math.Max(0, stream.Length - 8192);
            stream.Seek(seekPos, SeekOrigin.Begin);

            using var reader = new StreamReader(stream);
            var cutoffTime = DateTime.UtcNow.AddSeconds(-30);

            while (!reader.EndOfStream && !ct.IsCancellationRequested)
            {
                var line = reader.ReadLine();
                if (line is null) break;

                // Look for EXECVE events involving sensitive binaries
                if (line.Contains("type=EXECVE", StringComparison.Ordinal))
                {
                    foreach (var sensPath in SensitivePaths)
                    {
                        if (line.Contains(sensPath, StringComparison.Ordinal))
                        {
                            signals.Add(new Signal($"sensitive_file_access:{sensPath}", 65, 0.75));
                            break;
                        }
                    }
                }

                // Privilege escalation via su/sudo
                if (line.Contains("type=USER_AUTH", StringComparison.Ordinal) &&
                    line.Contains("res=failed", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("failed_auth_attempt", 40, 0.6));
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    [SupportedOSPlatform("linux")]
    private static void DetectAuditLogTruncation(List<Signal> signals, string auditLogPath)
    {
        try
        {
            var currentSize = new FileInfo(auditLogPath).Length;

            if (_lastAuditLogSize >= 0)
            {
                // Audit logs should only grow (or rotate to a new file with similar size).
                // A significant decrease indicates truncation (attacker clearing evidence).
                if (currentSize < _lastAuditLogSize * 0.5 && _lastAuditLogSize > 4096)
                {
                    signals.Add(new Signal(
                        $"audit_log_truncated:was:{_lastAuditLogSize}:now:{currentSize}",
                        90, 0.92));
                }
                else if (currentSize == 0 && _lastAuditLogSize > 0)
                {
                    signals.Add(new Signal("audit_log_cleared", 95, 0.98));
                }
            }

            _lastAuditLogSize = currentSize;
        }
        catch { }
    }

    [SupportedOSPlatform("linux")]
    private static void DetectPrivilegeEscalation(List<Signal> signals, CancellationToken ct)
    {
        // Check for SUID binaries in unusual locations
        try
        {
            var tmpDirs = new[] { "/tmp", "/var/tmp", "/dev/shm" };
            foreach (var dir in tmpDirs)
            {
                if (!Directory.Exists(dir) || ct.IsCancellationRequested) continue;

                try
                {
                    var files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        try
                        {
                            // Check if file is executable (approximate — full SUID check needs stat)
                            var info = new FileInfo(file);
                            if (info.Length > 0 && info.Extension == "" &&
                                (info.Attributes & FileAttributes.ReadOnly) == 0)
                            {
                                // Executable in temp directory is suspicious
                                var age = DateTime.UtcNow - info.CreationTimeUtc;
                                if (age.TotalMinutes < 5)
                                {
                                    signals.Add(new Signal($"executable_in_tmp:{Path.GetFileName(file)}", 55, 0.65));
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch { }
    }

    private static bool IsUnexpectedRootProcess(string name) =>
        name is not ("init" or "systemd" or "kthreadd" or "sshd" or "cron"
            or "rsyslogd" or "dockerd" or "containerd" or "snapd"
            or "NetworkManager" or "polkitd" or "dbus-daemon");
}
