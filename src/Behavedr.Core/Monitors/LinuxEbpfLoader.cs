namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Production helper to load Behavedr eBPF objects and dump event maps via bpftool (0.3.2).
/// Keeps managed code free of fragile inline bytecode while supporting field installs.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfLoader
{
    public const string DefaultPinDir = "/sys/fs/bpf/behavedr";
    public const string DefaultObjectName = "behavedr_exec.bpf.o";

    private readonly ILogger _logger;

    public LinuxEbpfLoader(ILogger? logger = null)
    {
        _logger = logger ?? NullLogger.Instance;
    }

    public string? FindObject()
    {
        foreach (var dir in new[]
                 {
                     AppContext.BaseDirectory,
                     Path.Combine(AppContext.BaseDirectory, "ebpf"),
                     "/opt/behavedr",
                     "/opt/behavedr/ebpf",
                     Directory.GetCurrentDirectory(),
                     Path.Combine(Directory.GetCurrentDirectory(), "native", "linux", "ebpf"),
                 })
        {
            var p = Path.Combine(dir, DefaultObjectName);
            if (File.Exists(p)) return p;
            // suite object alternate name
            p = Path.Combine(dir, "behavedr_suite.bpf.o");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    public bool TryLoadAll(string objectPath, string pinDir = DefaultPinDir)
    {
        try
        {
            Directory.CreateDirectory(pinDir);
            // Clear prior pins best-effort
            Run("rm", $"-rf {pinDir}/*");

            var rc = Run("bpftool", $"prog loadall \"{objectPath}\" {pinDir} type tracing");
            if (rc != 0)
                rc = Run("bpftool", $"prog loadall \"{objectPath}\" {pinDir}");
            if (rc != 0)
            {
                _logger.LogWarning("[eBPF] bpftool prog loadall failed rc={Rc}", rc);
                return false;
            }

            // Attach common tracepoints if not auto-attached
            TryAttach(pinDir, "sched_process_exec", "sched", "sched_process_exec");
            TryAttach(pinDir, "sys_enter_openat", "syscalls", "sys_enter_openat");
            TryAttach(pinDir, "sys_enter_connect", "syscalls", "sys_enter_connect");

            _logger.LogInformation("[eBPF] Loaded object {Obj} into {Pin}", objectPath, pinDir);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[eBPF] load failed");
            return false;
        }
    }

    /// <summary>
    /// Dump array map "events" (hex) into structured records via bpftool JSON if available.
    /// </summary>
    public IReadOnlyList<EbpfMapEvent> DumpEvents(string pinDir = DefaultPinDir)
    {
        var list = new List<EbpfMapEvent>();
        var mapPin = Path.Combine(pinDir, "events");
        if (!File.Exists(mapPin) && !Directory.Exists(pinDir))
            return list;

        // bpftool map dump pinned /sys/fs/bpf/behavedr/events
        var (rc, stdout) = RunCapture("bpftool", $"map dump pinned {mapPin}");
        if (rc != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            // try name lookup
            (rc, stdout) = RunCapture("bpftool", "map dump name events");
            if (rc != 0 || string.IsNullOrWhiteSpace(stdout))
                return list;
        }

        // Parse loosely: look for "comm" style hex dumps or key/value pairs
        // Fallback: any line with hex value bytes → synthetic event
        foreach (Match m in Regex.Matches(stdout, @"key:\s*(\d+)\s+value:\s*([0-9a-fA-F\s]+)"))
        {
            var key = int.Parse(m.Groups[1].Value);
            var hex = Regex.Replace(m.Groups[2].Value, @"\s+", "");
            if (hex.Length < 16) continue;
            try
            {
                var bytes = Convert.FromHexString(hex.Length % 2 == 0 ? hex : hex + "0");
                if (bytes.Length < 16) continue;
                var kind = BitConverter.ToUInt32(bytes, 0);
                var pid = BitConverter.ToUInt32(bytes, 4);
                var tgid = BitConverter.ToUInt32(bytes, 8);
                var comm = System.Text.Encoding.ASCII.GetString(bytes, 16, Math.Min(16, bytes.Length - 16)).TrimEnd('\0');
                list.Add(new EbpfMapEvent((int)kind, (int)pid, (int)tgid, comm, key));
            }
            catch { /* parse skip */ }
        }

        return list;
    }

    private void TryAttach(string pinDir, string progHint, string cat, string name)
    {
        // Find any pinned prog and try attach — best effort
        if (!Directory.Exists(pinDir)) return;
        foreach (var f in Directory.EnumerateFiles(pinDir))
        {
            Run("bpftool", $"prog attach pinned {f} tracepoint {cat} {name}");
        }
        _ = progHint;
    }

    private static int Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"{file} {args} 2>/dev/null\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            if (p is null) return -1;
            if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return -1; }
            return p.ExitCode;
        }
        catch { return -1; }
    }

    private static (int rc, string stdout) RunCapture(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "/bin/sh",
                Arguments = $"-c \"{file} {args} 2>/dev/null\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            if (p is null) return (-1, "");
            var stdout = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return (-1, ""); }
            return (p.ExitCode, stdout);
        }
        catch { return (-1, ""); }
    }

    public readonly record struct EbpfMapEvent(int Kind, int Pid, int Tgid, string Comm, int Slot);
}
