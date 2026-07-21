namespace Behavedr.Core.Response;

using System.Diagnostics;
using Behavedr.Core.Models;
using Behavedr.Core.Monitors;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Traces the full attack chain from a detected malicious process back to its origin.
/// Walks the parent process tree, kills chain processes, and logs forensic evidence.
/// Only invoked for high-confidence detections with active response enabled.
/// </summary>
public class ChainTracer
{
    private readonly ProcessAncestryCache _ancestryCache;
    private readonly ILogger<ChainTracer> _logger;

    private static readonly HashSet<string> CriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
        "explorer", "dwm", "winlogon", "behavedr",
    };

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    public ChainTracer(ProcessAncestryCache ancestryCache, ILogger<ChainTracer>? logger = null)
    {
        _ancestryCache = ancestryCache;
        _logger = logger ?? NullLogger<ChainTracer>.Instance;
    }

    /// <summary>
    /// Trace and kill the attack chain rooted at the detected process.
    /// Returns the list of PIDs killed.
    /// </summary>
    public List<int> TraceAndKill(int rootPid, string rootProcessName)
    {
        var killed = new List<int>();
        var chain = _ancestryCache.GetAncestryChain(rootPid, 8);

        _logger.LogWarning("[ChainTracer] Tracing chain from {Process} (PID {Pid}): {Chain}",
            rootProcessName, rootPid, _ancestryCache.GetAncestryString(rootPid));

        // Kill the root process first
        KillProcess(rootPid, rootProcessName, killed);

        // Walk ancestors and kill non-system processes
        foreach (var ancestor in chain)
        {
            if (CriticalSystemProcesses.Contains(ancestor.ProcessName)) continue;

            // Verify it's not from system directory
            try
            {
                using var proc = Process.GetProcessById(ancestor.Pid);
                var path = proc.MainModule?.FileName;
                if (path != null && path.StartsWith(WinDir, StringComparison.OrdinalIgnoreCase))
                    continue;
            }
            catch { continue; }

            KillProcess(ancestor.Pid, ancestor.ProcessName, killed);
        }

        if (killed.Count > 1)
        {
            _logger.LogWarning("[ChainTracer] Killed {Count} processes in attack chain: [{Pids}]",
                killed.Count, string.Join(", ", killed));
        }

        return killed;
    }

    private void KillProcess(int pid, string name, List<int> killed)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (!proc.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase))
                return; // PID reused

            proc.Kill(entireProcessTree: true);
            killed.Add(pid);
            _logger.LogWarning("[ChainTracer] Killed: {Process} (PID {Pid})", name, pid);
        }
        catch (ArgumentException) { } // Already exited
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[ChainTracer] Failed to kill {Process} (PID {Pid})", name, pid);
        }
    }
}
