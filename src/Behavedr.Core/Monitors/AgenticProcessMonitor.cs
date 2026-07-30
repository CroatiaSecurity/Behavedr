namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Cross-platform detection of AI coding agents / MCP toolchains abused for
/// autonomous recon, credential access, and LOLBin/shell spawning.
/// </summary>
public sealed class AgenticProcessMonitor : IPlatformMonitor
{
    private readonly ILogger<AgenticProcessMonitor> _logger;
    private readonly HashSet<int> _agentPids = new();
    private readonly Dictionary<int, int> _spawnCounts = new();
    private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastPrune = DateTime.UtcNow;

    public string PlatformName => "AgenticProcess";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    private static readonly HashSet<string> AgentNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "claude", "cursor", "codex", "aider", "windsurf", "continue",
        "gemini", "ollama", "lmstudio", "open-webui", "npx"
    };

    private static readonly HashSet<string> HighRiskChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "bash", "zsh", "sh", "wsl",
        "python", "python3", "node", "certutil", "mshta", "bitsadmin",
        "curl", "wget", "ssh", "scp", "rclone", "nc", "ncat", "socat"
    };

    private static readonly string[] CredFragments =
    {
        "login data", "cookies", "key4.db", "logins.json",
        ".ssh/id_", "credentials", ".aws/", ".azure/",
        ".config/gcloud", ".kube/config", ".gnupg/"
    };

    public AgenticProcessMonitor(ILogger<AgenticProcessMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<AgenticProcessMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if (!IsSupported) return Task.FromResult<IEnumerable<Signal>>(signals);

        try
        {
            if ((DateTime.UtcNow - _lastPrune).TotalMinutes > 10)
            {
                _agentPids.Clear();
                _spawnCounts.Clear();
                _alerted.Clear();
                _lastPrune = DateTime.UtcNow;
            }

            Process[] procs;
            try { procs = Process.GetProcesses(); }
            catch { return Task.FromResult<IEnumerable<Signal>>(signals); }

            var idToName = new Dictionary<int, string>();
            var idToPpid = new Dictionary<int, int>();

            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    idToName[p.Id] = Normalize(p.ProcessName);
                    idToPpid[p.Id] = GetParentPid(p.Id);
                }
                catch { /* skip */ }
            }

            foreach (var (pid, name) in idToName)
            {
                if (IsAgentName(name))
                    _agentPids.Add(pid);
            }

            foreach (var (pid, name) in idToName)
            {
                if (ct.IsCancellationRequested) break;
                if (!idToPpid.TryGetValue(pid, out var ppid)) continue;
                var parentName = idToName.GetValueOrDefault(ppid, "");
                var parentIsAgent = _agentPids.Contains(ppid) || IsAgentName(parentName);
                if (!parentIsAgent) continue;

                _spawnCounts[ppid] = _spawnCounts.GetValueOrDefault(ppid) + 1;

                if (!HighRiskChildren.Contains(name)) continue;

                string? path = null;
                try
                {
                    using var proc = Process.GetProcessById(pid);
                    path = GetImagePath(proc);
                }
                catch { /* deny */ }

                var cred = path != null && CredFragments.Any(f =>
                    path.Contains(f, StringComparison.OrdinalIgnoreCase));
                var burst = _spawnCounts.GetValueOrDefault(ppid) >= 12;
                var key = $"{ppid}:{name}:{cred}:{burst}";
                if (!_alerted.Add(key)) continue;

                if (cred)
                    signals.Add(new Signal($"agentic_cred_spawn:{parentName}->{name}:pid={pid}", 88, 0.90));
                else if (burst)
                    signals.Add(new Signal($"agentic_burst:{parentName}:count={_spawnCounts[ppid]}", 70, 0.75));
                else
                    signals.Add(new Signal($"agentic_child:{parentName}->{name}:pid={pid}", 62, 0.68));
            }

            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { /* ignore */ }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[AgenticProcessMonitor] error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private static string Normalize(string name)
    {
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return name[..^4];
        return name;
    }

    private static bool IsAgentName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var n = Normalize(name);
        if (AgentNames.Contains(n)) return true;
        return n.Contains("claude", StringComparison.OrdinalIgnoreCase) ||
               n.Contains("cursor", StringComparison.OrdinalIgnoreCase) ||
               n.Contains("codex", StringComparison.OrdinalIgnoreCase);
    }

    private static int GetParentPid(int pid)
    {
        if (OperatingSystem.IsWindows())
            return WindowsParentPid(pid);
        if (OperatingSystem.IsLinux())
            return LinuxParentPid(pid);
        if (OperatingSystem.IsMacOS())
            return MacParentPid(pid);
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static int WindowsParentPid(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId={pid}");
            foreach (var obj in searcher.Get())
            {
                return Convert.ToInt32(obj["ParentProcessId"]);
            }
        }
        catch { /* ignore */ }
        return 0;
    }

    private static int LinuxParentPid(int pid)
    {
        try
        {
            var status = File.ReadAllText($"/proc/{pid}/status");
            foreach (var line in status.Split('\n'))
            {
                if (line.StartsWith("PPid:", StringComparison.Ordinal))
                    return int.Parse(line["PPid:".Length..].Trim());
            }
        }
        catch { /* ignore */ }
        return 0;
    }

    private static int MacParentPid(int pid)
    {
        try
        {
            var psi = new ProcessStartInfo("ps", $"-o ppid= -p {pid}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return 0;
            var output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(1000);
            if (int.TryParse(output, out var ppid)) return ppid;
        }
        catch { /* ignore */ }
        return 0;
    }

    private static string? GetImagePath(Process p)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                return p.MainModule?.FileName;
            if (OperatingSystem.IsLinux() && File.Exists($"/proc/{p.Id}/exe"))
                return new FileInfo($"/proc/{p.Id}/exe").LinkTarget ?? $"/proc/{p.Id}/exe";
        }
        catch { /* deny */ }
        return null;
    }
}
