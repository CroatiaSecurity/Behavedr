namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Network isolation response action for Linux using nftables.
/// When a malicious process is detected, drops all network traffic for that process
/// by creating an nftables rule matching the process's UID/GID or cgroup.
///
/// Since per-PID nftables rules are not natively supported (nftables works on
/// packets, not processes), we use the owner match extension (meta skuid) to
/// isolate by user, or add the process to a cgroup and filter by cgroup path.
///
/// For simplicity and reliability, this implementation:
/// 1. Creates a dedicated nftables table "behavedr_isolation"
/// 2. Adds a rule to drop all output from the target PID's UID (if non-root)
/// 3. For root processes: blocks the specific destination IPs observed in C2 signals
///
/// Requires: CAP_NET_ADMIN (granted via systemd AmbientCapabilities).
/// Falls back gracefully if nftables is not installed.
/// </summary>
[SupportedOSPlatform("linux")]
public class LinuxNetworkIsolation : IResponseAction
{
    private readonly ILogger<LinuxNetworkIsolation> _logger;
    private bool _tableCreated;

    public string Name => "LinuxNetworkIsolation";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxNetworkIsolation(ILogger<LinuxNetworkIsolation>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxNetworkIsolation>.Instance;
    }

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux())
            return ResponseOutcome.Skipped(Name, "Not Linux");

        var processId = result.Event.ProcessId;
        if (!int.TryParse(processId, out var pid) || pid <= 4)
            return ResponseOutcome.Skipped(Name, $"Invalid PID for isolation: {processId}");

        // Ensure our nftables table exists
        if (!_tableCreated)
        {
            await EnsureIsolationTable(ct);
        }

        // Get the UID of the target process
        var uid = GetProcessUid(pid);
        if (uid < 0)
            return ResponseOutcome.Failed(Name, $"Cannot determine UID for PID {pid}");

        // Don't isolate root (UID 0) by UID — too broad. Instead block specific IPs.
        if (uid == 0)
        {
            return await IsolateByDestination(result, pid, ct);
        }

        // Non-root: isolate by UID (drops all network for that user)
        return await IsolateByUid(uid, pid, result.Event.ProcessName, ct);
    }

    [SupportedOSPlatform("linux")]
    private async Task<ResponseOutcome> IsolateByUid(int uid, int pid, string processName, CancellationToken ct)
    {
        var rule = $"add rule inet behavedr_isolation output meta skuid {uid} counter drop comment \"behavedr:pid:{pid}:{processName}\"";
        var success = await RunNft(rule, ct);

        if (success)
        {
            _logger.LogWarning(
                "[NetworkIsolation] Isolated UID {Uid} (process: {Process}, PID {Pid}) — all outbound traffic dropped",
                uid, processName, pid);
            return ResponseOutcome.Ok(Name, $"Isolated UID {uid} ({processName}) via nftables");
        }

        return ResponseOutcome.Failed(Name, $"nft rule addition failed for UID {uid}");
    }

    [SupportedOSPlatform("linux")]
    private async Task<ResponseOutcome> IsolateByDestination(DetectionResult result, int pid, CancellationToken ct)
    {
        // Extract destination IPs from signal strings (format: "...→IP:PORT:pid:N")
        var ips = new HashSet<string>();
        foreach (var signal in result.Signals)
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                signal.Type, @"→([\d\.]+):\d+");
            if (match.Success)
                ips.Add(match.Groups[1].Value);
        }

        if (ips.Count == 0)
            return ResponseOutcome.Skipped(Name, "No destination IPs found in signals for root process isolation");

        var blocked = 0;
        foreach (var ip in ips)
        {
            var rule = $"add rule inet behavedr_isolation output ip daddr {ip} counter drop comment \"behavedr:c2block:pid:{pid}\"";
            if (await RunNft(rule, ct))
                blocked++;
        }

        if (blocked > 0)
        {
            _logger.LogWarning(
                "[NetworkIsolation] Blocked {Count} C2 destination IPs for root PID {Pid}",
                blocked, pid);
            return ResponseOutcome.Ok(Name, $"Blocked {blocked} C2 IPs via nftables");
        }

        return ResponseOutcome.Failed(Name, "Failed to add nftables rules for C2 IPs");
    }

    [SupportedOSPlatform("linux")]
    private async Task EnsureIsolationTable(CancellationToken ct)
    {
        // Create table and chain if they don't exist
        await RunNft("add table inet behavedr_isolation", ct);
        await RunNft("add chain inet behavedr_isolation output { type filter hook output priority 0 ; policy accept ; }", ct);
        _tableCreated = true;
    }

    /// <summary>
    /// Remove all isolation rules (cleanup on shutdown or manual release).
    /// </summary>
    [SupportedOSPlatform("linux")]
    public async Task ReleaseAllIsolation(CancellationToken ct = default)
    {
        await RunNft("delete table inet behavedr_isolation", ct);
        _tableCreated = false;
        _logger.LogInformation("[NetworkIsolation] All isolation rules released");
    }

    [SupportedOSPlatform("linux")]
    private static async Task<bool> RunNft(string args, CancellationToken ct)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "/usr/sbin/nft",
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            // Try nft first, fall back to /sbin/nft
            if (!File.Exists("/usr/sbin/nft"))
            {
                if (File.Exists("/sbin/nft"))
                    proc.StartInfo.FileName = "/sbin/nft";
                else
                    return false; // nft not installed
            }

            proc.Start();
            await proc.WaitForExitAsync(ct);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
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
}
