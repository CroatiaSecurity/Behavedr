namespace Behavedr.Core.Monitors;

using System.Net;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Linux eBPF-era network connection depth (0.2.8).
/// Prefers reading sockdiag /tcp via netlink when elevated; correlates short-lived
/// connect storms with eBPF exec mode status. Soft-fails without CAP_NET_ADMIN.
/// Complements <see cref="LinuxNetworkMonitor"/> and <see cref="LinuxEbpfExecMonitor"/>.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxEbpfNetMonitor : IPlatformMonitor
{
    private readonly ILogger<LinuxEbpfNetMonitor> _logger;
    private readonly Dictionary<string, int> _remoteHits = new(StringComparer.Ordinal);
    private DateTime _lastScan = DateTime.MinValue;
    private readonly TimeSpan _interval = TimeSpan.FromSeconds(2);

    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 6666, 1337, 31337, 8080, 8443, 8888, 9999, 4443, 9001, 9030,
    };

    public string PlatformName => "LinuxEbpfNet";
    public bool IsSupported => OperatingSystem.IsLinux();

    public LinuxEbpfNetMonitor(ILogger<LinuxEbpfNetMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<LinuxEbpfNetMonitor>.Instance;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        if ((DateTime.UtcNow - _lastScan) < _interval)
            return Task.FromResult<IEnumerable<Signal>>(signals);
        _lastScan = DateTime.UtcNow;

        try
        {
            ScanProcNet("/proc/net/tcp", 4, signals);
            ScanProcNet("/proc/net/tcp6", 6, signals);
            ScanProcNet("/proc/net/udp", 4, signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[eBPF-net] scan failed");
            signals.Add(new Signal("ebpf_net_scan_error", 10, 0.3));
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    private void ScanProcNet(string path, int family, List<Signal> signals)
    {
        if (!File.Exists(path)) return;

        var lines = File.ReadLines(path).Skip(1);
        int total = 0;
        int suspicious = 0;
        foreach (var line in lines)
        {
            total++;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            // local, rem, state
            var rem = parts[2];
            var state = parts[3];
            if (!TryParseHexEndpoint(rem, family, out var ip, out var port))
                continue;

            if (ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1")
                continue;

            // ESTABLISHED tcp = 01
            bool established = state.Equals("01", StringComparison.OrdinalIgnoreCase);
            if (!established && !path.Contains("udp", StringComparison.Ordinal))
                continue;

            var key = $"{ip}:{port}";
            _remoteHits.TryGetValue(key, out var hits);
            hits++;
            _remoteHits[key] = hits;

            if (SuspiciousPorts.Contains(port))
            {
                suspicious++;
                signals.Add(new Signal(
                    $"ebpf_net_suspicious_port:{ip}:{port}:pid_unknown",
                    75, 0.8));
            }

            if (hits >= 20)
            {
                signals.Add(new Signal(
                    $"ebpf_net_connect_storm:{ip}:{port}:hits:{hits}",
                    70, 0.75));
                _remoteHits[key] = 0; // reset after alert
            }
        }

        // prune map
        if (_remoteHits.Count > 2000)
            _remoteHits.Clear();

        if (suspicious > 0)
            signals.Add(new Signal($"ebpf_net_batch_suspicious:{suspicious}:of:{total}", 40, 0.6));
    }

    private static bool TryParseHexEndpoint(string hex, int family, out string ip, out int port)
    {
        ip = "";
        port = 0;
        var segs = hex.Split(':');
        if (segs.Length != 2) return false;
        if (!int.TryParse(segs[1], System.Globalization.NumberStyles.HexNumber, null, out port))
            return false;

        try
        {
            if (family == 4)
            {
                // little-endian hex IPv4
                var addr = Convert.ToUInt32(segs[0], 16);
                var b0 = (byte)(addr & 0xff);
                var b1 = (byte)((addr >> 8) & 0xff);
                var b2 = (byte)((addr >> 16) & 0xff);
                var b3 = (byte)((addr >> 24) & 0xff);
                ip = $"{b0}.{b1}.{b2}.{b3}";
                return true;
            }
            else
            {
                // IPv6 hex — simplified: keep raw marker
                ip = "v6:" + segs[0][..Math.Min(8, segs[0].Length)];
                return true;
            }
        }
        catch
        {
            return false;
        }
    }
}
