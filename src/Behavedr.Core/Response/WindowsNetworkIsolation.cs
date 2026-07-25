namespace Behavedr.Core.Response;

using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Userland Windows network isolation via Windows Firewall (advfirewall).
/// Blocks observed C2 / remote IPs and optionally outbound traffic for a process image path.
/// Not a WFP callout driver — suitable for userland EDR without kernel signing.
/// Requires elevation (SYSTEM service context).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsNetworkIsolation : IResponseAction, IDisposable
{
    private readonly ILogger<WindowsNetworkIsolation> _logger;
    private readonly WindowsWfpEngine _wfp;
    private readonly HashSet<string> _blockedIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private const int MaxRules = 100;

    // Public DNS — never blackhole (same policy as macOS isolation)
    private static readonly HashSet<string> NeverBlock = new(StringComparer.OrdinalIgnoreCase)
    {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
        "208.67.222.222", "208.67.220.220", "127.0.0.1", "::1",
    };

    public string Name => "WindowsNetworkIsolation";
    public bool IsSupported => OperatingSystem.IsWindows();

    public WindowsNetworkIsolation(ILogger<WindowsNetworkIsolation>? logger = null)
    {
        _logger = logger ?? NullLogger<WindowsNetworkIsolation>.Instance;
        _wfp = new WindowsWfpEngine(_logger);
    }

    public void Dispose() => _wfp.Dispose();

    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return ResponseOutcome.Skipped(Name, "Not Windows");

        var ips = ExtractRemoteIps(result);
        if (ips.Count == 0)
        {
            // Fall back: block outbound for process image if we can resolve it
            if (int.TryParse(result.Event.ProcessId, out var pid) && pid > 4)
            {
                var image = TryGetProcessImage(pid);
                if (!string.IsNullOrEmpty(image) && File.Exists(image))
                    return await BlockProcessImageAsync(image, result.Event.ProcessName, ct);
            }
            return ResponseOutcome.Skipped(Name, "No remote IPs or process image to isolate");
        }

        int blocked = 0;
        foreach (var ip in ips)
        {
            ct.ThrowIfCancellationRequested();
            if (await BlockIpAsync(ip, result.Event.ProcessName, ct))
                blocked++;
        }

        return blocked > 0
            ? ResponseOutcome.Ok(Name, $"Blocked {blocked} remote IP(s) for {result.Event.ProcessName}")
            : ResponseOutcome.Skipped(Name, "No new IPs blocked (limit, DNS protect, or netsh failure)");
    }

    private async Task<bool> BlockIpAsync(string ip, string processName, CancellationToken ct)
    {
        if (NeverBlock.Contains(ip) || IsPrivateOrLinkLocal(ip))
            return false;

        lock (_lock)
        {
            if (_blockedIps.Count >= MaxRules)
            {
                _logger.LogWarning("[WinNetIsolation] Rule limit {Max} reached", MaxRules);
                return false;
            }
            if (!_blockedIps.Add(ip))
                return false;
        }

        // Prefer real WFP filter engine; fall back to advfirewall (also WFP-backed) via netsh.
        if (IPAddress.TryParse(ip, out var addr) && _wfp.BlockRemoteAddress(addr, $"Behavedr:{processName}"))
        {
            _logger.LogWarning("[WinNetIsolation] WFP blocked remote IP {Ip} ({Process})", ip, processName);
            return true;
        }

        var safeName = $"BehavedrBlock_{ip.Replace(':', '_').Replace('.', '_')}";
        var args =
            $"advfirewall firewall add rule name=\"{safeName}\" " +
            $"dir=out action=block remoteip={ip} enable=yes " +
            $"description=\"Behavedr isolation for {Sanitize(processName)}\"";

        var ok = await RunNetshAsync(args, ct);
        if (ok)
        {
            _logger.LogWarning("[WinNetIsolation] advfirewall blocked remote IP {Ip} ({Process})", ip, processName);
            return true;
        }

        lock (_lock) { _blockedIps.Remove(ip); }
        return false;
    }

    private async Task<ResponseOutcome> BlockProcessImageAsync(string imagePath, string processName, CancellationToken ct)
    {
        var hash = Math.Abs(imagePath.GetHashCode(StringComparison.OrdinalIgnoreCase));
        var ruleName = $"BehavedrBlockProg_{hash:X8}";
        var args =
            $"advfirewall firewall add rule name=\"{ruleName}\" " +
            $"dir=out action=block program=\"{imagePath}\" enable=yes " +
            $"description=\"Behavedr process isolation for {Sanitize(processName)}\"";

        var ok = await RunNetshAsync(args, ct);
        return ok
            ? ResponseOutcome.Ok(Name, $"Blocked outbound for {processName} image")
            : ResponseOutcome.Failed(Name, "netsh process block failed (need elevation?)");
    }

    private static async Task<bool> RunNetshAsync(string arguments, CancellationToken ct)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                },
            };
            proc.Start();
            await proc.WaitForExitAsync(ct);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static List<string> ExtractRemoteIps(DetectionResult result)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ipv4 = Ipv4Regex();
        foreach (var signal in result.Signals)
        {
            foreach (Match m in ipv4.Matches(signal.Type ?? ""))
                found.Add(m.Value);
        }
        // Also scan process path / command line style fields on the event if present
        foreach (Match m in ipv4.Matches(result.Event.ProcessName ?? ""))
            found.Add(m.Value);

        return found.ToList();
    }

    private static string? TryGetProcessImage(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsPrivateOrLinkLocal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return true;
        var b = addr.GetAddressBytes();
        if (b.Length != 4) return false; // allow blocking public IPv6-ish strings carefully
        if (b[0] == 10) return true;
        if (b[0] == 127) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        return false;
    }

    private static string Sanitize(string s) =>
        string.Concat(s.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.').Take(40));

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")]
    private static partial Regex Ipv4Regex();
}
