namespace Behavedr.Core.Monitors;

using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS network posture monitor (0.2.8). Sandbox-limited: interface flags, proxy,
/// VPN path detection, injected NE filter signals. Not a full packet inspection stack
/// without Network Extension entitlement.
/// </summary>
[SupportedOSPlatform("ios")]
public sealed class IosNetworkMonitor : IPlatformMonitor
{
    private readonly ILogger<IosNetworkMonitor> _logger;
    private readonly List<Signal> _injected = new();
    private readonly object _lock = new();
    private string? _token;

    public string PlatformName => "IosNetwork";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosNetworkMonitor(ILogger<IosNetworkMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<IosNetworkMonitor>.Instance;
    }

    public void SetInjectionToken(string token)
    {
        lock (_lock) _token = token;
    }

    public void InjectNetworkSignals(IEnumerable<Signal> signals, string token)
    {
        lock (_lock)
        {
            if (_token is null || !string.Equals(token, _token, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Invalid injection token.");
            _injected.Clear();
            _injected.AddRange(signals);
        }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        lock (_lock)
        {
            signals.AddRange(_injected);
            _injected.Clear();
        }

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                var name = ni.Name ?? "";
                var desc = ni.Description ?? "";
                // Common VPN/tunnel interface names
                if (name.Contains("utun", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("ppp", StringComparison.OrdinalIgnoreCase) ||
                    desc.Contains("VPN", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal($"ios_vpn_interface:{name}", 30, 0.6));
                }
            }

            // HTTP proxy env (MDM or attacker)
            var httpProxy = Environment.GetEnvironmentVariable("http_proxy")
                ?? Environment.GetEnvironmentVariable("HTTP_PROXY")
                ?? Environment.GetEnvironmentVariable("ALL_PROXY");
            if (!string.IsNullOrEmpty(httpProxy))
                signals.Add(new Signal("ios_http_proxy_configured", 45, 0.7));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[iOS net] enumeration failed");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
