namespace Behavedr.Core.Monitors;

using System.Net.Http;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Connectivity canary verifying the agent can reach external endpoints.
/// Detects EDRSilencer WFP blocking, DNS poisoning, firewall rules silencing agent traffic.
/// 3 consecutive failures → high-confidence "Network Silencing Detected" signal.
/// </summary>
public class ConnectivityCanaryMonitor : IPlatformMonitor
{
    private readonly ILogger<ConnectivityCanaryMonitor> _logger;
    private readonly HttpClient _http;
    private int _consecutiveFailures;
    private DateTime _lastCheck = DateTime.MinValue;
    private DateTime? _firstFailure;
    private const int CheckIntervalSeconds = 45;

    private static readonly string[] CanaryUrls =
    [
        "https://cloudflare.com/cdn-cgi/trace",
        "https://www.google.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
    ];

    public string PlatformName => "ConnectivityCanary";
    public bool IsSupported => true;

    public ConnectivityCanaryMonitor(ILogger<ConnectivityCanaryMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<ConnectivityCanaryMonitor>.Instance;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("Behavedr-Canary/1.0");
    }

    public async Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if ((DateTime.UtcNow - _lastCheck).TotalSeconds < CheckIntervalSeconds)
            return signals;

        _lastCheck = DateTime.UtcNow;
        var reachable = await CheckConnectivityAsync(ct);

        if (!reachable)
        {
            _consecutiveFailures++;
            _firstFailure ??= DateTime.UtcNow;

            if (_consecutiveFailures >= 3)
            {
                var silenceDuration = DateTime.UtcNow - _firstFailure.Value;
                var confidence = silenceDuration.TotalMinutes > 10 ? 0.95 : 0.85;
                signals.Add(new Signal(
                    $"network_silencing_detected:failures:{_consecutiveFailures}",
                    90, confidence));
                _logger.LogCritical(
                    "SECURITY: Network silencing detected — {Failures} consecutive connectivity failures over {Duration:F0}s",
                    _consecutiveFailures, silenceDuration.TotalSeconds);
            }
        }
        else
        {
            if (_consecutiveFailures >= 3)
                _logger.LogInformation("Network connectivity restored after {Failures} failures", _consecutiveFailures);
            _consecutiveFailures = 0;
            _firstFailure = null;
        }

        return signals;
    }

    private async Task<bool> CheckConnectivityAsync(CancellationToken ct)
    {
        foreach (var url in CanaryUrls)
        {
            try
            {
                var response = await _http.GetAsync(url, ct);
                if (response.IsSuccessStatusCode || (int)response.StatusCode == 204)
                    return true;
            }
            catch { }
        }
        return false;
    }
}
