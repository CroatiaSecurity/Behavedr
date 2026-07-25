namespace Behavedr.Core.Monitors;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS App Attest / device integrity companion monitor (0.2.8).
/// Generates nonces and validates platform-injected attestation results.
/// Full DCAppAttestService calls live in MAUI iOS injection; Core stays portable.
/// </summary>
[SupportedOSPlatform("ios")]
public sealed class IosAppAttestMonitor : IPlatformMonitor
{
    private readonly ILogger<IosAppAttestMonitor> _logger;
    private readonly List<Signal> _injected = new();
    private readonly object _lock = new();
    private string? _token;
    private DateTime _lastNonceAt = DateTime.MinValue;
    private string? _lastNonce;

    public string PlatformName => "IosAppAttest";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosAppAttestMonitor(ILogger<IosAppAttestMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<IosAppAttestMonitor>.Instance;
    }

    public void SetInjectionToken(string token)
    {
        lock (_lock) _token = token;
    }

    public void InjectAttestationSignals(IEnumerable<Signal> signals, string token)
    {
        lock (_lock)
        {
            if (_token is null || !string.Equals(token, _token, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Invalid injection token.");
            _injected.Clear();
            _injected.AddRange(signals);
        }
    }

    /// <summary>Challenge nonce for App Attest / DeviceCheck binding.</summary>
    public string GetOrCreateNonce()
    {
        if (_lastNonce is not null && (DateTime.UtcNow - _lastNonceAt) < TimeSpan.FromMinutes(5))
            return _lastNonce;
        var bytes = RandomNumberGenerator.GetBytes(32);
        _lastNonce = Convert.ToBase64String(bytes);
        _lastNonceAt = DateTime.UtcNow;
        return _lastNonce;
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();
        lock (_lock)
        {
            signals.AddRange(_injected);
            _injected.Clear();
        }

        // Staleness: if no platform injection for a long time, surface soft signal
        if (signals.Count == 0 && (DateTime.UtcNow - _lastNonceAt).TotalHours > 24)
            signals.Add(new Signal("ios_app_attest_stale_or_unwired", 35, 0.5));

        // Always expose current nonce marker for platform layer (low weight telemetry)
        var nonce = GetOrCreateNonce();
        signals.Add(new Signal(
            $"ios_app_attest_nonce:{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)))[..16]}",
            5, 0.3));

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
