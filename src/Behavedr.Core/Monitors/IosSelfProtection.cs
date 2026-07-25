namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS self-protection signals within sandbox (0.2.8).
/// Debugger attach, dyld injection heuristics, time-gap suspension, binary path checks.
/// </summary>
[SupportedOSPlatform("ios")]
public sealed class IosSelfProtection : IPlatformMonitor
{
    private readonly ILogger<IosSelfProtection> _logger;
    private DateTime _lastMono = DateTime.UtcNow;
    private string? _baselineHash;

    public string PlatformName => "IosSelfProtection";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosSelfProtection(ILogger<IosSelfProtection>? logger = null)
    {
        _logger = logger ?? NullLogger<IosSelfProtection>.Instance;
        try
        {
            var path = Environment.ProcessPath;
            if (path is not null && File.Exists(path))
            {
                using var fs = File.OpenRead(path);
                _baselineHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
            }
        }
        catch { }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (Debugger.IsAttached)
            signals.Add(new Signal("ios_debugger_attached", 90, 0.95));

        // Suspension / background freeze gap
        var now = DateTime.UtcNow;
        var gap = (now - _lastMono).TotalSeconds;
        _lastMono = now;
        if (gap > 120)
            signals.Add(new Signal($"ios_execution_gap:{gap:F0}s", 40, 0.55));

        // Dyld insert env (often stripped on iOS but check)
        var dyld = Environment.GetEnvironmentVariable("DYLD_INSERT_LIBRARIES");
        if (!string.IsNullOrEmpty(dyld))
            signals.Add(new Signal("ios_dyld_insert_libraries", 85, 0.9));

        // Binary hash drift (rare on iOS unless re-signed sideload)
        try
        {
            var path = Environment.ProcessPath;
            if (_baselineHash is not null && path is not null && File.Exists(path))
            {
                using var fs = File.OpenRead(path);
                var h = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
                if (!string.Equals(h, _baselineHash, StringComparison.OrdinalIgnoreCase))
                    signals.Add(new Signal("ios_binary_hash_mismatch", 95, 0.99));
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[iOS self-protect] hash check");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }
}
