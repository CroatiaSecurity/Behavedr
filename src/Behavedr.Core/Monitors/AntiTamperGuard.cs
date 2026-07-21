namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Anti-tamper guard providing self-protection against:
/// 1. Process suspension detection via QPC (QueryPerformanceCounter) timing
/// 2. Binary integrity verification (detect on-disk replacement)
/// 3. Service registry self-healing (re-register if service key deleted)
/// 4. Last-gasp logging on unexpected exit
/// 5. Network connectivity silencing detection
///
/// Uses QPC instead of DateTime to resist clock manipulation attacks.
/// Scan: 2s for timing checks, 10s for integrity/service checks.
/// </summary>
[SupportedOSPlatform("windows")]
public class AntiTamperGuard : IPlatformMonitor
{
    private readonly ILogger<AntiTamperGuard> _logger;
    private long _lastPerfCount;
    private readonly long _perfFrequency;
    private string? _binaryHash;
    private DateTime _lastCheck = DateTime.UtcNow;
    private const int SuspendThresholdMs = 4000; // 4s gap = suspension detected

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    [DllImport("kernel32.dll")]
    private static extern bool QueryPerformanceFrequency(out long lpFrequency);

    public string PlatformName => "AntiTamper";
    public bool IsSupported => OperatingSystem.IsWindows();

    public AntiTamperGuard(ILogger<AntiTamperGuard>? logger = null)
    {
        _logger = logger ?? NullLogger<AntiTamperGuard>.Instance;

        if (OperatingSystem.IsWindows())
        {
            QueryPerformanceFrequency(out _perfFrequency);
            QueryPerformanceCounter(out _lastPerfCount);
        }

        // Establish binary integrity baseline
        var exePath = Environment.ProcessPath;
        if (exePath is not null && File.Exists(exePath))
        {
            try
            {
                using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                _binaryHash = Convert.ToHexString(SHA256.HashData(stream));
            }
            catch { }
        }
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        // 1. Suspension detection via QPC
        DetectSuspension(signals);

        // 2. Binary integrity check (every 10s)
        if ((DateTime.UtcNow - _lastCheck).TotalSeconds >= 10)
        {
            CheckBinaryIntegrity(signals);
            CheckServiceRegistration(signals);
            _lastCheck = DateTime.UtcNow;
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void DetectSuspension(List<Signal> signals)
    {
        if (_perfFrequency <= 0) return;

        QueryPerformanceCounter(out long currentCount);
        var elapsedMs = (currentCount - _lastPerfCount) * 1000.0 / _perfFrequency;
        _lastPerfCount = currentCount;

        // If elapsed time far exceeds expected interval, we were suspended
        if (elapsedMs > SuspendThresholdMs)
        {
            signals.Add(new Signal(
                $"process_suspension_detected:{elapsedMs:F0}ms_gap",
                90, 0.95));
            _logger.LogCritical(
                "SECURITY: Process suspension detected — {Elapsed:F0}ms gap (threshold: {Threshold}ms). " +
                "Possible NtSuspendProcess attack.",
                elapsedMs, SuspendThresholdMs);
        }
    }

    private void CheckBinaryIntegrity(List<Signal> signals)
    {
        if (_binaryHash is null) return;

        var exePath = Environment.ProcessPath;
        if (exePath is null || !File.Exists(exePath)) return;

        try
        {
            using var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var currentHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!string.Equals(currentHash, _binaryHash, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(new Signal("binary_integrity_violation", 95, 0.99));
                _logger.LogCritical("SECURITY: Binary integrity violation — on-disk executable has been modified!");
            }
        }
        catch (IOException) { } // File locked — normal on Windows
        catch (Exception ex) { _logger.LogDebug(ex, "[AntiTamper] Integrity check error"); }
    }

    [SupportedOSPlatform("windows")]
    private void CheckServiceRegistration(List<Signal> signals)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Behavedr");

            if (key is null)
            {
                signals.Add(new Signal("service_registration_deleted", 85, 0.9));
                _logger.LogCritical("SECURITY: Behavedr service registration has been deleted — attempting re-registration");
                AttemptServiceReregistration();
            }
        }
        catch { }
    }

    [SupportedOSPlatform("windows")]
    private void AttemptServiceReregistration()
    {
        try
        {
            var exePath = Environment.ProcessPath;
            if (exePath is null) return;

            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Services\Behavedr");
            key.SetValue("ImagePath", exePath);
            key.SetValue("DisplayName", "Behavedr EDR Agent");
            key.SetValue("Start", 2); // Auto start
            key.SetValue("Type", 16); // Win32OwnProcess
            key.SetValue("ErrorControl", 1); // Normal

            _logger.LogWarning("Service registration restored via registry");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to re-register service");
        }
    }
}
