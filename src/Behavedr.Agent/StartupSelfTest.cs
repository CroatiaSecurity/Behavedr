namespace Behavedr.Agent;

using Behavedr.Core;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Pre-flight checks before monitors are trusted (pattern from Sentinel StartupSelfTest).
/// Validates crypto, config integrity, monitor registration, quarantine path, and key protection.
/// </summary>
public sealed class StartupSelfTest : IHostedService
{
    private readonly DetectionEngine _engine;
    private readonly ResponseEngine _responseEngine;
    private readonly ILogger<StartupSelfTest> _logger;

    public StartupSelfTest(
        DetectionEngine engine,
        ResponseEngine responseEngine,
        ILogger<StartupSelfTest> logger)
    {
        _engine = engine;
        _responseEngine = responseEngine;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[StartupSelfTest] Running pre-flight checks...");
        int passed = 0, failed = 0;

        // 1. SecureEnvelope seal/unseal round-trip
        try
        {
            var payload = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var sealedData = SecureEnvelope.Seal(payload, "selftest");
            var opened = SecureEnvelope.Unseal(sealedData, "selftest");
            if (opened is not null && opened.AsSpan().SequenceEqual(payload))
                passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] SecureEnvelope round-trip FAILED");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] SecureEnvelope check FAILED");
        }

        // 2. Machine key available
        try
        {
            var key = KeyProtection.GetMachineKey();
            if (key is { Length: 32 }) passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] Machine key length invalid");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Machine key check FAILED");
        }

        // 3. Monitors registered for this platform
        try
        {
            var count = _engine.RegisteredMonitors.Count;
            if (count > 0)
            {
                passed++;
                _logger.LogInformation("[StartupSelfTest] {Count} monitors registered ({Platform})",
                    count, PlatformMonitors.CurrentPlatformSummary());
            }
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] No monitors registered");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Monitor count check FAILED");
        }

        // 4. At least one response action registered
        try
        {
            if (_responseEngine.RegisteredActions.Count > 0) passed++;
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] No response actions registered");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Response actions check FAILED");
        }

        // 5. Quarantine + buffer directories writable
        try
        {
            foreach (var dir in new[] { "quarantine", "buffer", "logs" })
            {
                Directory.CreateDirectory(dir);
                var probe = Path.Combine(dir, $".selftest-{Guid.NewGuid():N}");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
            }
            passed++;
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Directory writability FAILED");
        }

        // 6. Update signature verifier has a production key baked in
        try
        {
            if (UpdateSignatureVerifier.IsProductionKeyConfigured())
            {
                passed++;
            }
            else
            {
                failed++;
                _logger.LogWarning("[StartupSelfTest] Update signing public key is PLACEHOLDER (dev mode)");
            }
        }
        catch (Exception ex)
        {
            failed++;
            _logger.LogWarning(ex, "[StartupSelfTest] Update key check FAILED");
        }

        if (failed == 0)
            _logger.LogInformation("[StartupSelfTest] All {Passed} checks PASSED", passed);
        else
            _logger.LogWarning("[StartupSelfTest] {Passed} passed, {Failed} FAILED — agent continues with degraded confidence",
                passed, failed);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
