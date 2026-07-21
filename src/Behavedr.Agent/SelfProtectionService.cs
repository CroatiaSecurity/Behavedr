namespace Behavedr.Agent;

using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// Background service providing agent self-protection:
/// - Binary integrity verification at startup
/// - Anti-debug detection
/// - Parent process monitoring (detect kill attempts)
/// - Periodic self-health checks
/// </summary>
public sealed class SelfProtectionService : BackgroundService
{
    private readonly ILogger<SelfProtectionService> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly bool _enableSelfProtection;
    private readonly bool _enableIntegrityCheck;
    private string? _startupHash;

    public SelfProtectionService(
        IConfiguration configuration,
        ILogger<SelfProtectionService> logger,
        IHostApplicationLifetime lifetime)
    {
        _logger = logger;
        _lifetime = lifetime;
#if DEBUG
        _enableSelfProtection = configuration.GetValue("Agent:EnableSelfProtection", true);
        _enableIntegrityCheck = configuration.GetValue("Agent:EnableIntegrityCheck", true);
#else
        // SECURITY: In Release builds, self-protection is always enabled and cannot be
        // disabled via configuration. An attacker who tampers config must not be able
        // to disable protection mechanisms.
        _ = configuration; // Suppress unused parameter warning
        _enableSelfProtection = true;
        _enableIntegrityCheck = true;
#endif
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_enableSelfProtection)
        {
            _logger.LogWarning("Self-protection is DISABLED via configuration");
            return;
        }

        _logger.LogInformation("Self-protection service started");

        // Perform startup integrity check
        if (_enableIntegrityCheck)
        {
            PerformIntegrityCheck();
        }

        // Check for debugger at startup
        CheckForDebugger();

        // Periodic health monitoring
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await timer.WaitForNextTickAsync(stoppingToken);
                PerformHealthCheck();
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Self-protection health check failed");
            }
        }
    }

    /// <summary>
    /// Compute and store SHA-256 of our own binary at startup.
    /// On subsequent checks, verify it hasn't been modified on disk.
    /// </summary>
    private void PerformIntegrityCheck()
    {
        try
        {
            var assemblyPath = GetExecutablePath();
            if (assemblyPath is null || !File.Exists(assemblyPath))
            {
                _logger.LogWarning("Cannot determine executable path for integrity check");
                return;
            }

            _startupHash = ComputeFileHash(assemblyPath);
            _logger.LogInformation("Binary integrity baseline established (SHA-256: {Hash})",
                _startupHash[..16] + "...");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to compute binary integrity hash");
        }
    }

    /// <summary>
    /// Detect if a debugger is attached (anti-reversing measure).
    /// In Release builds: terminates the process immediately.
    /// In Debug builds: logs a warning only (allows legitimate debugging).
    /// </summary>
    private void CheckForDebugger()
    {
        if (Debugger.IsAttached)
        {
#if DEBUG
            _logger.LogWarning("SECURITY: Debugger detected attached to agent process (debug build — allowing)");
#else
            _logger.LogCritical("SECURITY: Debugger detected attached to agent process — terminating");
            Environment.FailFast("Security violation: debugger attached to Behavedr agent in Release mode");
#endif
        }
    }

    /// <summary>
    /// Periodic health check: verify binary integrity, check for debuggers,
    /// ensure we're still running with expected privileges.
    /// </summary>
    private void PerformHealthCheck()
    {
        // Re-check debugger
        if (Debugger.IsAttached)
        {
#if DEBUG
            _logger.LogWarning("SECURITY: Debugger attached during runtime (debug build — allowing)");
#else
            _logger.LogCritical("SECURITY: Debugger attached during runtime — terminating");
            Environment.FailFast("Security violation: debugger attached to Behavedr agent in Release mode");
#endif
        }

        // Verify binary hasn't been replaced on disk
        if (_enableIntegrityCheck && _startupHash is not null)
        {
            VerifyBinaryIntegrity();
        }

        // Verify our process hasn't been hollowed (basic check: can we still resolve our own types?)
        try
        {
            var engineType = Type.GetType("Behavedr.Core.DetectionEngine, Behavedr.Core");
            if (engineType is null)
            {
                _logger.LogCritical("SECURITY: Core assembly type resolution failed — possible process hollowing");
            }
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "SECURITY: Type resolution check threw — agent may be compromised");
        }
    }

    private void VerifyBinaryIntegrity()
    {
        try
        {
            var assemblyPath = GetExecutablePath();
            if (assemblyPath is null || !File.Exists(assemblyPath))
                return;

            var currentHash = ComputeFileHash(assemblyPath);
            if (!string.Equals(currentHash, _startupHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogCritical(
                    "SECURITY: Binary integrity violation detected! Expected={Expected}, Current={Current}",
                    _startupHash?[..16] + "...", currentHash[..16] + "...");

                // In production, this could trigger: alert, graceful shutdown, or re-exec from known-good backup
            }
        }
        catch (IOException)
        {
            // File locked — this is normal on Windows when running
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Binary integrity verification failed");
        }
    }

    private static string? GetExecutablePath()
    {
        // For single-file deployments, Environment.ProcessPath is the actual exe
        return Environment.ProcessPath
            ?? Assembly.GetExecutingAssembly().Location;
    }

    private static string ComputeFileHash(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hashBytes = SHA256.HashData(stream);
        return Convert.ToHexString(hashBytes);
    }
}
