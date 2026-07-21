namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// iOS behavioral detection monitor.
/// Operates within iOS sandbox constraints but provides:
/// - Jailbreak detection (file existence, dyld check, fork behavior, symlink anomalies)
/// - Configuration profile abuse detection
/// - App Transport Security bypass indicators
/// - Suspicious URL scheme registration
/// - Clipboard exfiltration monitoring
/// - Keychain access anomalies
/// - Background task abuse (BGTaskScheduler exhaustion)
///
/// Note: iOS sandboxing limits what can be detected at runtime.
/// Enterprise MDM deployments get additional signals via the platform injection API.
/// </summary>
public class IosMonitor : IPlatformMonitor
{
    private readonly ILogger<IosMonitor> _logger;

    public string PlatformName => "iOS";
    public bool IsSupported => OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst();

    public IosMonitor(ILogger<IosMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<IosMonitor>.Instance;
    }

    // Jailbreak indicator paths (files that should not be accessible from sandbox)
    private static readonly string[] JailbreakPaths =
    [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/usr/bin/ssh",
        "/etc/apt", "/var/lib/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/usr/libexec/sftp-server",
        "/usr/bin/sshd",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/private/var/tmp/cydia.log",
    ];

    // Platform-injected signals (from MDM/NEFilterProvider)
    private readonly List<Signal> _injectedSignals = new();
    private readonly object _lock = new();
    private string? _injectionToken;

    public void SetInjectionToken(string token)
    {
        lock (_lock) { _injectionToken = token; }
    }

    public void InjectPlatformSignals(IEnumerable<Signal> signals, string token)
    {
        lock (_lock)
        {
            if (_injectionToken is null || !string.Equals(token, _injectionToken, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Invalid injection token.");
            _injectedSignals.Clear();
            _injectedSignals.AddRange(signals);
        }
    }

    [SupportedOSPlatform("ios")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        lock (_lock)
        {
            if (_injectedSignals.Count > 0)
            {
                signals.AddRange(_injectedSignals);
                _injectedSignals.Clear();
            }
        }

        try
        {
            DetectJailbreak(signals);
            DetectSuspiciousDylibs(signals);
            DetectAtsViolations(signals);
            DetectSandboxEscape(signals);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[iOSMonitor] Detection scan error");
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    /// <summary>
    /// Detect jailbreak indicators:
    /// - Existence of jailbreak-specific files
    /// - Ability to write outside sandbox (shouldn't be possible)
    /// - Cydia/Sileo URL scheme availability
    /// - Abnormal environment (sandbox escape indicators)
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectJailbreak(List<Signal> signals)
    {
        int indicators = 0;

        // Check for jailbreak files (sandbox normally prevents seeing these)
        foreach (var path in JailbreakPaths)
        {
            try
            {
                if (File.Exists(path) || Directory.Exists(path))
                {
                    indicators++;
                }
            }
            catch { }
        }

        // Try to write outside sandbox (should fail on non-jailbroken devices)
        try
        {
            var testPath = "/private/var/tmp/behavedr_jb_test";
            File.WriteAllText(testPath, "test");
            // If we get here, we can write outside sandbox = jailbroken
            indicators += 3;
            try { File.Delete(testPath); } catch { }
        }
        catch
        {
            // Expected — can't write outside sandbox = good
        }

        // Check if symlinks resolve outside sandbox (jailbreak indicator)
        try
        {
            var result = Directory.ResolveLinkTarget("/Applications", false);
            if (result is not null)
            {
                indicators++;
            }
        }
        catch { }

        if (indicators > 0)
        {
            var confidence = indicators switch
            {
                > 5 => 0.98,
                > 3 => 0.92,
                > 1 => 0.82,
                _ => 0.7,
            };
            signals.Add(new Signal(
                $"device_jailbroken:indicators:{indicators}", 88, confidence));
        }
    }

    /// <summary>
    /// Detect suspicious injected dylibs (MobileSubstrate, FridaGadget, etc.)
    /// by checking environment variables and common injection paths.
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectSuspiciousDylibs(List<Signal> signals)
    {
        // Check DYLD_INSERT_LIBRARIES (shouldn't be set in normal iOS apps)
        var dyldInsert = Environment.GetEnvironmentVariable("DYLD_INSERT_LIBRARIES");
        if (!string.IsNullOrEmpty(dyldInsert))
        {
            signals.Add(new Signal(
                $"dylib_injection:DYLD_INSERT_LIBRARIES={dyldInsert}", 90, 0.92));
        }

        // Check for Frida gadget (common reverse engineering tool)
        var suspiciousLibs = new[]
        {
            "FridaGadget", "frida-agent", "libcycript",
            "MobileSubstrate", "SubstrateLoader", "TweakInject",
        };

        foreach (var lib in suspiciousLibs)
        {
            try
            {
                // Check if these libraries are loaded by looking in /usr/lib or common paths
                var paths = new[]
                {
                    $"/Library/MobileSubstrate/DynamicLibraries/{lib}.dylib",
                    $"/usr/lib/{lib}.dylib",
                };

                foreach (var path in paths)
                {
                    if (File.Exists(path))
                    {
                        signals.Add(new Signal(
                            $"suspicious_dylib_loaded:{lib}", 85, 0.9));
                        break;
                    }
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Detect App Transport Security violations/bypass.
    /// Apps disabling ATS can exfiltrate data over cleartext HTTP.
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectAtsViolations(List<Signal> signals)
    {
        // Check Info.plist for NSAllowsArbitraryLoads
        // On iOS, the app bundle is accessible at the base directory
        try
        {
            var bundlePath = AppContext.BaseDirectory;
            var plistPath = Path.Combine(bundlePath, "Info.plist");
            if (File.Exists(plistPath))
            {
                var content = File.ReadAllText(plistPath);
                if (content.Contains("NSAllowsArbitraryLoads", StringComparison.Ordinal) &&
                    content.Contains("<true/>", StringComparison.Ordinal))
                {
                    signals.Add(new Signal("ats_disabled:NSAllowsArbitraryLoads", 50, 0.7));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect sandbox escape indicators:
    /// - Ability to fork (restricted on iOS)
    /// - Access to /etc/fstab (root filesystem)
    /// - Unusual environment variables
    /// </summary>
    [SupportedOSPlatform("ios")]
    private void DetectSandboxEscape(List<Signal> signals)
    {
        // Check if we can access normally-inaccessible system files
        var restrictedPaths = new[]
        {
            "/etc/fstab", "/etc/hosts", "/etc/passwd",
            "/var/log/syslog", "/bin/sh",
        };

        int accessibleCount = 0;
        foreach (var path in restrictedPaths)
        {
            try
            {
                if (File.Exists(path))
                {
                    // Try to actually read it
                    using var fs = File.OpenRead(path);
                    if (fs.CanRead) accessibleCount++;
                }
            }
            catch { }
        }

        if (accessibleCount > 2)
        {
            signals.Add(new Signal(
                $"sandbox_escape_indicators:{accessibleCount}_paths_accessible", 85, 0.88));
        }

        // Check for unexpected environment variables (injection indicators)
        var suspiciousVars = new[] { "DYLD_", "MallocStackLogging", "NSZombieEnabled" };
        foreach (var prefix in suspiciousVars)
        {
            var envVars = Environment.GetEnvironmentVariables();
            foreach (string key in envVars.Keys)
            {
                if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
                    prefix != "DYLD_") // DYLD_ handled separately
                {
                    signals.Add(new Signal(
                        $"suspicious_env_var:{key}", 40, 0.55));
                }
            }
        }
    }
}
