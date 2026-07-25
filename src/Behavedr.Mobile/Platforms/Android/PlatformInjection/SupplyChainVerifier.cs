using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography;

using Signal = Behavedr.Core.Models.Signal;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Supply chain verification for the Behavedr APK itself.
///
/// Protects against:
/// 1. APK repackaging (attacker modifies APK and re-signs with different key)
/// 2. Sideloaded malicious builds (modified agent reporting to attacker C2)
/// 3. Downgrade attacks (installing older vulnerable version)
/// 4. Debug build deployment (debug key leaks, instrumentation enabled)
/// 5. Installer manipulation (non-Play Store installation in enterprise environment)
///
/// Verification methods:
/// - APK signing certificate fingerprint pinning (SHA-256 of cert)
/// - Installer package validation (must come from trusted source)
/// - Version code anti-rollback (current >= minimum_allowed)
/// - Debug key detection (reject debug-signed builds in production)
/// - Binary integrity check (DEX file hash verification)
///
/// v0.2.0 audit: Closes supply chain attack surface on Android.
/// </summary>
public sealed class SupplyChainVerifier
{
    private readonly Context _context;
    private readonly ILogger _logger;

    /// <summary>
    /// Expected signing certificate SHA-256 fingerprints (hex, no colons).
    /// Configure via <c>BEHAVEDR_ANDROID_CERT_SHA256</c> (comma-separated) and/or
    /// compile-time embeds below. Empty set = pin not configured (fail-closed signal).
    /// Generate: <c>apksigner verify --print-certs app.apk</c> then strip colons.
    /// </summary>
    private static readonly HashSet<string> TrustedCertFingerprints = LoadTrustedFingerprints();

    private static HashSet<string> LoadTrustedFingerprints()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Optional compile-time pins (leave empty until you have real release certs).
        // Do NOT put PLACEHOLDER strings here — they would look like trust and are rejected.
        foreach (var builtIn in new[]
        {
            // "YOUR_RELEASE_CERT_SHA256_HEX",
            // "YOUR_PLAY_UPLOAD_CERT_SHA256_HEX",
        })
        {
            AddFingerprint(set, builtIn);
        }

        var env = Environment.GetEnvironmentVariable("BEHAVEDR_ANDROID_CERT_SHA256");
        if (!string.IsNullOrWhiteSpace(env))
        {
            foreach (var part in env.Split([',', ';', ' ', '\n', '\r', '\t'],
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                AddFingerprint(set, part);
        }
        return set;
    }

    private static void AddFingerprint(HashSet<string> set, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return;
        if (raw.Contains("PLACEHOLDER", StringComparison.OrdinalIgnoreCase)) return;
        var n = NormalizeFingerprint(raw);
        if (n.Length >= 32) // SHA-256 hex is 64; allow shorter only if operator error but skip junk
            set.Add(n);
    }

    private static string NormalizeFingerprint(string raw) =>
        raw.Replace(":", "", StringComparison.Ordinal)
           .Replace(" ", "", StringComparison.Ordinal)
           .Trim()
           .ToUpperInvariant();

    public static bool IsSignerPinConfigured => TrustedCertFingerprints.Count > 0;

    // Trusted installer packages (sources allowed to install Behavedr)
    private static readonly HashSet<string> TrustedInstallers = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.android.vending",           // Google Play Store
        "com.google.android.packageinstaller", // System installer
        "com.android.packageinstaller",  // AOSP installer
        "com.sec.android.app.samsungapps", // Samsung Galaxy Store
        "com.microsoft.intune.mam",      // Microsoft Intune
        "com.google.android.apps.work.cloud", // Google Workspace
    };

    // Minimum allowed version code (anti-rollback)
    private const int MinimumVersionCode = 7;

    private bool _verified;
    private VerificationResult? _cachedResult;

    public SupplyChainVerifier(Context context, ILogger? logger = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Perform full supply chain verification. Should be called at startup.
    /// Returns signals for any verification failures.
    /// </summary>
    public IReadOnlyList<Signal> Verify()
    {
        if (_verified && _cachedResult is not null)
            return _cachedResult.Signals;

        var signals = new List<Signal>();
        var result = new VerificationResult(signals);

        VerifySigningCertificate(signals);
        VerifyInstallerSource(signals);
        VerifyVersionAntiRollback(signals);
        VerifyNotDebugBuild(signals);
        VerifyBinaryIntegrity(signals);
        VerifyNotTestSigned(signals);

        _cachedResult = result;
        _verified = true;

        if (signals.Any(s => s.Weight >= 80))
        {
            _logger.LogCritical("[SupplyChain] CRITICAL verification failure — agent may be compromised");
        }
        else if (signals.Count > 0)
        {
            _logger.LogWarning("[SupplyChain] {Count} verification warnings", signals.Count);
        }
        else
        {
            _logger.LogInformation("[SupplyChain] All verifications passed");
        }

        return signals;
    }

    /// <summary>
    /// Verify the APK signing certificate matches our pinned fingerprints.
    /// This is the PRIMARY defense against repackaging attacks.
    /// </summary>
    private void VerifySigningCertificate(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return;

            PackageInfo? pkgInfo;

            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
                // API 28+: Use GET_SIGNING_CERTIFICATES
#pragma warning disable CA1416
                pkgInfo = pm.GetPackageInfo(_context.PackageName!,
                    (PackageInfoFlags)((long)PackageInfoFlags.SigningCertificates));

                var signingInfo = pkgInfo?.SigningInfo;
                if (signingInfo is null)
                {
                    signals.Add(new Signal("supply_chain:no_signing_info", 90, 0.95));
#pragma warning restore CA1416
                    return;
                }

                var signers = signingInfo.HasMultipleSigners
                    ? signingInfo.GetApkContentsSigners()?.ToArray()
                    : signingInfo.GetSigningCertificateHistory()?.ToArray();
#pragma warning restore CA1416

                if (signers is null || signers.Length == 0)
                {
                    signals.Add(new Signal("supply_chain:no_signers", 90, 0.95));
                    return;
                }

                EvaluateSignerTrust(signers, signals, isDebuggable: IsDebuggableApp());
            }
            else
            {
                // Pre-P: Use deprecated GET_SIGNATURES
#pragma warning disable CS0618, CA1422
                pkgInfo = pm.GetPackageInfo(_context.PackageName!,
                    PackageInfoFlags.Signatures);

                var sigs = pkgInfo?.Signatures;
                if (sigs is null || sigs.Count == 0)
                {
                    signals.Add(new Signal("supply_chain:no_signatures", 90, 0.95));
                    return;
                }

                EvaluateSignerTrust(sigs.ToArray(), signals, isDebuggable: IsDebuggableApp());
#pragma warning restore CS0618, CA1422
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[SupplyChain] Certificate verification error");
            signals.Add(new Signal("supply_chain:cert_verify_error", 50, 0.6));
        }
    }

    /// <summary>
    /// Fail-closed cert pin: PLACEHOLDER strings never count as trusted.
    /// Unconfigured pin is a high-severity ops signal on non-debug builds.
    /// </summary>
    private void EvaluateSignerTrust(Android.Content.PM.Signature[]? signers, List<Signal> signals, bool isDebuggable)
    {
        if (signers is null || signers.Length == 0)
        {
            signals.Add(new Signal("supply_chain:no_signers", 90, 0.95));
            return;
        }

        if (!IsSignerPinConfigured)
        {
            // Never pretend trust. Debug builds: warning only. Release: high weight.
            var weight = isDebuggable ? 40 : 88;
            signals.Add(new Signal(
                "supply_chain:signer_pin_not_configured:set_BEHAVEDR_ANDROID_CERT_SHA256",
                weight, isDebuggable ? 0.55 : 0.92));
            _logger.LogWarning(
                "[SupplyChain] No trusted cert fingerprints configured. " +
                "Set BEHAVEDR_ANDROID_CERT_SHA256 or embed release pins. Pin not configured ≠ trusted.");
            return;
        }

        bool foundTrusted = false;
        foreach (var sig in signers)
        {
            var certBytes = sig?.ToByteArray();
            if (certBytes is null) continue;
            var fingerprint = NormalizeFingerprint(Convert.ToHexString(SHA256.HashData(certBytes)));
            if (TrustedCertFingerprints.Contains(fingerprint))
            {
                foundTrusted = true;
                break;
            }
        }

        if (!foundTrusted)
        {
            signals.Add(new Signal("supply_chain:untrusted_signer", 95, 0.98));
            _logger.LogCritical("[SupplyChain] APK signed with UNTRUSTED certificate — possible repackaging!");
        }
    }

    private bool IsDebuggableApp()
    {
        try
        {
            var appInfo = _context.PackageManager?.GetApplicationInfo(_context.PackageName!, 0);
            return appInfo is not null && (appInfo.Flags & ApplicationInfoFlags.Debuggable) != 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// Verify the APK was installed from a trusted source.
    /// Sideloaded agents could be modified malicious builds.
    /// </summary>
    private void VerifyInstallerSource(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return;

            string? installerPackage;

            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
            {
#pragma warning disable CA1416
                var installSource = pm.GetInstallSourceInfo(_context.PackageName!);
                installerPackage = installSource?.InstallingPackageName;
#pragma warning restore CA1416
            }
            else
            {
#pragma warning disable CS0618, CA1422
                installerPackage = pm.GetInstallerPackageName(_context.PackageName!);
#pragma warning restore CS0618, CA1422
            }

            if (string.IsNullOrEmpty(installerPackage))
            {
                // No installer — likely sideloaded via adb or file manager
                signals.Add(new Signal("supply_chain:sideloaded_agent", 60, 0.78));
                _logger.LogWarning("[SupplyChain] Agent was sideloaded (no installer package)");
            }
            else if (!TrustedInstallers.Contains(installerPackage))
            {
                signals.Add(new Signal($"supply_chain:untrusted_installer:{installerPackage}", 55, 0.72));
                _logger.LogWarning("[SupplyChain] Agent installed by untrusted source: {Installer}",
                    installerPackage);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[SupplyChain] Installer source check failed");
        }
    }

    /// <summary>
    /// Verify version code is >= minimum allowed.
    /// Prevents downgrade attacks where attacker installs older vulnerable version.
    /// </summary>
    private void VerifyVersionAntiRollback(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            var pkgInfo = pm?.GetPackageInfo(_context.PackageName!, 0);
            if (pkgInfo is null) return;

            long versionCode;
            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
#pragma warning disable CA1416
                versionCode = pkgInfo.LongVersionCode;
#pragma warning restore CA1416
            }
            else
            {
#pragma warning disable CS0618, CA1422
                versionCode = pkgInfo.VersionCode;
#pragma warning restore CS0618, CA1422
            }

            if (versionCode < MinimumVersionCode)
            {
                signals.Add(new Signal(
                    $"supply_chain:version_rollback:v{versionCode}<min{MinimumVersionCode}", 80, 0.9));
                _logger.LogCritical(
                    "[SupplyChain] Version rollback detected! Current={Current}, Minimum={Min}",
                    versionCode, MinimumVersionCode);
            }
        }
        catch { }
    }

    /// <summary>
    /// Detect if running a debug build. Debug builds have reduced security
    /// and are instrumentation-friendly — should never be deployed to production.
    /// </summary>
    private void VerifyNotDebugBuild(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            var appInfo = pm?.GetApplicationInfo(_context.PackageName!, 0);
            if (appInfo is null) return;

            if ((appInfo.Flags & ApplicationInfoFlags.Debuggable) != 0)
            {
                signals.Add(new Signal("supply_chain:debug_build", 75, 0.88));
                _logger.LogCritical("[SupplyChain] Running a DEBUG build — " +
                    "instrumentation attacks are trivial!");
            }
        }
        catch { }
    }

    /// <summary>
    /// Verify binary integrity by hashing the APK file itself.
    /// Detects on-disk modification after installation (requires root to exploit,
    /// but we detect it anyway for defense-in-depth).
    /// </summary>
    private void VerifyBinaryIntegrity(List<Signal> signals)
    {
        try
        {
            var pm = _context.PackageManager;
            var appInfo = pm?.GetApplicationInfo(_context.PackageName!, 0);
            var apkPath = appInfo?.SourceDir;
            if (apkPath is null || !File.Exists(apkPath)) return;

            // Compute APK hash
            using var stream = File.OpenRead(apkPath);
            var hash = Convert.ToHexString(SHA256.HashData(stream));

            // Store hash for comparison on subsequent runs
            var hashFile = Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "security", "apk_hash.txt");

            var hashDir = Path.GetDirectoryName(hashFile);
            if (hashDir is not null) Directory.CreateDirectory(hashDir);

            if (File.Exists(hashFile))
            {
                var storedHash = File.ReadAllText(hashFile).Trim();
                if (!string.Equals(storedHash, hash, StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("supply_chain:apk_modified_on_disk", 90, 0.95));
                    _logger.LogCritical("[SupplyChain] APK file modified on disk!");
                }
            }

            File.WriteAllText(hashFile, hash);
        }
        catch { }
    }

    /// <summary>
    /// Detect if the APK is signed with Android's debug/test key.
    /// The debug key has a known fingerprint that any developer has access to.
    /// </summary>
    private void VerifyNotTestSigned(List<Signal> signals)
    {
        // Android debug keystore CN=Android Debug, O=Android
        // The debug key SHA-256 varies per machine, but we can check the subject
        try
        {
            var pm = _context.PackageManager;
            if (pm is null) return;

            PackageInfo? pkgInfo;
            Android.Content.PM.Signature[]? sigs;

            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
#pragma warning disable CA1416
                pkgInfo = pm.GetPackageInfo(_context.PackageName!,
                    (PackageInfoFlags)((long)PackageInfoFlags.SigningCertificates));
                var signingInfo = pkgInfo?.SigningInfo;
                sigs = signingInfo?.HasMultipleSigners == true
                    ? signingInfo.GetApkContentsSigners()?.ToArray()
                    : signingInfo?.GetSigningCertificateHistory()?.ToArray();
#pragma warning restore CA1416
            }
            else
            {
#pragma warning disable CS0618, CA1422
                pkgInfo = pm.GetPackageInfo(_context.PackageName!,
                    PackageInfoFlags.Signatures);
                sigs = pkgInfo?.Signatures?.ToArray();
#pragma warning restore CS0618, CA1422
            }

            if (sigs is null) return;

            foreach (var sig in sigs)
            {
                var certBytes = sig?.ToByteArray();
                if (certBytes is null) continue;

                // Parse X.509 certificate to check issuer
                // A debug cert typically has "CN=Android Debug" in the subject
                var certStr = System.Text.Encoding.UTF8.GetString(certBytes);
                if (certStr.Contains("Android Debug", StringComparison.OrdinalIgnoreCase) ||
                    certStr.Contains("CN=Android Debug", StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new Signal("supply_chain:debug_key_signed", 80, 0.9));
                    _logger.LogCritical("[SupplyChain] APK signed with Android debug key!");
                    break;
                }
            }
        }
        catch { }
    }
}

internal record VerificationResult(List<Signal> Signals);
