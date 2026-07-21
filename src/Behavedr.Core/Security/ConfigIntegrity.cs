namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Provides HMAC-SHA256 integrity protection for configuration files.
/// 
/// On first run (or after authorized config changes), call <see cref="SealConfigFile"/>
/// to compute and store an HMAC in a sidecar .hmac file.
/// 
/// On every subsequent load, call <see cref="VerifyConfigFile"/> to detect tampering.
/// Uses the machine-derived key from <see cref="ConfigProtection"/> for the HMAC key.
/// </summary>
public static class ConfigIntegrity
{
    private const string HmacExtension = ".hmac";

    /// <summary>
    /// Compute HMAC-SHA256 of a config file and store it in a sidecar file.
    /// Call this at install time or when the config is legitimately modified.
    /// </summary>
    public static void SealConfigFile(string configPath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(configPath))
        {
            logger.LogWarning("Cannot seal config: file not found at {Path}", configPath);
            return;
        }

        var hmac = ComputeHmac(configPath);
        var hmacPath = configPath + HmacExtension;
        File.WriteAllText(hmacPath, Convert.ToBase64String(hmac));

        logger.LogInformation("Config file sealed: {Path}", configPath);
    }

    /// <summary>
    /// Verify that a config file has not been tampered with since it was sealed.
    /// </summary>
    /// <param name="configPath">Path to the config file.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>
    /// <see cref="ConfigIntegrityResult.Valid"/> if HMAC matches,
    /// <see cref="ConfigIntegrityResult.Tampered"/> if mismatch,
    /// <see cref="ConfigIntegrityResult.NotSealed"/> if no .hmac sidecar exists (first run).
    /// </returns>
    public static ConfigIntegrityResult VerifyConfigFile(string configPath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(configPath))
        {
            logger.LogWarning("Config file not found: {Path}", configPath);
            return ConfigIntegrityResult.NotSealed;
        }

        var hmacPath = configPath + HmacExtension;
        if (!File.Exists(hmacPath))
        {
            logger.LogWarning("No HMAC sidecar found for {Path} — config not yet sealed (first run?)", configPath);
            return ConfigIntegrityResult.NotSealed;
        }

        try
        {
            var storedHmacBase64 = File.ReadAllText(hmacPath).Trim();
            var storedHmac = Convert.FromBase64String(storedHmacBase64);
            var computedHmac = ComputeHmac(configPath);

            if (CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac))
            {
                logger.LogDebug("Config integrity verified: {Path}", configPath);
                return ConfigIntegrityResult.Valid;
            }
            else
            {
                logger.LogCritical(
                    "SECURITY: Config file integrity check FAILED for {Path} — file may have been tampered with!",
                    configPath);
                return ConfigIntegrityResult.Tampered;
            }
        }
        catch (FormatException)
        {
            logger.LogCritical("SECURITY: HMAC sidecar file is corrupted for {Path}", configPath);
            return ConfigIntegrityResult.Tampered;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Config integrity verification failed unexpectedly for {Path}", configPath);
            return ConfigIntegrityResult.Tampered;
        }
    }

    /// <summary>
    /// Compute HMAC-SHA256 of file contents using the machine-derived key.
    /// </summary>
    private static byte[] ComputeHmac(string filePath)
    {
        var key = GetHmacKey();
        var fileBytes = File.ReadAllBytes(filePath);
        return HMACSHA256.HashData(key, fileBytes);
    }

    /// <summary>
    /// Derive an HMAC key from the machine key used by ConfigProtection.
    /// Uses HKDF to derive a separate key specifically for config integrity.
    /// </summary>
    private static byte[] GetHmacKey()
    {
        // We derive from the same machine key but with a unique context label
        // to get a cryptographically independent key for HMAC.
        var machineKey = GetMachineKeyBytes();
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            machineKey,
            outputLength: 32,
            info: Encoding.UTF8.GetBytes("behavedr-config-integrity-v1"));
    }

    /// <summary>
    /// Get the raw machine key bytes (same key store as ConfigProtection).
    /// </summary>
    private static byte[] GetMachineKeyBytes()
    {
        var keyDir = GetKeyDirectory();
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Combine(keyDir, ".behavedr-key");

        if (File.Exists(keyPath))
        {
            var keyBase64 = File.ReadAllText(keyPath).Trim();
            return Convert.FromBase64String(keyBase64);
        }

        // Generate new key if none exists
        var newKey = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(keyPath, Convert.ToBase64String(newKey));

        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch { }

        return newKey;
    }

    private static string GetKeyDirectory()
    {
        if (OperatingSystem.IsWindows())
            return Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData), "Behavedr");

        const string systemDir = "/etc/behavedr";
        try
        {
            if (Directory.Exists(systemDir) ||
                Directory.CreateDirectory(systemDir).Exists)
                return systemDir;
        }
        catch { }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".behavedr");
    }
}

public enum ConfigIntegrityResult
{
    /// <summary>HMAC matches — config is unmodified.</summary>
    Valid,

    /// <summary>HMAC does NOT match — config may have been tampered with.</summary>
    Tampered,

    /// <summary>No HMAC sidecar file exists (first run or not yet sealed).</summary>
    NotSealed,
}
