namespace Behavedr.Core.Security;

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Provides encryption/decryption for sensitive configuration values.
/// Uses DPAPI on Windows, AES with machine-derived key on Linux/macOS.
/// </summary>
public static class ConfigProtection
{
    private const string KeyFileName = ".behavedr-key";

    /// <summary>Encrypt a value for safe storage in config files.</summary>
    public static string Encrypt(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var bytes = Encoding.UTF8.GetBytes(plaintext);

        if (OperatingSystem.IsWindows())
        {
            return EncryptWindows(bytes);
        }

        return EncryptCrossPlatform(bytes);
    }

    /// <summary>Decrypt a previously encrypted value.</summary>
    public static string Decrypt(string ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        if (OperatingSystem.IsWindows())
        {
            return DecryptWindows(ciphertext);
        }

        return DecryptCrossPlatform(ciphertext);
    }

    /// <summary>Check if a string looks like an encrypted value.</summary>
    public static bool IsEncrypted(string value) =>
        value.StartsWith("ENC:", StringComparison.Ordinal);

    /// <summary>
    /// Decrypt a value if it's encrypted, otherwise return as-is.
    /// </summary>
    public static string DecryptIfNeeded(string value) =>
        IsEncrypted(value) ? Decrypt(value["ENC:".Length..]) : value;

    [SupportedOSPlatform("windows")]
    private static string EncryptWindows(byte[] data)
    {
        var encrypted = ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(encrypted);
    }

    [SupportedOSPlatform("windows")]
    private static string DecryptWindows(string ciphertext)
    {
        var encrypted = Convert.FromBase64String(ciphertext);
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(decrypted);
    }

    private static string EncryptCrossPlatform(byte[] data)
    {
        var key = GetOrCreateMachineKey();
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        var encrypted = aes.EncryptCbc(data, aes.IV);

        // Format: IV (base64) + "." + ciphertext (base64)
        return Convert.ToBase64String(aes.IV) + "." + Convert.ToBase64String(encrypted);
    }

    private static string DecryptCrossPlatform(string ciphertext)
    {
        var parts = ciphertext.Split('.');
        if (parts.Length != 2)
            throw new CryptographicException("Invalid encrypted format");

        var iv = Convert.FromBase64String(parts[0]);
        var encrypted = Convert.FromBase64String(parts[1]);

        var key = GetOrCreateMachineKey();
        using var aes = Aes.Create();
        aes.Key = key;

        var decrypted = aes.DecryptCbc(encrypted, iv);
        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>
    /// Get or create a machine-specific AES key stored in a protected file.
    /// Supports key versioning for rotation: keys are stored as .behavedr-key-v{N}.
    /// On Linux/macOS this lives in /etc/behavedr/ (root-owned) or ~/.behavedr/
    /// </summary>
    private static byte[] GetOrCreateMachineKey()
    {
        var keyDir = GetKeyDirectory();
        Directory.CreateDirectory(keyDir);

        // Try current key (unversioned for backward compat)
        var keyPath = Path.Combine(keyDir, KeyFileName);
        if (File.Exists(keyPath))
        {
            var keyBase64 = File.ReadAllText(keyPath).Trim();
            return Convert.FromBase64String(keyBase64);
        }

        // Generate new key with version tracking
        var newKey = RandomNumberGenerator.GetBytes(32); // AES-256
        File.WriteAllText(keyPath, Convert.ToBase64String(newKey));

        // Write version metadata
        var versionPath = Path.Combine(keyDir, ".behavedr-key-version");
        File.WriteAllText(versionPath, "1");

        // Try to restrict file permissions (best-effort on cross-platform)
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.SetUnixFileMode(versionPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch { }

        return newKey;
    }

    /// <summary>
    /// Rotate the machine key. Old key is preserved as .behavedr-key-v{oldVersion}
    /// for decrypting existing data during migration.
    /// </summary>
    public static void RotateKey(ILogger? logger = null)
    {
        var keyDir = GetKeyDirectory();
        var keyPath = Path.Combine(keyDir, KeyFileName);
        var versionPath = Path.Combine(keyDir, ".behavedr-key-version");

        int currentVersion = 1;
        if (File.Exists(versionPath))
        {
            int.TryParse(File.ReadAllText(versionPath).Trim(), out currentVersion);
        }

        // Archive current key
        if (File.Exists(keyPath))
        {
            var archivePath = Path.Combine(keyDir, $".behavedr-key-v{currentVersion}");
            File.Copy(keyPath, archivePath, overwrite: true);
        }

        // Generate new key
        var newKey = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(keyPath, Convert.ToBase64String(newKey));
        File.WriteAllText(versionPath, (currentVersion + 1).ToString());

        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch { }

        logger?.LogInformation("Machine key rotated: v{Old} → v{New}", currentVersion, currentVersion + 1);
    }

    /// <summary>
    /// Get a previous key version (for decrypting data encrypted with an older key).
    /// Returns null if the version doesn't exist.
    /// </summary>
    public static byte[]? GetKeyVersion(int version)
    {
        var keyDir = GetKeyDirectory();
        var archivePath = Path.Combine(keyDir, $".behavedr-key-v{version}");

        if (!File.Exists(archivePath))
            return null;

        var keyBase64 = File.ReadAllText(archivePath).Trim();
        return Convert.FromBase64String(keyBase64);
    }

    private static string GetKeyDirectory()
    {
        if (OperatingSystem.IsWindows())
            return Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData), "Behavedr");

        // Linux/macOS: prefer /etc/behavedr if writable, else user home
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
