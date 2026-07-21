namespace Behavedr.Core.Security;

using System.Runtime.Versioning;
using System.Security.Cryptography;

/// <summary>
/// DPAPI-based key protection for the machine key on Windows.
/// Wraps the raw key material with ProtectedData (LocalMachine scope) so that
/// only SYSTEM on the same machine can unwrap it. Prevents offline key extraction
/// from disk images or backups.
///
/// On Linux/macOS: falls back to file-permission-based protection (chmod 600).
///
/// Key file format:
///   Unprotected (legacy): raw base64 key
///   Protected (v2): "DPAPI:" prefix + base64 of DPAPI-encrypted blob
/// </summary>
public static class KeyProtection
{
    private const string DpapiPrefix = "DPAPI:";
    private const string KeyFileName = ".behavedr-key";

    /// <summary>
    /// Get the machine key, unwrapping DPAPI protection if present.
    /// On first call with a legacy (unprotected) key, upgrades it to DPAPI-protected.
    /// </summary>
    public static byte[] GetMachineKey()
    {
        var keyDir = GetKeyDirectory();
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Combine(keyDir, KeyFileName);

        if (File.Exists(keyPath))
        {
            var content = File.ReadAllText(keyPath).Trim();

            if (content.StartsWith(DpapiPrefix, StringComparison.Ordinal))
            {
                // DPAPI-protected key — unwrap
                return UnprotectKey(content[DpapiPrefix.Length..]);
            }

            // Legacy unprotected key — read and upgrade
            var rawKey = Convert.FromBase64String(content);

            if (OperatingSystem.IsWindows())
            {
                // Upgrade to DPAPI-protected format
                ProtectAndWriteKey(keyPath, rawKey);
            }

            return rawKey;
        }

        // Generate new key
        var newKey = RandomNumberGenerator.GetBytes(32);
        WriteProtectedKey(keyPath, newKey);
        return newKey;
    }

    /// <summary>
    /// Write a key to disk with platform-appropriate protection.
    /// Windows: DPAPI LocalMachine scope
    /// Linux/macOS: chmod 600
    /// </summary>
    private static void WriteProtectedKey(string keyPath, byte[] key)
    {
        if (OperatingSystem.IsWindows())
        {
            ProtectAndWriteKey(keyPath, key);
        }
        else
        {
            File.WriteAllText(keyPath, Convert.ToBase64String(key));
            try
            {
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectAndWriteKey(string keyPath, byte[] rawKey)
    {
        try
        {
            var protectedBytes = ProtectedData.Protect(
                rawKey, GetEntropy(), DataProtectionScope.LocalMachine);
            var content = DpapiPrefix + Convert.ToBase64String(protectedBytes);
            File.WriteAllText(keyPath, content);
            RestrictFilePermissions(keyPath);
        }
        catch (CryptographicException)
        {
            // DPAPI unavailable (e.g., running in container without machine keys)
            // Fall back to raw storage with restricted permissions
            File.WriteAllText(keyPath, Convert.ToBase64String(rawKey));
            RestrictFilePermissions(keyPath);
        }
    }

    private static byte[] UnprotectKey(string protectedBase64)
    {
        if (OperatingSystem.IsWindows())
        {
            return UnprotectKeyWindows(protectedBase64);
        }

        // Non-Windows shouldn't have DPAPI prefix, but handle gracefully
        throw new CryptographicException("DPAPI-protected key found on non-Windows platform");
    }

    [SupportedOSPlatform("windows")]
    private static byte[] UnprotectKeyWindows(string protectedBase64)
    {
        var protectedBytes = Convert.FromBase64String(protectedBase64);
        return ProtectedData.Unprotect(
            protectedBytes, GetEntropy(), DataProtectionScope.LocalMachine);
    }

    /// <summary>
    /// Additional entropy for DPAPI binding. Uses a fixed application-specific value
    /// so that only Behavedr can unwrap its own keys (defense against other apps
    /// running as SYSTEM from accessing the key).
    /// </summary>
    private static byte[] GetEntropy()
    {
        // Fixed entropy — binds the key to Behavedr specifically
        return "Behavedr-MachineKey-v2-2026"u8.ToArray();
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictFilePermissions(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var security = fileInfo.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var systemSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                systemSid,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                adminsSid,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));

            fileInfo.SetAccessControl(security);
        }
        catch
        {
            // Best effort — may fail in non-admin context
        }
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
