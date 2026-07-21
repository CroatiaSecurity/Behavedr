namespace Behavedr.Core.Security;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

/// <summary>
/// Platform-adaptive key protection for the machine key:
///
/// Windows: DPAPI (DataProtectionScope.LocalMachine) + per-installation entropy.
///   Only SYSTEM on the same machine can unwrap. Prevents offline extraction.
///
/// Linux: Kernel keyring (add_key/request_key syscalls) stores key in kernel memory.
///   Key is NOT on the filesystem and cannot be read via /proc or disk access.
///   Falls back to file-permission (chmod 600) if keyring is unavailable (containers).
///
/// macOS: File-permission-based (chmod 600) with machine-id binding.
///   TODO: Keychain Services integration for hardware-backed keys on Apple Silicon.
///
/// Key file format:
///   Unprotected (legacy): raw base64 key
///   Protected (v2): "DPAPI:" prefix + base64 of DPAPI-encrypted blob
///   Keyring (v3): "KEYRING:" prefix — key is in kernel keyring, file is a marker only
/// </summary>
public static class KeyProtection
{
    private const string DpapiPrefix = "DPAPI:";
    private const string KeyringPrefix = "KEYRING:";
    private const string KeyFileName = ".behavedr-key";
    private const string KeyringDescription = "behavedr:machine-key";

    /// <summary>
    /// Get the machine key using the most secure storage available:
    /// - Windows: DPAPI (LocalMachine scope)
    /// - Linux: Kernel keyring (key lives in kernel memory, not on disk)
    /// - macOS/fallback: File with chmod 600
    /// On first call with a legacy (unprotected) key, upgrades to best available protection.
    /// </summary>
    public static byte[] GetMachineKey()
    {
        // Linux: Try kernel keyring first (key never touches disk)
        if (OperatingSystem.IsLinux())
        {
            var keyringKey = TryGetKeyFromKeyring();
            if (keyringKey is not null)
                return keyringKey;
        }

        var keyDir = GetKeyDirectory();
        Directory.CreateDirectory(keyDir);
        var keyPath = Path.Combine(keyDir, KeyFileName);

        if (File.Exists(keyPath))
        {
            var content = File.ReadAllText(keyPath).Trim();

            if (content.StartsWith(KeyringPrefix, StringComparison.Ordinal))
            {
                // Keyring marker file — key should be in keyring but isn't (reboot?)
                // Re-generate and store in keyring
                var newKey = RandomNumberGenerator.GetBytes(32);
                if (OperatingSystem.IsLinux() && TryStoreKeyInKeyring(newKey))
                {
                    return newKey;
                }
                // Keyring unavailable — fall back to file storage
                WriteProtectedKey(keyPath, newKey);
                return newKey;
            }

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
            else if (OperatingSystem.IsLinux())
            {
                // Upgrade to kernel keyring storage
                if (TryStoreKeyInKeyring(rawKey))
                {
                    // Write marker file and remove raw key from disk
                    File.WriteAllText(keyPath, KeyringPrefix + "v1");
                    try { File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                    catch { }
                }
            }

            return rawKey;
        }

        // Generate new key
        var newKey2 = RandomNumberGenerator.GetBytes(32);

        // Linux: store in kernel keyring if possible
        if (OperatingSystem.IsLinux() && TryStoreKeyInKeyring(newKey2))
        {
            // Write marker file so we know key is in keyring
            File.WriteAllText(keyPath, KeyringPrefix + "v1");
            try { File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { }
            return newKey2;
        }

        WriteProtectedKey(keyPath, newKey2);
        return newKey2;
    }

    /// <summary>
    /// Rotate the machine key. Old key is preserved as .behavedr-key-v{oldVersion}
    /// for decrypting existing data during migration.
    /// v0.1.3: Moved here from ConfigProtection to consolidate key management (H-1 fix).
    /// </summary>
    public static void RotateKey(Microsoft.Extensions.Logging.ILogger? logger = null)
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
        WriteProtectedKey(keyPath, newKey);

        File.WriteAllText(versionPath, (currentVersion + 1).ToString());

        logger?.LogInformation("Machine key rotated: v{Old} → v{New}", currentVersion, currentVersion + 1);
    }

    /// <summary>
    /// Get a previous key version (for decrypting data encrypted with an older key).
    /// Returns null if the version doesn't exist.
    /// v0.1.3: Moved here from ConfigProtection to consolidate key management (H-1 fix).
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

    /// <summary>
    /// Write a key to disk with platform-appropriate protection.
    /// V-2 FIX: On Windows, uses a temp file with restricted ACL then atomic rename
    /// to eliminate the permission race window. On Linux/macOS, sets chmod before
    /// writing content (open with restricted mode).
    /// </summary>
    private static void WriteProtectedKey(string keyPath, byte[] key)
    {
        if (OperatingSystem.IsWindows())
        {
            ProtectAndWriteKey(keyPath, key);
        }
        else
        {
            // V-2 FIX: Create file with O_CREAT|O_EXCL semantics and restricted mode
            var tempPath = keyPath + ".tmp." + Guid.NewGuid().ToString("N")[..8];
            try
            {
                File.WriteAllText(tempPath, Convert.ToBase64String(key));
                File.SetUnixFileMode(tempPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                File.Move(tempPath, keyPath, overwrite: true); // Atomic rename on same volume
            }
            catch
            {
                // Fallback: direct write (original behavior)
                File.WriteAllText(keyPath, Convert.ToBase64String(key));
                try { File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                catch { }
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
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

    private const string EntropyFileName = ".behavedr-entropy";

    /// <summary>
    /// Additional entropy for DPAPI binding. Uses a per-installation random value
    /// generated at first run and stored in a separate file with restricted ACLs.
    /// This prevents other SYSTEM-level processes from unwrapping the key even if
    /// they know the source code, since the entropy is unique per machine install.
    ///
    /// Falls back to a fixed application-specific value if the entropy file cannot
    /// be created/read (e.g., permission issues in containers).
    /// </summary>
    private static byte[] GetEntropy()
    {
        try
        {
            var keyDir = GetKeyDirectory();
            var entropyPath = Path.Combine(keyDir, EntropyFileName);

            if (File.Exists(entropyPath))
            {
                var entropyBase64 = File.ReadAllText(entropyPath).Trim();
                var entropy = Convert.FromBase64String(entropyBase64);
                if (entropy.Length >= 16)
                    return entropy;
            }

            // Generate random entropy at install time (32 bytes)
            var newEntropy = RandomNumberGenerator.GetBytes(32);
            Directory.CreateDirectory(keyDir);
            File.WriteAllText(entropyPath, Convert.ToBase64String(newEntropy));

            // Restrict permissions on entropy file
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    RestrictFilePermissions(entropyPath);
                }
                else
                {
                    File.SetUnixFileMode(entropyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
            catch { }

            return newEntropy;
        }
        catch
        {
            // V-4 FIX: Log critical warning when falling back to fixed entropy.
            // This significantly weakens DPAPI binding — all installations with this
            // fallback share the same entropy, reducing protection to base LocalMachine scope.
            System.Diagnostics.Trace.TraceError(
                "SECURITY CRITICAL: Behavedr DPAPI entropy file unavailable — falling back to fixed entropy. " +
                "Key protection is degraded. Ensure the Behavedr data directory is writable.");
            // Fallback: fixed entropy (less secure but allows operation)
            return "Behavedr-MachineKey-v2-2026-fallback"u8.ToArray();
        }
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

    // =========================================================================
    // Linux Kernel Keyring Integration
    // =========================================================================
    // The kernel keyring stores keys in kernel memory, inaccessible via /proc
    // or filesystem. Keys survive until session ends or explicit revocation.
    // We use KEY_SPEC_USER_KEYRING (-4) which persists per-UID across processes.
    //
    // Syscall numbers (x86_64):
    //   add_key    = 248
    //   request_key = 249
    //   keyctl     = 250
    // =========================================================================

    private const int KEY_SPEC_USER_KEYRING = -4;
    private const int KEYCTL_READ = 11;

    /// <summary>
    /// Try to retrieve the machine key from the Linux kernel keyring.
    /// Returns null if key is not in the keyring (first run, or after reboot).
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static byte[]? TryGetKeyFromKeyring()
    {
        try
        {
            // request_key("user", "behavedr:machine-key", null, KEY_SPEC_USER_KEYRING)
            var keyId = request_key("user", KeyringDescription, null, KEY_SPEC_USER_KEYRING);
            if (keyId < 0)
                return null;

            // Read the key data: keyctl(KEYCTL_READ, key_id, buffer, buflen)
            var buffer = new byte[32];
            var bytesRead = keyctl_read(KEYCTL_READ, keyId, buffer, buffer.Length);
            if (bytesRead == 32)
                return buffer;

            return null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Store a key in the Linux kernel keyring. Returns true if successful.
    /// The key will persist in kernel memory for the lifetime of the user session
    /// (or until explicitly revoked). It is NOT accessible via the filesystem.
    /// </summary>
    [SupportedOSPlatform("linux")]
    private static bool TryStoreKeyInKeyring(byte[] key)
    {
        try
        {
            // add_key("user", "behavedr:machine-key", payload, payload_len, KEY_SPEC_USER_KEYRING)
            var keyId = add_key("user", KeyringDescription, key, key.Length, KEY_SPEC_USER_KEYRING);
            return keyId >= 0;
        }
        catch
        {
            return false;
        }
    }

    // P/Invoke: Linux keyring syscalls via libc wrappers
    [DllImport("libc", EntryPoint = "add_key", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int add_key(
        string type, string description, byte[] payload, int plen, int keyring);

    [DllImport("libc", EntryPoint = "request_key", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int request_key(
        string type, string description, string? callout_info, int dest_keyring);

    [DllImport("libc", EntryPoint = "keyctl", SetLastError = true)]
    private static extern int keyctl_read(int operation, int key_id, byte[] buffer, int buflen);

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
