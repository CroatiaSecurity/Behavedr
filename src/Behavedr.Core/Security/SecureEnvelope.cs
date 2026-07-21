namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Provides authenticated encryption (AES-256-GCM) for data at rest.
/// Used to protect offline buffer reports and other sensitive local storage.
/// 
/// Envelope format (binary):
///   [1 byte: version] [12 bytes: nonce] [16 bytes: tag] [N bytes: ciphertext]
/// 
/// Key derivation uses HKDF from the machine key with a purpose-specific context label.
/// </summary>
public static class SecureEnvelope
{
    private const byte EnvelopeVersion = 1;
    private const int NonceSize = 12; // AES-GCM standard
    private const int TagSize = 16;   // 128-bit authentication tag
    private const int HeaderSize = 1 + NonceSize + TagSize; // version + nonce + tag

    /// <summary>
    /// Encrypt and authenticate data using AES-256-GCM with a purpose-derived key.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <param name="purpose">Key derivation context (e.g., "offline-buffer", "policy-cache").</param>
    /// <returns>Encrypted envelope as base64 string.</returns>
    public static string Seal(byte[] plaintext, string purpose)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentException.ThrowIfNullOrEmpty(purpose);

        var key = DeriveKey(purpose);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Assemble envelope: version || nonce || tag || ciphertext
        var envelope = new byte[HeaderSize + ciphertext.Length];
        envelope[0] = EnvelopeVersion;
        nonce.CopyTo(envelope.AsSpan(1));
        tag.CopyTo(envelope.AsSpan(1 + NonceSize));
        ciphertext.CopyTo(envelope.AsSpan(HeaderSize));

        return Convert.ToBase64String(envelope);
    }

    /// <summary>
    /// Encrypt and authenticate a string (UTF-8).
    /// </summary>
    public static string SealString(string plaintext, string purpose) =>
        Seal(Encoding.UTF8.GetBytes(plaintext), purpose);

    /// <summary>
    /// Decrypt and verify an envelope. Returns null if authentication fails (tampered/corrupted).
    /// </summary>
    /// <param name="envelopeBase64">Base64-encoded envelope from <see cref="Seal"/>.</param>
    /// <param name="purpose">Must match the purpose used during sealing.</param>
    /// <returns>Decrypted plaintext, or null if verification fails.</returns>
    public static byte[]? Unseal(string envelopeBase64, string purpose)
    {
        ArgumentException.ThrowIfNullOrEmpty(envelopeBase64);
        ArgumentException.ThrowIfNullOrEmpty(purpose);

        byte[] envelope;
        try
        {
            envelope = Convert.FromBase64String(envelopeBase64);
        }
        catch (FormatException)
        {
            return null;
        }

        if (envelope.Length < HeaderSize + 1) // Must have at least 1 byte of ciphertext
            return null;

        var version = envelope[0];
        if (version != EnvelopeVersion)
            return null; // Unknown version — cannot decrypt

        var nonce = envelope.AsSpan(1, NonceSize);
        var tag = envelope.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = envelope.AsSpan(HeaderSize);

        var key = DeriveKey(purpose);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
        catch (CryptographicException)
        {
            // Authentication failed — data has been tampered with
            return null;
        }
    }

    /// <summary>
    /// Decrypt and verify an envelope as a UTF-8 string.
    /// Returns null if authentication fails.
    /// </summary>
    public static string? UnsealString(string envelopeBase64, string purpose)
    {
        var plaintext = Unseal(envelopeBase64, purpose);
        return plaintext is null ? null : Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// Derive a purpose-specific AES-256 key from the machine key using HKDF.
    /// </summary>
    private static byte[] DeriveKey(string purpose)
    {
        var machineKey = GetMachineKeyBytes();
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            machineKey,
            outputLength: 32,
            info: Encoding.UTF8.GetBytes($"behavedr-{purpose}-v1"));
    }

    /// <summary>
    /// Get the raw machine key bytes (shared key store with ConfigProtection/ConfigIntegrity).
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
