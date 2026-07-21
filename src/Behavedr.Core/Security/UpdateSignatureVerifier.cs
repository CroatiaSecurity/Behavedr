namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Verifies Ed25519 (via RSA-PSS fallback on .NET) signatures on auto-update packages.
/// Uses a baked-in public key to ensure only CroatiaSecurity-signed binaries are accepted.
/// 
/// Signing workflow:
///   1. Build release zip
///   2. Sign with private key: produces .sig file (RSA-PSS SHA-256)
///   3. Upload both .zip and .sig to GitHub Releases
///   4. Agent downloads both, verifies .sig against baked-in public key before extracting
/// </summary>
public static class UpdateSignatureVerifier
{
    // RSA-4096 public key for update verification (PEM format, baked in at compile time).
    // Generate a keypair with: openssl genrsa -out update-signing-key.pem 4096
    // Extract public key: openssl rsa -in update-signing-key.pem -pubout -out update-signing-key.pub.pem
    // Sign: openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sign update-signing-key.pem -out file.sig file.zip
    //
    // REPLACE THIS with your actual public key before production release.
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0PLACEHOLDER000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        0000000000000000000000000000000000000000000000000000000000000000
        00000000000000000000000000000000000000000000AgMBAAE=
        -----END PUBLIC KEY-----
        """;

    /// <summary>
    /// Verify that a file's signature is valid against the baked-in public key.
    /// </summary>
    /// <param name="filePath">Path to the file to verify.</param>
    /// <param name="signaturePath">Path to the .sig file (RSA-PSS SHA-256 signature).</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>True if signature is valid, false otherwise.</returns>
    public static bool VerifySignature(string filePath, string signaturePath, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!File.Exists(filePath))
        {
            logger.LogError("Cannot verify signature: file not found at {Path}", filePath);
            return false;
        }

        if (!File.Exists(signaturePath))
        {
            logger.LogError("Cannot verify signature: .sig file not found at {Path}", signaturePath);
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);

            var signatureBytes = File.ReadAllBytes(signaturePath);
            using var fileStream = File.OpenRead(filePath);

            var isValid = rsa.VerifyData(
                fileStream,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            if (isValid)
            {
                logger.LogInformation("Update signature verified successfully for {File}", Path.GetFileName(filePath));
            }
            else
            {
                logger.LogCritical("SECURITY: Update signature verification FAILED for {File} — rejecting update", Path.GetFileName(filePath));
            }

            return isValid;
        }
        catch (CryptographicException ex)
        {
            logger.LogCritical(ex, "SECURITY: Cryptographic error during signature verification — rejecting update");
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Signature verification failed unexpectedly");
            return false;
        }
    }

    /// <summary>
    /// Check if the public key has been replaced from the placeholder.
    /// Returns false if the key is still the placeholder (development builds).
    /// </summary>
    public static bool IsProductionKeyConfigured() =>
        !PublicKeyPem.Contains("PLACEHOLDER", StringComparison.Ordinal);

    /// <summary>
    /// Get the baked-in public key PEM for use by other verification components (e.g., policy signing).
    /// Returns null if the production key is not configured.
    /// </summary>
    public static string? GetPublicKeyPem() =>
        IsProductionKeyConfigured() ? PublicKeyPem : null;
}
