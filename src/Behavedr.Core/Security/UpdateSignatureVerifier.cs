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
    // Generate a keypair with: dotnet run --project tools (GenerateKey)
    // Sign: openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sign update-signing-key.pem -out file.sig file.zip
    // Keep the private key (update-signing-key.pem) in a secure location — NEVER commit it.
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3eMZ0UT+wV8uly2K0lNZ
        14k2yDWXL0PfAoA6CnemQPPr4YypR7ExREx9DsX6jmCrBn+zxvh+Mhgs2o7p3nHx
        /wmyGio3zk4cujTBMPjMqrYEvhbq5oSibor+R2PhF4JUGpZfBqPHfKAeTp1QLiOY
        W+A7f5mPQjXnkTXWFrX8S9m7kGiM9et3PKkU7h18Pvbnt+t4Gl6ef8hQ358jxOmT
        J1qWJezuRy3uc8CUefoIphrxRNXy1aLh+FahJTYCgPixDGM5ltPySvY9/CgY5jg3
        tlsOyxxDugygXYwc/fm8SrU2kSOfU0h+MlKcOsYs0rLOZ2oG72Mq9vBbjGtH9nMq
        64gjm2j9KVIGSEimKi+AkeCSrNGlJWldG/le1we4PSDm0fzMGXqWszW3nIiNsrfb
        C0lj/ajg/Y7P81omdTwBNe1ZOupGjoH0HmAWqXPr7QRwDhgb/NxlNF1J8eKltLIn
        LW0KAOcp2Z/EaJzMZ6N3IL7fv8LNEZ3fUpNdgUH9foo3iCHWzq3UgybjMtS0kWj6
        ntVYOoNPfozGWn52vS+PN/wA6U1l51mfBh62Eix/NDd1UimcPVxJHzOVzHoQNXi3
        0lTShdomBZLExd7acfHMwzHonYZDwXQ2VbgAQNmA3rSP3vyi+nqAMMXB6EqtHeWR
        hv3bUXuQzZ8w40Lvk3E7x8ECAwEAAQ==
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
