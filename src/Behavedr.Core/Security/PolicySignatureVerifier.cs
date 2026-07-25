namespace Behavedr.Core.Security;

using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Verifies RSA-PSS SHA-256 signatures on server-issued policy updates.
///
/// Key separation (v0.2.4+):
/// Policy verification uses its own public key PEM so a compromise of the
/// <em>update</em> signing key does not automatically authorize policy injection,
/// and vice versa. Until a distinct policy key is provisioned, the policy key
/// intentionally matches the update key and <see cref="IsUsingSharedUpdateKey"/>
/// returns true. Operators should rotate to a dedicated policy key pair for
/// production multi-control environments (see docs/SUPPLY_CHAIN.md).
///
/// Signing workflow (server side):
///   1. Canonicalize policy JSON (exclude Signature field)
///   2. Sign with policy private key: RSA-PSS SHA-256, saltlen = digest
///   3. Deliver Base64 signature with the policy payload
/// </summary>
public static class PolicySignatureVerifier
{
    // Dedicated policy public key. When equal to the update key PEM, dual-use is active.
    // Replace with a distinct RSA-4096 public key after offline ceremony.
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
    /// Returns true when the policy public key is still shared with the update signing key.
    /// Shared keys reduce blast-radius isolation; plan a rotation ceremony.
    /// </summary>
    public static bool IsUsingSharedUpdateKey()
    {
        var update = UpdateSignatureVerifier.GetPublicKeyPem();
        if (update is null)
            return false;
        return string.Equals(
            NormalizePem(PublicKeyPem),
            NormalizePem(update),
            StringComparison.Ordinal);
    }

    public static bool IsProductionKeyConfigured() =>
        !PublicKeyPem.Contains("PLACEHOLDER", StringComparison.Ordinal);

    public static string? GetPublicKeyPem() =>
        IsProductionKeyConfigured() ? PublicKeyPem : null;

    /// <summary>
    /// Verify RSA-PSS signature over arbitrary payload bytes (canonical policy JSON).
    /// </summary>
    public static bool VerifyPayload(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!IsProductionKeyConfigured())
        {
            logger.LogWarning("Policy signing key is not configured (development mode) — accepting without verification");
            return true;
        }

        if (payload.IsEmpty || signature.IsEmpty)
        {
            logger.LogCritical("SECURITY: Empty policy payload or signature — rejecting");
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);

            var valid = rsa.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            if (!valid)
                logger.LogCritical("SECURITY: Policy signature verification FAILED — rejecting policy");

            return valid;
        }
        catch (CryptographicException ex)
        {
            logger.LogCritical(ex, "SECURITY: Cryptographic error during policy signature verification");
            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Policy signature verification failed unexpectedly");
            return false;
        }
    }

    private static string NormalizePem(string pem) =>
        pem.Replace("\r", "", StringComparison.Ordinal)
           .Replace("\n", "", StringComparison.Ordinal)
           .Replace(" ", "", StringComparison.Ordinal);
}
