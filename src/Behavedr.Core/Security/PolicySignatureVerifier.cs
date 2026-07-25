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
    // Interim: same free RSA-4096 material as update signing until a second pair is provisioned.
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAw7vJ6R8Cd9Nm5nSnefrr
        t7pXvPw8bYC3vn7n14l3S34MdhGzxOCdyU+kkCggNbNLmj8GGqex+EPt0pfEzvzj
        h+mi0doKMkHCEB5h/eu5bZn86xc2twbKbhXU5FWSh0BZMejcltAEhVCig/o5LlIv
        is0Xf/On4IIUW1KAd7/mJAkjW/4OpyyhJ7KKpttCXa6loR0atCu9JA6YAne7yrsZ
        EdA9jOV+i5EsMassQ2RLhMTm7tLoWBDFL6hu06v5KPqR0dRPrVnq/QTePpVQq0fj
        Ax4QLld8oPto1F6Bwv82Ch9U4ZE+uyzdp8uxCbdbPsOeV92bTUdq8gVH0kZOTeUQ
        4NNoYJIozA5hOtn09oy9wJKaODF+5YzV44la8roaAMgWBfUMIcmZOUWtVidbcB0W
        oo6Pe4rFbW6Pcwd5oTY0Zjff3zuN+Yxy15V6csQwV23HWZRrvdFvucthNbyCVCjd
        ZR8Yg4I3NkTzUiBbwe6/XA7FwlOYX6/2CqE4kaXKKjR893Kh7dSVXIF3LUEdBN8t
        rlNybhR6yjNrcOdZ0C8OIXrwqQK5Tt+T4b/JdMvZeYHmL6uc5+XpL0hHvqSYqqWZ
        PIr5ASAaFo77CPr02MSvQA3VQe3bA8LhFPh8mO6t7MyZtq/WysMPLPomHCo6BeAP
        uMbu9EG1q/hZqhtso8g4iT0CAwEAAQ==
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
