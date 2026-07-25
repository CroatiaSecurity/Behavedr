#if IOS || MACCATALYST
using Foundation;
using Security;
using System.Security.Cryptography;

namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// iOS/macCatalyst Secure Enclave–backed key material helper (0.3.2).
/// Stores a 32-byte machine key in the Keychain (WhenUnlockedThisDeviceOnly).
/// Used by MAUI iOS to avoid filesystem secrets when possible.
/// </summary>
public static class IosKeychainProtection
{
    private const string Service = "com.croatiasecurity.behavedr";
    private const string Account = "machine-key-v1";

    public static byte[] GetOrCreateMachineKey()
    {
        var existing = TryGet();
        if (existing is { Length: 32 })
            return existing;

        var key = RandomNumberGenerator.GetBytes(32);
        Store(key);
        return key;
    }

    public static byte[]? TryGet()
    {
        var query = new SecRecord(SecKind.GenericPassword)
        {
            Service = Service,
            Account = Account,
        };
        var match = SecKeyChain.QueryAsData(query, false, out var status);
        if (status != SecStatusCode.Success || match is null)
            return null;
        return match.ToArray();
    }

    public static bool Store(byte[] key)
    {
        // Remove prior
        var del = new SecRecord(SecKind.GenericPassword)
        {
            Service = Service,
            Account = Account,
        };
        SecKeyChain.Remove(del);

        var record = new SecRecord(SecKind.GenericPassword)
        {
            Service = Service,
            Account = Account,
            ValueData = NSData.FromArray(key),
            Accessible = SecAccessible.WhenUnlockedThisDeviceOnly,
        };
        var status = SecKeyChain.Add(record);
        return status == SecStatusCode.Success || status == SecStatusCode.DuplicateItem;
    }
}
#endif
