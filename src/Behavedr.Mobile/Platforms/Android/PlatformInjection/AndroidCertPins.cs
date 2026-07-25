namespace Behavedr.Mobile.PlatformInjection;

/// <summary>
/// Publisher APK signing certificate pins — <b>not</b> an end-user setting.
/// Users only install the APK; they never configure pins.
///
/// <para><b>Default (recommended until you have a stable release keystore):</b>
/// leave <see cref="BakedInPins"/> empty. The running app self-pins whatever
/// cert signed the installed APK and alerts if that cert later changes.</para>
///
/// <para><b>When you ship production APKs:</b> paste your release cert SHA-256
/// (hex, no colons) into <see cref="BakedInPins"/> once. Get it with:
/// <c>apksigner verify --print-certs Behavedr.apk</c></para>
/// </summary>
internal static class AndroidCertPins
{
    /// <summary>
    /// Optional publisher pins (comma-separated hex SHA-256).
    /// Leave empty for zero-config self-pin. Fill once per release keystore.
    /// </summary>
    private const string BakedInPins =
        // "YOUR_RELEASE_CERT_SHA256_HEX_HERE",
        "";

    public static string[] VendorFingerprints
    {
        get
        {
            var list = new List<string>();
            AddFromCsv(list, BakedInPins);
            // MDM / managed device only — never required for normal users
            AddFromCsv(list, Environment.GetEnvironmentVariable("BEHAVEDR_ANDROID_CERT_SHA256"));
            return list.ToArray();
        }
    }

    private static void AddFromCsv(List<string> list, string? csv)
    {
        if (string.IsNullOrWhiteSpace(csv)) return;
        foreach (var part in csv.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains("PLACEHOLDER", StringComparison.OrdinalIgnoreCase)) continue;
            if (part.Contains("YOUR_RELEASE", StringComparison.OrdinalIgnoreCase)) continue;
            var n = part.Replace(":", "", StringComparison.Ordinal)
                .Replace(" ", "", StringComparison.Ordinal)
                .Trim()
                .ToUpperInvariant();
            if (n.Length >= 32 && !list.Contains(n, StringComparer.OrdinalIgnoreCase))
                list.Add(n);
        }
    }
}
