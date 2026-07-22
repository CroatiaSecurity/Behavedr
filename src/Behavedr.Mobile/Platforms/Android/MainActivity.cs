using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Mobile.PlatformInjection;

using Environment = System.Environment;

namespace Behavedr.Mobile;

/// <summary>
/// Launcher activity — zero visuals. Initializes all Android platform security
/// components, starts the foreground monitoring service, and immediately moves
/// to background. The user only sees the app icon.
///
/// Initialization order (critical for security):
/// 1. Register Android Keystore bridge (before any key operations)
/// 2. Run supply chain verification (detect repackaging/sideloading)
/// 3. Start foreground service (continuous monitoring)
/// 4. Schedule WorkManager watchdog (persistence)
/// 5. Request battery optimization whitelist (Doze bypass)
/// 6. Initialize platform signal provider (native API bridge)
/// 7. Start Play Integrity attestation (device verification)
/// 8. Move to background
/// </summary>
[Activity(
    Theme = "@android:style/Theme.NoDisplay",
    MainLauncher = true,
    Exported = true,
    LaunchMode = LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.ScreenSize
        | ConfigChanges.Orientation
        | ConfigChanges.UiMode
        | ConfigChanges.ScreenLayout
        | ConfigChanges.SmallestScreenSize
        | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    private AndroidPlatformSignalProvider? _platformSignalProvider;
    private PlayIntegrityAttestor? _playIntegrityAttestor;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // === PHASE 1: Critical security initialization ===

        // 1. Register Android Keystore bridge — MUST be first
        //    This connects Core's KeyProtection to hardware-backed crypto
        KeystoreBridgeRegistration.Register();

        // 2. Supply chain verification — detect repackaging/tampering early
        var supplyChainVerifier = new SupplyChainVerifier(ApplicationContext!);
        var scSignals = supplyChainVerifier.Verify();
        if (scSignals.Any(s => s.Weight >= 90))
        {
            // Critical supply chain failure — log and continue monitoring
            // (we still want to report the compromise to server)
            WriteForensicLog("SUPPLY_CHAIN_CRITICAL: " +
                string.Join(", ", scSignals.Where(s => s.Weight >= 90).Select(s => s.Type)));
        }

        // === PHASE 2: Service persistence ===

        // 3. Start the foreground monitoring service
        var serviceIntent = new Intent(this, typeof(BehavedrForegroundService));
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
        {
            StartForegroundService(serviceIntent);
        }
        else
        {
            StartService(serviceIntent);
        }

        // 4. Schedule WorkManager watchdog (ensures service restarts if killed)
        WorkManagerWatchdog.Schedule(ApplicationContext!);

        // === PHASE 3: Platform optimizations ===

        // 5. Request battery optimization whitelist (Doze bypass)
        var batteryManager = new BatteryOptimizationManager(ApplicationContext!);
        if (!batteryManager.IsWhitelisted)
        {
            batteryManager.RequestWhitelist(this);
        }

        // === PHASE 4: Platform signal injection ===

        // 6. Initialize platform signal provider
        //    This bridges native Android APIs (UsageStats, PackageManager, etc.) into Core
        _platformSignalProvider = new AndroidPlatformSignalProvider(Application!);
        _platformSignalProvider.Start();

        // 7. Start Play Integrity attestation (periodic device verification)
        _playIntegrityAttestor = new PlayIntegrityAttestor(ApplicationContext!);
        _playIntegrityAttestor.Start();

        // === PHASE 5: Update security ===

        // Check for rollback attacks
        var updateSecurity = new AndroidUpdateSecurity(ApplicationContext!);
        var updateSignals = updateSecurity.DetectRollback();
        if (updateSignals.Count > 0)
        {
            WriteForensicLog("UPDATE_ROLLBACK: " +
                string.Join(", ", updateSignals.Select(s => s.Type)));
        }

        // === Done — move to background ===
        MoveTaskToBack(true);
    }

    protected override void OnDestroy()
    {
        _platformSignalProvider?.Dispose();
        _playIntegrityAttestor?.Dispose();
        base.OnDestroy();
    }

    private static void WriteForensicLog(string message)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "logs");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "startup-forensic.log");
            File.AppendAllText(logPath,
                $"[{DateTime.UtcNow:O}] PID={Environment.ProcessId} {message}{Environment.NewLine}");
        }
        catch { }
    }
}
