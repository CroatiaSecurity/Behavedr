using Microsoft.Extensions.Logging;

namespace Behavedr.Mobile;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder.UseMauiApp<App>();

#if DEBUG
        builder.Logging.AddDebug();
#endif

        // Create the detection engine with all platform monitors
        builder.Services.AddSingleton(_ => Core.AgentBootstrap.CreateEngine());

#if ANDROID
        // Register Android-specific platform services
        RegisterAndroidServices(builder.Services);
#endif

        return builder.Build();
    }

#if ANDROID
    private static void RegisterAndroidServices(IServiceCollection services)
    {
        // Platform signal provider (UsageStats, PackageManager, Lifecycle, Settings)
        services.AddSingleton<PlatformInjection.AndroidPlatformSignalProvider>();

        // Play Integrity attestation
        services.AddSingleton<PlatformInjection.PlayIntegrityAttestor>();

        // Battery optimization manager
        services.AddSingleton<PlatformInjection.BatteryOptimizationManager>();

        // Device Owner / DPM manager
        services.AddSingleton<PlatformInjection.DeviceOwnerManager>();

        // Supply chain verifier
        services.AddSingleton<PlatformInjection.SupplyChainVerifier>();

        // Update security
        services.AddSingleton<PlatformInjection.AndroidUpdateSecurity>();
    }
#endif
}
