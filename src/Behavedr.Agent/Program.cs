using Behavedr.Agent;
using Behavedr.Core;
using Behavedr.Core.Platform;
using Behavedr.Core.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Behavedr Agent v{Version} starting on {Platform}",
        typeof(DetectionEngine).Assembly.GetName().Version?.ToString(3) ?? "0.0.5",
        PlatformMonitors.CurrentPlatformSummary());

    var builder = Host.CreateApplicationBuilder(args);

    // SECURITY: Verify config file integrity before using it
    var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    var integrityResult = ConfigIntegrity.VerifyConfigFile(configPath);
    switch (integrityResult)
    {
        case ConfigIntegrityResult.Tampered:
            Log.Fatal("SECURITY: Configuration file integrity check FAILED — agent refusing to start. " +
                      "Re-seal config with a trusted copy or reinstall the agent.");
            return 78; // EX_CONFIG
        case ConfigIntegrityResult.NotSealed:
            Log.Warning("Config file not yet sealed — sealing now (first run)");
            ConfigIntegrity.SealConfigFile(configPath);
            break;
        case ConfigIntegrityResult.Valid:
            Log.Information("Config file integrity verified");
            break;
    }

    // Serilog replaces the default Microsoft logger
    builder.Services.AddSerilog((services, cfg) => cfg
        .WriteTo.Console()
        .WriteTo.File("logs/behavedr-.log", rollingInterval: Serilog.RollingInterval.Day,
            retainedFileCountLimit: 14, fileSizeLimitBytes: 10_485_760, rollOnFileSizeLimit: true)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext());

    // Scoring config from appsettings
    var scoringConfig = builder.Configuration
        .GetSection("Scoring")
        .Get<ScoringConfig>() ?? ScoringConfig.Default;

    if (!scoringConfig.IsValid())
    {
        Log.Warning("Invalid scoring config detected, falling back to defaults");
        scoringConfig = ScoringConfig.Default;
    }

    builder.Services.AddSingleton(scoringConfig);
    builder.Services.AddSingleton<ScoringEngine>();
    builder.Services.AddSingleton<DetectionEngine>();

    // Agent self-protection service
    builder.Services.AddHostedService<SelfProtectionService>();

    // Core monitoring background service
    builder.Services.AddHostedService<MonitoringService>();

    // Windows Service / systemd integration
    if (OperatingSystem.IsWindows())
        builder.Services.AddWindowsService(options => options.ServiceName = "Behavedr");
    // Note: UseSystemd() requires the IHostBuilder API. With HostApplicationBuilder,
    // systemd notification is handled via Microsoft.Extensions.Hosting.Systemd automatically
    // when the NOTIFY_SOCKET env var is set by systemd.

    var host = builder.Build();
    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Behavedr Agent terminated unexpectedly");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

return 0;
