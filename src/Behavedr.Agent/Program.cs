using Behavedr.Agent;
using Behavedr.Core;
using Behavedr.Core.Communication;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Behavedr.Core.Security;
using Behavedr.Core.Update;
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
        typeof(DetectionEngine).Assembly.GetName().Version?.ToString(3) ?? "0.1.3",
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
            Log.Warning("Config file not yet sealed — validating before sealing (first run)");
            // SECURITY: Validate config values are within acceptable bounds before sealing.
            // Prevents an attacker from pre-placing a malicious config that gets sealed as trusted.
            if (!ConfigIntegrity.ValidateConfigBeforeSealing(configPath))
            {
                Log.Fatal("SECURITY: Configuration values are outside acceptable bounds — refusing to seal. " +
                          "Verify appsettings.json contains valid values and restart.");
                return 78; // EX_CONFIG
            }
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
    builder.Services.AddSingleton<BehavioralCorrelationEngine>();
    builder.Services.AddSingleton<DetectionEngine>();

    // v0.1.3: Response engine with process kill and file quarantine (C-1 fix)
    var responsePolicy = builder.Configuration
        .GetSection("Response")
        .Get<ResponsePolicy>() ?? ResponsePolicy.Default;
    if (!responsePolicy.IsValid())
    {
        Log.Warning("Invalid response policy detected, falling back to defaults");
        responsePolicy = ResponsePolicy.Default;
    }
    builder.Services.AddSingleton(responsePolicy);
    builder.Services.AddSingleton<ResponseEngine>();
    builder.Services.AddSingleton<ProcessKillAction>();
    builder.Services.AddSingleton<FileQuarantineAction>();
    builder.Services.AddSingleton<IsolationResponseEngine>();
    builder.Services.AddSingleton<ChainTracer>(sp =>
        new ChainTracer(PlatformMonitors.SharedAncestryCache,
            sp.GetService<ILogger<ChainTracer>>()));

    // v0.1.3: Communication layer — agent-to-server reporting (C-3 fix)
    var commConfig = builder.Configuration
        .GetSection("Communication")
        .Get<CommunicationConfig>() ?? CommunicationConfig.Default;
    builder.Services.AddSingleton(commConfig);
    builder.Services.AddSingleton<IBehavedrClient>(sp =>
        new GrpcBehavedrClient(commConfig, sp.GetService<ILogger<GrpcBehavedrClient>>()));
    builder.Services.AddSingleton<OfflineBuffer>();

    // v0.1.3: Auto-updater (H-6 fix)
    builder.Services.AddSingleton<AutoUpdater>();

    // Agent self-protection service
    builder.Services.AddHostedService<SelfProtectionService>();

    // Agent watchdog service (mutual monitoring, last-gasp logging)
    builder.Services.AddHostedService<AgentWatchdog>();

    // Core monitoring background service
    builder.Services.AddHostedService<MonitoringService>();

    // v0.1.3: Communication background service
    builder.Services.AddHostedService<CommunicationService>();

    // v0.1.3: Auto-update check background service
    builder.Services.AddHostedService<UpdateCheckService>();

    // Windows Service / systemd integration
    if (OperatingSystem.IsWindows())
        builder.Services.AddWindowsService(options => options.ServiceName = "Behavedr");
    // Note: UseSystemd() requires the IHostBuilder API. With HostApplicationBuilder,
    // systemd notification is handled via Microsoft.Extensions.Hosting.Systemd automatically
    // when the NOTIFY_SOCKET env var is set by systemd.

    var host = builder.Build();

    // v0.1.3: Register response actions after build (C-1 fix)
    var responseEngine = host.Services.GetRequiredService<ResponseEngine>();
    responseEngine.RegisterAction(host.Services.GetRequiredService<ProcessKillAction>());
    responseEngine.RegisterAction(host.Services.GetRequiredService<FileQuarantineAction>());

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
