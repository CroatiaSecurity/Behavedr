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

        builder.Services.AddSingleton(sp =>
        {
            var engine = Core.AgentBootstrap.CreateEngine();
            return engine;
        });

        return builder.Build();
    }
}
