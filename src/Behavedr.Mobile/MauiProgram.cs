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

        builder.Services.AddSingleton(_ => Core.AgentBootstrap.CreateEngine());

        return builder.Build();
    }
}
