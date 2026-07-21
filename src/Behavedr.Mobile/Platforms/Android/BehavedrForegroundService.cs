using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Behavedr.Core;
using Behavedr.Core.Platform;

namespace Behavedr.Mobile;

/// <summary>
/// Android foreground service — runs behavioral monitoring continuously.
/// Only visible artifact: a persistent notification with the Behavedr icon.
/// This is required by Android to keep the process alive in background.
/// </summary>
[Service(
    ForegroundServiceType = ForegroundService.TypeSpecialUse,
    Exported = false)]
public class BehavedrForegroundService : Service
{
    private const int NotificationId = 1;
    private const string ChannelId = "behavedr_agent";
    private CancellationTokenSource? _cts;
    private DetectionEngine? _engine;

    public override IBinder? OnBind(Intent? intent) => null;

    public override void OnCreate()
    {
        base.OnCreate();
        CreateNotificationChannel();
        _engine = AgentBootstrap.CreateEngine();
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        var notification = BuildNotification();
        StartForeground(NotificationId, notification);

        _cts = new CancellationTokenSource();
        _ = Task.Run(() => MonitoringLoop(_cts.Token));

        return StartCommandResult.Sticky;
    }

    public override void OnDestroy()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        base.OnDestroy();
    }

    private async Task MonitoringLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            if (_engine is not null)
            {
                foreach (var monitor in _engine.RegisteredMonitors)
                {
                    try
                    {
                        await monitor.GetSignalsAsync(ct);
                    }
                    catch (System.OperationCanceledException)
                    {
                        return;
                    }
                    catch
                    {
                        // Individual monitor failures don't kill the service
                    }
                }
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
            catch (System.OperationCanceledException)
            {
                return;
            }
        }
    }

    private void CreateNotificationChannel()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.O)
            return;

        var channel = new NotificationChannel(
            ChannelId,
            "Behavedr Agent",
            NotificationImportance.Low)
        {
            Description = "Behavioral monitoring service"
        };

        var manager = GetSystemService(NotificationService) as NotificationManager;
        manager?.CreateNotificationChannel(channel);
    }

    private Notification BuildNotification()
    {
        var builder = new Notification.Builder(this, ChannelId)
            .SetContentTitle("Behavedr")
            .SetContentText("Monitoring active")
            .SetSmallIcon(Resource.Mipmap.appicon)
            .SetOngoing(true)
            .SetCategory(Notification.CategoryService);

        return builder.Build()!;
    }
}
