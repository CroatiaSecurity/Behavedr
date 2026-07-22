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
///
/// Resilience mechanisms (v0.1.8 hardening):
/// - StartCommandResult.Sticky: OS restarts service if killed for resources
/// - OnTaskRemoved override: restarts via AlarmManager if user swipes away
/// - WakeLock: prevents CPU sleep during detection cycles
/// - BOOT_COMPLETED receiver: auto-start on device boot
/// - Monitoring interval reduced from 30s to 10s for better detection coverage
/// </summary>
[Service(
    ForegroundServiceType = ForegroundService.TypeSpecialUse,
    Exported = false)]
public class BehavedrForegroundService : Service
{
    private const int NotificationId = 1;
    private const string ChannelId = "behavedr_agent";
    private const string WakeLockTag = "behavedr:monitoring";
    private CancellationTokenSource? _cts;
    private DetectionEngine? _engine;
    private PowerManager.WakeLock? _wakeLock;

    public override IBinder? OnBind(Intent? intent) => null;

    public override void OnCreate()
    {
        base.OnCreate();
        CreateNotificationChannel();
        AcquireWakeLock();
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
        ReleaseWakeLock();
        base.OnDestroy();
    }

    /// <summary>
    /// Called when the user swipes the app away from recents.
    /// Schedule a restart via AlarmManager to ensure the service comes back.
    /// This is critical — without it, swiping kills the service permanently on some OEMs.
    /// </summary>
    public override void OnTaskRemoved(Intent? rootIntent)
    {
        base.OnTaskRemoved(rootIntent);
        ScheduleRestart();
    }

    private async Task MonitoringLoop(CancellationToken ct)
    {
        // Reduced interval from 30s to 10s for better real-time detection coverage
        var interval = TimeSpan.FromSeconds(10);

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
                    catch (OperationCanceledException)
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
                await Task.Delay(interval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Schedule a service restart via AlarmManager.
    /// Used when the service is killed by user swipe or OEM battery optimization.
    /// Fires after 5 seconds to give the system time to clean up.
    /// </summary>
    private void ScheduleRestart()
    {
        try
        {
            var restartIntent = new Intent(this, typeof(BehavedrForegroundService));
            restartIntent.SetPackage(PackageName);

            var pendingIntent = PendingIntent.GetService(
                this, 1, restartIntent,
                PendingIntentFlags.OneShot | PendingIntentFlags.Immutable);

            var alarmManager = GetSystemService(AlarmService) as AlarmManager;
            if (alarmManager is not null && pendingIntent is not null)
            {
                var triggerTime = SystemClock.ElapsedRealtime() + 5000; // 5 seconds
                alarmManager.SetExactAndAllowWhileIdle(
                    AlarmType.ElapsedRealtimeWakeup, triggerTime, pendingIntent);
            }
        }
        catch
        {
            // Best effort — some OEMs restrict AlarmManager
        }
    }

    /// <summary>
    /// Acquire a partial wake lock to prevent CPU from sleeping during monitoring.
    /// Without this, Doze mode can delay detection cycles by minutes.
    /// </summary>
    private void AcquireWakeLock()
    {
        try
        {
            var powerManager = GetSystemService(PowerService) as PowerManager;
            _wakeLock = powerManager?.NewWakeLock(WakeLockFlags.Partial, WakeLockTag);
            _wakeLock?.Acquire();
        }
        catch { }
    }

    private void ReleaseWakeLock()
    {
        try
        {
            if (_wakeLock?.IsHeld == true)
                _wakeLock.Release();
        }
        catch { }
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
            Description = "Behavioral monitoring service",
            LockscreenVisibility = NotificationVisibility.Secret,
        };

        // Minimize user annoyance while maintaining persistence
        channel.SetShowBadge(false);
        channel.EnableVibration(false);
        channel.EnableLights(false);

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
            .SetCategory(Notification.CategoryService)
            .SetVisibility(NotificationVisibility.Secret);

        return builder.Build()!;
    }
}
