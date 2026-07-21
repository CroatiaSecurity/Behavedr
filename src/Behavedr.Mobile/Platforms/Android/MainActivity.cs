using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;

namespace Behavedr.Mobile;

/// <summary>
/// Launcher activity — zero visuals. Starts the foreground monitoring service
/// and immediately moves to background. The user only sees the app icon.
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
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Start the foreground monitoring service
        var serviceIntent = new Intent(this, typeof(BehavedrForegroundService));
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
        {
            StartForegroundService(serviceIntent);
        }
        else
        {
            StartService(serviceIntent);
        }

        // Move to back immediately — user sees nothing
        MoveTaskToBack(true);
    }
}
