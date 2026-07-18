using Behavedr.Core;
using Behavedr.Core.Platform;

namespace Behavedr.Mobile;

public partial class MainPage : ContentPage
{
    private readonly DetectionEngine _engine;

    public MainPage()
    {
        InitializeComponent();
        _engine = AgentBootstrap.CreateEngine();
        RenderStatus();
    }

    private void RenderStatus()
    {
        var platform = PlatformMonitors.CurrentPlatformSummary();
        PlatformLabel.Text = $"Platform: {platform}";
        StatusLabel.Text = _engine.RegisteredMonitors.Count > 0
            ? "Agent active — behavioral monitoring on"
            : "Agent idle — no platform monitor for this OS";

        MonitorsList.Children.Clear();
        foreach (var monitor in _engine.RegisteredMonitors)
        {
            MonitorsList.Children.Add(new Label
            {
                Text = $"• {monitor.GetType().Name} ({monitor.PlatformName})",
                FontSize = 14,
            });
        }

        if (_engine.RegisteredMonitors.Count == 0)
        {
            MonitorsList.Children.Add(new Label
            {
                Text = "• (none supported on this host)",
                FontSize = 14,
                Opacity = 0.6,
            });
        }
    }

    private async void OnRefreshClicked(object? sender, EventArgs e)
    {
        var lines = new List<string>();
        foreach (var monitor in _engine.RegisteredMonitors)
        {
            var signals = await monitor.GetSignalsAsync();
            foreach (var s in signals)
                lines.Add($"{monitor.PlatformName}: {s.Type} w={s.Weight:0.#} c={s.Confidence:0.##}");
        }

        SignalsLabel.Text = lines.Count == 0
            ? "No signals (monitor not supported on this OS)."
            : string.Join(Environment.NewLine, lines);
    }
}
