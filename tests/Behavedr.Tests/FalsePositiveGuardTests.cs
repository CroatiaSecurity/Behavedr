using Behavedr.Core;
using Behavedr.Core.Models;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

/// <summary>
/// Golden / regression checks so high-privilege response paths do not fire on
/// obviously legitimate system processes (false-positive guard suite).
/// </summary>
public class FalsePositiveGuardTests
{
    [Theory]
    [InlineData("csrss")]
    [InlineData("lsass")]
    [InlineData("services")]
    [InlineData("systemd")]
    [InlineData("launchd")]
    [InlineData("behavedr")]
    public async Task ProcessKill_SkipsProtectedNames_WhenSystemPathUnknown(string name)
    {
        // PID 1 is low enough that Windows path treats <=4 as system-critical protection
        var kill = new ProcessKillAction();
        var result = new DetectionResult(
            DetectionEvent.Create("1", name, "test", "fp-suite", false),
            99, true,
            new List<Signal> { new("synthetic", 99, 1.0) });

        var outcome = await kill.ExecuteAsync(result);
        Assert.Contains("Protected", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessKill_RefusesSelf()
    {
        var kill = new ProcessKillAction();
        var result = new DetectionResult(
            DetectionEvent.Create(Environment.ProcessId.ToString(), "testhost", "test", "fp-suite", false),
            99, true,
            new List<Signal>());

        var outcome = await kill.ExecuteAsync(result);
        Assert.Contains("own process", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AlertOnly_NeverKills()
    {
        var engine = new ResponseEngine(new ResponsePolicy
        {
            Mode = ResponseMode.AlertOnly,
            ResponseThreshold = 10,
        });
        engine.RegisterAction(new ProcessKillAction());

        var result = new DetectionResult(
            DetectionEvent.Create("99999", "not-a-real-process-xyz", "t", "fp", true),
            99, true,
            new List<Signal> { new("x", 99, 1) });

        var outcomes = await engine.RespondAsync(result);
        Assert.All(outcomes, o =>
            Assert.Contains("Alert-only", o.Message, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task IosResponse_RefusesPathsOutsideSandbox()
    {
        if (!(OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst() || OperatingSystem.IsWindows() || OperatingSystem.IsLinux()))
            return;

        var ios = new IosResponseEngine();
        // On non-iOS, IsSupported is false
        if (!ios.IsSupported)
        {
            var skip = await ios.ExecuteAsync(new DetectionResult(
                DetectionEvent.Create("1", "app", "t", "t", false),
                90, true,
                new List<Signal> { new("path:/etc/passwd", 90, 1) }));
            Assert.Contains("Not iOS", skip.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        var outcome = await ios.ExecuteAsync(new DetectionResult(
            DetectionEvent.Create("1", "app", "t", "t", false),
            90, true,
            new List<Signal> { new("path:/etc/passwd", 90, 1) }));
        Assert.Contains("sandbox", outcome.Message, StringComparison.OrdinalIgnoreCase);
    }
}
