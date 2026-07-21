using Behavedr.Core.Platform;

namespace Behavedr.Tests;

public class PlatformMonitorsTests
{
    [Fact]
    public void All_ContainsAtLeastBasePlatformMonitors()
    {
        // Base monitors: Windows, Linux, macOS, Android, iOS + cross-platform monitors.
        // On Windows, additional behavioral/anti-tamper monitors are added dynamically.
        Assert.True(PlatformMonitors.All.Count >= 7,
            $"Expected at least 7 monitors (5 platform + 2 cross-platform), got {PlatformMonitors.All.Count}");
    }

    [Fact]
    public void All_ContainsExpectedPlatforms()
    {
        var names = PlatformMonitors.All.Select(m => m.PlatformName).ToList();
        Assert.Contains("Windows", names);
        Assert.Contains("Linux", names);
        Assert.Contains("macOS", names);
        Assert.Contains("Android", names);
        Assert.Contains("iOS", names);
    }

    [Fact]
    public void Supported_ReturnsOnlyMatchingPlatform()
    {
        var supported = PlatformMonitors.Supported().ToList();

        // On the test host, exactly one desktop monitor should be supported
        Assert.True(supported.Count >= 1, "At least one monitor should be supported on the test host");

        // All returned monitors should report IsSupported = true
        Assert.All(supported, m => Assert.True(m.IsSupported));
    }

    [Fact]
    public void CurrentPlatformSummary_ReturnsNonEmpty()
    {
        var summary = PlatformMonitors.CurrentPlatformSummary();
        Assert.False(string.IsNullOrWhiteSpace(summary));
        Assert.NotEqual("Unknown", summary);
    }
}
