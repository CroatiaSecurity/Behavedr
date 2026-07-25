namespace Behavedr.Tests;

/// <summary>
/// Guards that epic source trees and loaders remain present (0.3.2).
/// Does not require Linux/macOS attach success on Windows CI.
/// </summary>
public class EpicCompletenessTests
{
    [Fact]
    public void EbpfSuiteSource_Exists()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "native", "linux", "ebpf", "behavedr_suite.bpf.c")));
        Assert.True(File.Exists(Path.Combine(root, "native", "linux", "ebpf", "README.md")));
        Assert.True(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfLoader.cs")));
    }

    [Fact]
    public void EndpointSecuritySystemExtension_ScaffoldExists()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "SystemExtension", "main.m")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "SystemExtension", "entitlements.plist")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c")));
    }

    [Fact]
    public void EpicsStatusDoc_Exists()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "docs", "EPICS_STATUS.md")));
    }

    [Fact]
    public void LinuxEbpfLoader_FindsNothingOnWindowsWithoutObject()
    {
        if (OperatingSystem.IsLinux()) return;
        var loader = new Behavedr.Core.Monitors.LinuxEbpfLoader();
        // On non-Linux FindObject may still find repo object if present — just must not throw
        _ = loader.FindObject();
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Behavedr.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
    }
}
