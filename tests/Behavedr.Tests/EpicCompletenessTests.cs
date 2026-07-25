namespace Behavedr.Tests;

/// <summary>
/// Guards that epic source trees and production loaders remain present (0.3.3).
/// Does not require Linux/macOS attach success on Windows CI.
/// </summary>
public class EpicCompletenessTests
{
    [Fact]
    public void EbpfSuiteSource_ExistsAndDocumentsLayout()
    {
        var root = FindRepoRoot();
        var suite = Path.Combine(root, "native", "linux", "ebpf", "behavedr_suite.bpf.c");
        Assert.True(File.Exists(suite));
        Assert.True(File.Exists(Path.Combine(root, "native", "linux", "ebpf", "README.md")));
        Assert.True(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfLoader.cs")));
        Assert.True(File.Exists(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfSuite.cs")));

        var c = File.ReadAllText(suite);
        Assert.Contains("EV_EXEC", c, StringComparison.Ordinal);
        Assert.Contains("EV_OPEN", c, StringComparison.Ordinal);
        Assert.Contains("EV_CONNECT", c, StringComparison.Ordinal);
        Assert.Contains("handle_exec", c, StringComparison.Ordinal);
        Assert.Contains("handle_openat", c, StringComparison.Ordinal);
        Assert.Contains("handle_connect", c, StringComparison.Ordinal);
        Assert.Contains("struct behavedr_event", c, StringComparison.Ordinal);
    }

    [Fact]
    public void EndpointSecuritySystemExtension_IsRealHostNotStub()
    {
        var root = FindRepoRoot();
        var main = Path.Combine(root, "native", "macos", "SystemExtension", "main.m");
        Assert.True(File.Exists(main));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "SystemExtension", "entitlements.plist")));
        Assert.True(File.Exists(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c")));

        var m = File.ReadAllText(main);
        Assert.Contains("es_new_client", m, StringComparison.Ordinal);
        Assert.Contains("es_subscribe", m, StringComparison.Ordinal);
        Assert.Contains("es_respond_auth_result", m, StringComparison.Ordinal);
        Assert.Contains("es.events", m, StringComparison.Ordinal);
        Assert.DoesNotContain("placeholder", m, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("TODO: implement", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EpicsStatusDoc_Exists()
    {
        var root = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(root, "docs", "EPICS_STATUS.md")));
        var doc = File.ReadAllText(Path.Combine(root, "docs", "EPICS_STATUS.md"));
        Assert.Contains("0.3.3", doc, StringComparison.Ordinal);
        Assert.Contains("not scaffold", doc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LinuxEbpfLoader_FindsNothingOnWindowsWithoutObject()
    {
        if (OperatingSystem.IsLinux()) return;
        var loader = new Behavedr.Core.Monitors.LinuxEbpfLoader();
        Assert.Null(loader.FindObject());
    }

    [Fact]
    public void EbpfEventLayout_MatchesDocumentedSize()
    {
        // kind+pid+tgid+pad = 16; comm = 16; path = 112 → 144
        Assert.Equal(144, Behavedr.Core.Monitors.LinuxEbpfLoader.EventSize);
        Assert.Equal(256, Behavedr.Core.Monitors.LinuxEbpfLoader.MaxSlots);
    }

    [Fact]
    public void LinuxEbpfSuite_SharedIsSingleton()
    {
        var a = Behavedr.Core.Monitors.LinuxEbpfSuite.Shared();
        var b = Behavedr.Core.Monitors.LinuxEbpfSuite.Shared();
        Assert.Same(a, b);
        Assert.False(a.IsActive); // no object on this host typically
    }

    [Fact]
    public void WindowsFirewallEngine_Constructs()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fw = new Behavedr.Core.Response.WindowsFirewallEngine();
        // Availability depends on COM registration; construction must not throw
        _ = fw.IsAvailable;
    }

    [Fact]
    public void WindowsWfpEngine_Constructs()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var wfp = new Behavedr.Core.Response.WindowsWfpEngine();
        Assert.False(wfp.IsOpen); // not opened until first block
    }

    [Fact]
    public void WindowsNetworkIsolation_WiresComFirst()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Response", "WindowsNetworkIsolation.cs"));
        Assert.Contains("WindowsFirewallEngine", src, StringComparison.Ordinal);
        Assert.Contains("WindowsWfpEngine", src, StringComparison.Ordinal);
        // Order: COM then WFP then netsh
        var com = src.IndexOf("_fwCom", StringComparison.Ordinal);
        var wfp = src.IndexOf("_wfp.BlockRemoteAddress", StringComparison.Ordinal);
        var netsh = src.IndexOf("BlockIpNetshAsync", StringComparison.Ordinal);
        Assert.True(com > 0 && wfp > com && netsh > wfp);
    }

    [Fact]
    public void EsBridgeSource_ExportsPollApiAndAuthGate()
    {
        var root = FindRepoRoot();
        var c = File.ReadAllText(Path.Combine(root, "native", "macos", "es_bridge", "behavedr_es_bridge.c"));
        Assert.Contains("behavedr_es_poll", c, StringComparison.Ordinal);
        Assert.Contains("behavedr_es_create", c, StringComparison.Ordinal);
        Assert.Contains("behavedr_es_set_auth_mode", c, StringComparison.Ordinal);
        Assert.Contains("BEHAVEDR_ES_RING", c, StringComparison.Ordinal);
        Assert.Contains("memory_order_release", c, StringComparison.Ordinal);
        Assert.Contains("g_auth_mode", c, StringComparison.Ordinal);
        Assert.Contains("path_is_denylisted", c, StringComparison.Ordinal);
    }

    [Fact]
    public void LoaderSource_UsesBpfSyscallsNotMapDumpOnly()
    {
        var root = FindRepoRoot();
        var src = File.ReadAllText(Path.Combine(root, "src", "Behavedr.Core", "Monitors", "LinuxEbpfLoader.cs"));
        Assert.Contains("BPF_OBJ_GET", src, StringComparison.Ordinal);
        Assert.Contains("BPF_MAP_LOOKUP_ELEM", src, StringComparison.Ordinal);
        Assert.Contains("pinmaps", src, StringComparison.Ordinal);
        Assert.DoesNotContain("map dump name", src, StringComparison.OrdinalIgnoreCase);
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
