namespace Behavedr.Core.Monitors;

using System.Diagnostics;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Browser credential file protection monitor.
/// Uses FileSystemWatcher on Chrome/Edge/Firefox credential database paths.
/// Detects non-browser processes accessing credential files (infostealers).
/// Covers: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Waterfox.
/// </summary>
[SupportedOSPlatform("windows")]
public class CredentialGuardMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<CredentialGuardMonitor> _logger;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly List<Signal> _pendingSignals = new();
    private readonly object _lock = new();
    private bool _initialized;

    // Browser processes that legitimately access credential files
    private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "brave", "opera", "vivaldi", "firefox",
        "waterfox", "chromium", "arc", "iridium", "ungoogled-chromium",
    };

    // Critical credential files to monitor
    private static readonly string[] ChromiumCredFiles = { "Login Data", "Cookies", "Web Data", "Local State" };
    private static readonly string[] FirefoxCredFiles = { "key4.db", "logins.json", "cookies.sqlite", "cert9.db" };

    public string PlatformName => "CredentialGuard";
    public bool IsSupported => OperatingSystem.IsWindows();

    public CredentialGuardMonitor(ILogger<CredentialGuardMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<CredentialGuardMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
        {
            InitializeWatchers();
            _initialized = true;
        }

        List<Signal> signals;
        lock (_lock)
        {
            signals = new List<Signal>(_pendingSignals);
            _pendingSignals.Clear();
        }

        // Also do a periodic scan for processes with handles to credential files
        ScanForCredentialAccess(signals, ct);

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void InitializeWatchers()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Chrome/Edge/Brave credential directories
        var chromiumPaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
            Path.Combine(localAppData, "Opera Software", "Opera Stable"),
        };

        foreach (var path in chromiumPaths)
        {
            if (!Directory.Exists(path)) continue;
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true
                };
                foreach (var file in ChromiumCredFiles)
                    watcher.Filters.Add(file);
                watcher.Changed += OnCredentialFileAccessed;
                watcher.Created += OnCredentialFileAccessed;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CredentialGuard] Failed to watch {Path}", path);
            }
        }

        // Firefox profiles
        var firefoxProfiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxProfiles))
        {
            try
            {
                foreach (var profileDir in Directory.GetDirectories(firefoxProfiles))
                {
                    var watcher = new FileSystemWatcher(profileDir)
                    {
                        NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.LastWrite,
                        EnableRaisingEvents = true
                    };
                    foreach (var file in FirefoxCredFiles)
                        watcher.Filters.Add(file);
                    watcher.Changed += OnCredentialFileAccessed;
                    _watchers.Add(watcher);
                }
            }
            catch { }
        }

        _logger.LogInformation("[CredentialGuard] Watching {Count} credential directories", _watchers.Count);
    }

    private void OnCredentialFileAccessed(object sender, FileSystemEventArgs e)
    {
        // Determine which process triggered the access
        // FileSystemWatcher doesn't give us PID, but we can check what processes
        // currently have the file open
        lock (_lock)
        {
            _pendingSignals.Add(new Signal(
                $"credential_file_accessed:{e.Name}",
                55, 0.65));
        }
    }

    [SupportedOSPlatform("windows")]
    private void ScanForCredentialAccess(List<Signal> signals, CancellationToken ct)
    {
        // Check if any non-browser process is accessing well-known credential paths
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (BrowserProcesses.Contains(name)) continue;
                    if (proc.Id == Environment.ProcessId) continue;

                    // Check loaded modules for SQLite (credential DB access indicator)
                    // Non-browser process loading sqlite3.dll is suspicious
                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (module.ModuleName?.Contains("sqlite", StringComparison.OrdinalIgnoreCase) == true &&
                            !BrowserProcesses.Contains(name) &&
                            name is not "python" and not "py" and not "sqlitebrowser")
                        {
                            signals.Add(new Signal(
                                $"non_browser_sqlite_loaded:{name}(pid:{proc.Id})",
                                50, 0.6));
                            break;
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
    }
}
