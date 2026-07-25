namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS EndpointSecurity client (production, 0.3.3).
/// Uses libbehavedr_es.dylib which owns the ES callback thread and a ring buffer.
/// Managed code polls via <c>behavedr_es_poll</c> (no GC-sensitive callbacks from ES).
/// Soft-fails without entitlement/dylib; <see cref="MacOSKqueueMonitor"/> remains primary.
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSEndpointSecurityMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<MacOSEndpointSecurityMonitor> _logger;
    private readonly object _lock = new();
    private readonly Queue<EsEvent> _events = new();
    private const int MaxEvents = 2000;

    private IntPtr _client = IntPtr.Zero;
    private IntPtr _lib = IntPtr.Zero;
    private bool _active;
    private bool _initialized;
    private Thread? _pollThread;
    private volatile bool _stop;

    private BehavedrEsCreate? _create;
    private BehavedrEsSubscribeDefault? _subscribeDefault;
    private BehavedrEsSubscribe? _subscribeLegacy;
    private BehavedrEsPoll? _poll;
    private BehavedrEsDelete? _delete;
    private BehavedrEsSetAuth? _setAuth;
    public string ActiveMode => _active ? "poll-ring-bridge" : "inactive";

    private static readonly HashSet<string> OffensiveTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz", "meterpreter", "empire", "sliver", "cobalt",
        "chisel", "ligolo", "socat", "ncat", "linpeas",
        "swiftbelt", "bifrost",
    };

    public string PlatformName => "MacOSEndpointSecurity";
    public bool IsSupported => OperatingSystem.IsMacOS();
    public bool IsActive => _active;

    public MacOSEndpointSecurityMonitor(ILogger<MacOSEndpointSecurityMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<MacOSEndpointSecurityMonitor>.Instance;
    }

    public bool TryConnect()
    {
        if (_initialized) return _active;
        _initialized = true;
        if (!OperatingSystem.IsMacOS()) return false;

        try
        {
            if (!TryBindLibrary(out var err))
            {
                Telemetry.SecurityTelemetry.ReportPlatformSoftFail("endpointsecurity");
                _logger.LogWarning("[ES] {Err}. kqueue remains primary. See packaging/unix/macos-endpointsecurity.md", err);
                return false;
            }

            int rc = _create!(out _client);
            if (rc != 0 || _client == IntPtr.Zero)
            {
                Telemetry.SecurityTelemetry.ReportPlatformSoftFail("endpointsecurity");
                _logger.LogWarning(
                    "[ES] es_new_client failed rc={Rc}. Need root + ES client entitlement.", rc);
                return false;
            }

            var authMode = string.Equals(
                Environment.GetEnvironmentVariable("BEHAVEDR_ES_AUTH"), "1", StringComparison.Ordinal);
            _setAuth?.Invoke(authMode ? 1 : 0);

            // Prefer native subscribe_default so event IDs come from framework headers
            // (hardcoded managed enums previously mismatched AUTH_EXEC=0 vs 8).
            if (_subscribeDefault is not null)
            {
                rc = _subscribeDefault(_client, authMode ? 1 : 0);
                if (rc < 0)
                {
                    _logger.LogWarning("[ES] behavedr_es_subscribe_default failed rc={Rc}", rc);
                    _delete!(_client);
                    _client = IntPtr.Zero;
                    return false;
                }
                if (authMode)
                    _logger.LogWarning("[ES] AUTH_EXEC denylist enabled (tmp droppers / known tools)");
            }
            else if (_subscribeLegacy is not null)
            {
                // Fallback: Apple 10.15+ enum order (AUTH_EXEC=0 … NOTIFY_EXEC=9 …)
                var events = BuildDefaultEventIds(authMode);
                rc = _subscribeLegacy(_client, events, events.Length);
                if (rc != 0)
                {
                    _logger.LogWarning("[ES] es_subscribe failed rc={Rc}", rc);
                    _delete!(_client);
                    _client = IntPtr.Zero;
                    return false;
                }
            }
            else
            {
                _logger.LogWarning("[ES] No subscribe symbol in dylib");
                _delete!(_client);
                _client = IntPtr.Zero;
                return false;
            }

            _active = true;
            _stop = false;
            _pollThread = new Thread(PollLoop)
            {
                IsBackground = true,
                Name = "Behavedr-ES-poll",
            };
            _pollThread.Start();
            _logger.LogInformation("[ES] Active — poll mode, auth={Auth}, via={Via}",
                authMode, _subscribeDefault is not null ? "subscribe_default" : "legacy-ids");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ES] Connect failed");
            Telemetry.SecurityTelemetry.ReportPlatformSoftFail("endpointsecurity");
            return false;
        }
    }

    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        if (!_initialized)
            TryConnect();

        var signals = new List<Signal>();
        if (!_active)
        {
            signals.Add(new Signal("endpointsecurity_inactive:using_kqueue_fallback", 15, 0.4));
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        List<EsEvent> batch;
        lock (_lock)
        {
            batch = _events.ToList();
            _events.Clear();
        }

        foreach (var e in batch)
        {
            signals.Add(new Signal(
                $"es_{e.Kind}:{e.ProcessName}:pid:{e.Pid}:{Truncate(e.Path, 80)}",
                e.Kind is "exec" or "auth_exec" or "auth_denied" ? 45 : 30,
                0.88));

            if (e.Kind is "exec" or "auth_exec" &&
                OffensiveTools.Any(t => e.ProcessName.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                                        e.Path.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                signals.Add(new Signal($"es_offensive_tool:{e.ProcessName}:pid:{e.Pid}", 93, 0.96));
            }

            if (e.Kind == "auth_denied")
                signals.Add(new Signal($"es_auth_denied:{e.ProcessName}:pid:{e.Pid}:{Truncate(e.Path, 64)}", 90, 0.95));
        }

        if (batch.Count > 0)
            signals.Add(new Signal($"es_batch:{batch.Count}", 12, 0.5));

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    public void Dispose()
    {
        _stop = true;
        try { _pollThread?.Join(1000); } catch { }
        if (_client != IntPtr.Zero && _delete is not null)
        {
            try { _delete(_client); } catch { }
            _client = IntPtr.Zero;
        }
        _active = false;
    }

    private void PollLoop()
    {
        var kind = new byte[32];
        var name = new byte[64];
        var path = new byte[512];
        while (!_stop)
        {
            try
            {
                int n = 0;
                while (n++ < 200 && _poll is not null)
                {
                    int rc = _poll(kind, kind.Length, out int pid, name, name.Length, path, path.Length);
                    if (rc <= 0) break;
                    var ev = new EsEvent(
                        CString(kind),
                        pid,
                        CString(name),
                        CString(path));
                    lock (_lock)
                    {
                        _events.Enqueue(ev);
                        while (_events.Count > MaxEvents)
                            _events.Dequeue();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ES] poll error");
            }
            Thread.Sleep(25);
        }
    }

    private bool TryBindLibrary(out string error)
    {
        error = "";
        foreach (var path in LibraryCandidates())
        {
            if (!File.Exists(path)) continue;
            _lib = dlopen(path, RTLD_NOW);
            if (_lib == IntPtr.Zero) continue;

            _create = Load<BehavedrEsCreate>("behavedr_es_create");
            _subscribeDefault = LoadOptional<BehavedrEsSubscribeDefault>("behavedr_es_subscribe_default");
            _subscribeLegacy = LoadOptional<BehavedrEsSubscribe>("behavedr_es_subscribe");
            _poll = Load<BehavedrEsPoll>("behavedr_es_poll");
            _delete = Load<BehavedrEsDelete>("behavedr_es_delete");
            _setAuth = LoadOptional<BehavedrEsSetAuth>("behavedr_es_set_auth_mode");

            if (_create is null || _poll is null || _delete is null ||
                (_subscribeDefault is null && _subscribeLegacy is null))
            {
                error = $"incomplete ABI in {path} (need create/poll/delete + subscribe*)";
                continue;
            }
            _logger.LogInformation(
                "[ES] Bound library {Path} (subscribe_default={Def}, set_auth={Auth})",
                path, _subscribeDefault is not null, _setAuth is not null);
            return true;
        }
        error = "libbehavedr_es.dylib not found or incomplete (build native/macos/es_bridge)";
        return false;
    }

    private T? Load<T>(string symbol) where T : Delegate
    {
        var sym = dlsym(_lib, symbol);
        return sym == IntPtr.Zero ? null : Marshal.GetDelegateForFunctionPointer<T>(sym);
    }

    private T? LoadOptional<T>(string symbol) where T : Delegate => Load<T>(symbol);

    private static IEnumerable<string> LibraryCandidates()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib");
        yield return "/opt/behavedr/libbehavedr_es.dylib";
        yield return Path.Combine(Directory.GetCurrentDirectory(), "libbehavedr_es.dylib");
        yield return Path.Combine(Directory.GetCurrentDirectory(), "native", "macos", "es_bridge", "libbehavedr_es.dylib");
    }

    private static string CString(byte[] buf)
    {
        var n = Array.IndexOf(buf, (byte)0);
        if (n < 0) n = buf.Length;
        return Encoding.UTF8.GetString(buf, 0, n);
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : s.Length <= n ? s : s[..n];

    /// <summary>
    /// Apple ESTypes.h order from macOS 10.15 (only used if dylib lacks subscribe_default).
    /// AUTH_EXEC=0, AUTH_OPEN=1, … AUTH_UNLINK=8, NOTIFY_EXEC=9, NOTIFY_OPEN=10,
    /// NOTIFY_FORK=11, NOTIFY_CLOSE=12, NOTIFY_CREATE=13, NOTIFY_EXCHANGEDATA=14,
    /// NOTIFY_EXIT=15. WRITE/RENAME appear later in the enum — prefer subscribe_default.
    /// </summary>
    private static uint[] BuildDefaultEventIds(bool authMode)
    {
        // Minimal correct set without WRITE/RENAME (those numbers vary by SDK generation).
        var list = new List<uint>
        {
            9,  // NOTIFY_EXEC
            11, // NOTIFY_FORK
            15, // NOTIFY_EXIT
            10, // NOTIFY_OPEN
            13, // NOTIFY_CREATE
        };
        if (authMode)
            list.Add(0); // AUTH_EXEC only
        return list.ToArray();
    }

    private readonly record struct EsEvent(string Kind, int Pid, string ProcessName, string Path);

    private const int RTLD_NOW = 2;

    [DllImport("libSystem.B.dylib")]
    private static extern IntPtr dlopen(string path, int mode);

    [DllImport("libSystem.B.dylib")]
    private static extern IntPtr dlsym(IntPtr handle, string symbol);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsCreate(out IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSubscribeDefault(IntPtr client, int authMode);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSubscribe(IntPtr client, uint[] events, int count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsPoll(
        byte[] kind, int kindLen,
        out int pid,
        byte[] name, int nameLen,
        byte[] path, int pathLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void BehavedrEsDelete(IntPtr client);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BehavedrEsSetAuth(int enabled);
}
