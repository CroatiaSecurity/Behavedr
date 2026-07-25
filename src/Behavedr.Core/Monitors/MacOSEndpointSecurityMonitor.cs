namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// macOS EndpointSecurity.framework client (platform epic).
///
/// Subscribes to NOTIFY_EXEC / NOTIFY_FORK / NOTIFY_EXIT when:
/// - Running as root
/// - EndpointSecurity.framework is present
/// - Process holds <c>com.apple.developer.endpoint-security.client</c> (or is in early-boot/dev context)
///
/// Without the entitlement, <see cref="TryConnect"/> fails closed and
/// <see cref="MacOSKqueueMonitor"/> remains the userland path.
/// Packaging: see packaging/unix/macos-endpointsecurity.md
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOSEndpointSecurityMonitor : IPlatformMonitor, IDisposable
{
    private readonly ILogger<MacOSEndpointSecurityMonitor> _logger;
    private readonly object _lock = new();
    private readonly Queue<EsEvent> _events = new();
    private const int MaxEvents = 500;

    private IntPtr _client = IntPtr.Zero;
    private bool _active;
    private bool _initialized;
    private Thread? _pump;
    private volatile bool _stop;

    private static readonly HashSet<string> OffensiveTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz", "meterpreter", "empire", "sliver", "cobalt",
        "chisel", "ligolo", "socat", "ncat", "linpeas",
        "swiftbelt", "bifrost", "osascript", "python",
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

        if (!OperatingSystem.IsMacOS())
            return false;

        if (!File.Exists("/System/Library/Frameworks/EndpointSecurity.framework/EndpointSecurity") &&
            !File.Exists("/System/Library/Frameworks/EndpointSecurity.framework/Versions/Current/EndpointSecurity"))
        {
            _logger.LogWarning("[ES] EndpointSecurity.framework not found");
            return false;
        }

        try
        {
            // es_new_client requires a block callback — on .NET we use a native helper if present,
            // otherwise dlopen + es_new_client with a static unmanaged callback.
            if (!NativeEs.TryCreateClient(OnEsMessage, out _client, out var err))
            {
                _logger.LogWarning(
                    "[ES] es_new_client failed ({Err}). Need root + endpoint-security client entitlement. " +
                    "kqueue path remains active. See packaging/unix/macos-endpointsecurity.md",
                    err);
                return false;
            }

            // NOTIFY for telemetry; AUTH for high-value paths when entitlements allow (0.2.8)
            var events = new List<uint>
            {
                ES_EVENT_TYPE_NOTIFY_EXEC,
                ES_EVENT_TYPE_NOTIFY_FORK,
                ES_EVENT_TYPE_NOTIFY_EXIT,
                ES_EVENT_TYPE_NOTIFY_OPEN,
            };

            // Optional AUTH mode via env BEHAVEDR_ES_AUTH=1 (requires full ES capability)
            var authMode = string.Equals(
                Environment.GetEnvironmentVariable("BEHAVEDR_ES_AUTH"), "1", StringComparison.Ordinal);
            if (authMode)
            {
                events.Add(ES_EVENT_TYPE_AUTH_EXEC);
                events.Add(ES_EVENT_TYPE_AUTH_OPEN);
                _logger.LogWarning("[ES] AUTH mode requested (BEHAVEDR_ES_AUTH=1) — will deny only denylist paths");
            }

            if (!NativeEs.TrySubscribe(_client, events.ToArray(), out err))
            {
                _logger.LogWarning("[ES] es_subscribe failed ({Err})", err);
                NativeEs.DeleteClient(_client);
                _client = IntPtr.Zero;
                return false;
            }

            _active = true;
            _stop = false;
            _pump = new Thread(PumpLoop) { IsBackground = true, Name = "Behavedr-ES-pump" };
            _pump.Start();
            _logger.LogInformation(
                "[ES] EndpointSecurity client subscribed (NOTIFY{Auth})",
                authMode ? "+AUTH" : "");
            return true;
        }
        catch (DllNotFoundException)
        {
            _logger.LogWarning("[ES] Failed to load EndpointSecurity — framework missing or wrong arch");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[ES] Connect failed");
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
                $"es_{e.Kind}:{e.ProcessName}:pid:{e.Pid}",
                e.Kind == "exec" ? 40 : 25,
                0.85));

            if (e.Kind == "exec" &&
                OffensiveTools.Any(t => e.ProcessName.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                signals.Add(new Signal(
                    $"es_offensive_tool:{e.ProcessName}:pid:{e.Pid}",
                    92, 0.95));
            }

            if (e.Kind == "open" && IsSensitivePath(e.Path))
            {
                signals.Add(new Signal(
                    $"es_sensitive_open:{e.ProcessName}:pid:{e.Pid}:{Truncate(e.Path, 80)}",
                    70, 0.8));
            }
        }

        if (batch.Count > 0)
            signals.Add(new Signal($"es_event_batch:{batch.Count}", 15, 0.6));

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    public void Dispose()
    {
        _stop = true;
        try { _pump?.Join(500); } catch { }
        if (_client != IntPtr.Zero)
        {
            NativeEs.DeleteClient(_client);
            _client = IntPtr.Zero;
        }
        _active = false;
    }

    private void OnEsMessage(string kind, int pid, string processName, string path)
    {
        lock (_lock)
        {
            _events.Enqueue(new EsEvent(kind, pid, processName, path));
            while (_events.Count > MaxEvents)
                _events.Dequeue();
        }
    }

    private void PumpLoop()
    {
        // EndpointSecurity delivers via callback; pump keeps process responsive
        while (!_stop)
            Thread.Sleep(200);
    }

    private static bool IsSensitivePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        return path.Contains("/Library/LaunchDaemons", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/Library/LaunchAgents", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/etc/", StringComparison.Ordinal)
            || path.Contains("shadow", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Authorization", StringComparison.OrdinalIgnoreCase);
    }

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n];

    // Event type constants from ESMessage.h (values stable across recent SDKs)
    private const uint ES_EVENT_TYPE_AUTH_EXEC = 8;
    private const uint ES_EVENT_TYPE_NOTIFY_EXEC = 9;
    private const uint ES_EVENT_TYPE_NOTIFY_OPEN = 10;
    private const uint ES_EVENT_TYPE_AUTH_OPEN = 11;
    private const uint ES_EVENT_TYPE_NOTIFY_FORK = 13;
    private const uint ES_EVENT_TYPE_NOTIFY_EXIT = 14;

    private readonly record struct EsEvent(string Kind, int Pid, string ProcessName, string Path);

    /// <summary>
    /// Thin P/Invoke + optional native shim. When full block-based es_new_client
    /// cannot be expressed from pure C#, we dlsym a helper exported from a small
    /// dylib <c>libbehavedr_es.dylib</c> if present; otherwise attempt framework
    /// symbols with a Cdecl stub (may fail without helper — then kqueue stays primary).
    /// </summary>
    private static class NativeEs
    {
        public static bool TryCreateClient(Action<string, int, string, string> callback, out IntPtr client, out string error)
        {
            client = IntPtr.Zero;
            error = "";

            // Prefer helper dylib that owns the Objective-C/block bridge
            if (File.Exists(HelperPath) || File.Exists(Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib")))
            {
                try
                {
                    var path = File.Exists(HelperPath) ? HelperPath : Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib");
                    var lib = dlopen(path, RTLD_NOW);
                    if (lib != IntPtr.Zero)
                    {
                        var sym = dlsym(lib, "behavedr_es_create");
                        if (sym != IntPtr.Zero)
                        {
                            var create = Marshal.GetDelegateForFunctionPointer<BehavedrEsCreate>(sym);
                            // Store callback in static for native to call via reverse P/Invoke
                            s_callback = callback;
                            int rc = create(OnNativeEvent, out client);
                            if (rc == 0 && client != IntPtr.Zero)
                                return true;
                            error = $"behavedr_es_create rc={rc}";
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }
            }

            // Without helper, mark unavailable with actionable error
            error = "libbehavedr_es.dylib not loaded (build native/macos/es_bridge)";
            return false;
        }

        public static bool TrySubscribe(IntPtr client, uint[] events, out string error)
        {
            error = "";
            try
            {
                if (File.Exists(HelperPath) || File.Exists(Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib")))
                {
                    var path = File.Exists(HelperPath) ? HelperPath : Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib");
                    var lib = dlopen(path, RTLD_NOW);
                    var sym = dlsym(lib, "behavedr_es_subscribe");
                    if (sym != IntPtr.Zero)
                    {
                        var sub = Marshal.GetDelegateForFunctionPointer<BehavedrEsSubscribe>(sym);
                        int rc = sub(client, events, events.Length);
                        if (rc == 0) return true;
                        error = $"subscribe rc={rc}";
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
            error = "subscribe symbol missing";
            return false;
        }

        public static void DeleteClient(IntPtr client)
        {
            try
            {
                var path = File.Exists(HelperPath) ? HelperPath : Path.Combine(AppContext.BaseDirectory, "libbehavedr_es.dylib");
                if (!File.Exists(path)) return;
                var lib = dlopen(path, RTLD_NOW);
                var sym = dlsym(lib, "behavedr_es_delete");
                if (sym == IntPtr.Zero) return;
                var del = Marshal.GetDelegateForFunctionPointer<BehavedrEsDelete>(sym);
                del(client);
            }
            catch { }
        }

        private static string HelperPath => "/opt/behavedr/libbehavedr_es.dylib";

        private static Action<string, int, string, string>? s_callback;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void NativeEventCb(IntPtr kind, int pid, IntPtr processName, IntPtr path);

        private static readonly NativeEventCb OnNativeEvent = static (k, pid, n, p) =>
        {
            var kind = Marshal.PtrToStringUTF8(k) ?? "event";
            var name = Marshal.PtrToStringUTF8(n) ?? "";
            var path = Marshal.PtrToStringUTF8(p) ?? "";
            s_callback?.Invoke(kind, pid, name, path);
        };

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int BehavedrEsCreate(NativeEventCb cb, out IntPtr client);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int BehavedrEsSubscribe(IntPtr client, uint[] events, int count);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void BehavedrEsDelete(IntPtr client);

        private const int RTLD_NOW = 2;

        [DllImport("libSystem.B.dylib")]
        private static extern IntPtr dlopen(string path, int mode);

        [DllImport("libSystem.B.dylib")]
        private static extern IntPtr dlsym(IntPtr handle, string symbol);
    }
}
