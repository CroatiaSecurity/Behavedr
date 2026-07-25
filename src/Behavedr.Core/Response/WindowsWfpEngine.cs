namespace Behavedr.Core.Response;

using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// User-mode Windows Filtering Platform (WFP) engine for network isolation.
/// Uses fwpuclnt.dll filter APIs — real WFP layers, not netsh text wrapping.
/// Does <b>not</b> require a callout driver or WHQL signing; callout drivers
/// remain optional for deep packet inspection beyond block/permit.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWfpEngine : IDisposable
{
    private readonly ILogger _logger;
    private IntPtr _engine = IntPtr.Zero;
    private readonly List<Guid> _filterIds = new();
    private readonly object _lock = new();
    private bool _disposed;
    private const int MaxFilters = 100;

    // Sub-layer GUID for Behavedr (stable, project-specific)
    private static readonly Guid BehavedrSubLayerKey = new("A7C4E8F1-2B3D-4E5F-9A0B-1C2D3E4F5A6C");
    private static readonly Guid FwpmLayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    private static readonly Guid FwpmLayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid FwpmConditionIpRemoteAddressV4 = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid FwpmConditionIpRemoteAddressV6 = new("246e1d8f-40f3-4f3b-b6bb-b5b501ffd1f7");

    public bool IsOpen => _engine != IntPtr.Zero;

    public WindowsWfpEngine(ILogger? logger = null)
    {
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Open the WFP filter engine and ensure our sub-layer exists.</summary>
    public bool TryOpen()
    {
        if (_engine != IntPtr.Zero)
            return true;

        uint result = FwpmEngineOpen0(
            serverName: null,
            authnService: RPC_C_AUTHN_WINNT,
            authIdentity: IntPtr.Zero,
            session: IntPtr.Zero,
            engineHandle: out _engine);

        if (result != 0 || _engine == IntPtr.Zero)
        {
            _logger.LogWarning("[WFP] FwpmEngineOpen0 failed: 0x{Code:X8}", result);
            _engine = IntPtr.Zero;
            return false;
        }

        EnsureSubLayer();
        _logger.LogInformation("[WFP] Filter engine open");
        return true;
    }

    /// <summary>
    /// Block outbound connections to a remote IPv4 or IPv6 address at ALE_AUTH_CONNECT.
    /// </summary>
    public bool BlockRemoteAddress(IPAddress address, string comment)
    {
        if (!TryOpen())
            return false;

        lock (_lock)
        {
            if (_filterIds.Count >= MaxFilters)
            {
                _logger.LogWarning("[WFP] Filter limit {Max} reached", MaxFilters);
                return false;
            }
        }

        bool isV6 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var layerKey = isV6 ? FwpmLayerAleAuthConnectV6 : FwpmLayerAleAuthConnectV4;
        var condField = isV6 ? FwpmConditionIpRemoteAddressV6 : FwpmConditionIpRemoteAddressV4;

        var filterKey = Guid.NewGuid();
        var displayName = $"Behavedr block {address}";

        // Build FWPM_FILTER0 on unmanaged heap for correct layout across runtimes
        IntPtr filterPtr = IntPtr.Zero;
        IntPtr namePtr = IntPtr.Zero;
        IntPtr descPtr = IntPtr.Zero;
        IntPtr condPtr = IntPtr.Zero;
        try
        {
            namePtr = Marshal.StringToHGlobalUni(displayName);
            descPtr = Marshal.StringToHGlobalUni(comment.Length > 200 ? comment[..200] : comment);

            var condition = new FWPM_FILTER_CONDITION0
            {
                fieldKey = condField,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = BuildAddrValue(address, isV6),
            };
            condPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
            Marshal.StructureToPtr(condition, condPtr, false);

            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = namePtr, description = descPtr },
                flags = 0,
                providerKey = IntPtr.Zero,
                providerData = default,
                layerKey = layerKey,
                subLayerKey = BehavedrSubLayerKey,
                weight = new FWP_VALUE0 { type = FWP_EMPTY },
                numFilterConditions = 1,
                filterCondition = condPtr,
                action = new FWPM_ACTION0 { type = FWP_ACTION_BLOCK, filterType = Guid.Empty },
                rawContext = 0,
                reserved = IntPtr.Zero,
                filterId = 0,
                effectiveWeight = new FWP_VALUE0 { type = FWP_EMPTY },
            };

            filterPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_FILTER0>());
            Marshal.StructureToPtr(filter, filterPtr, false);

            uint hr = FwpmFilterAdd0(_engine, filterPtr, IntPtr.Zero, out ulong filterId);
            if (hr != 0)
            {
                _logger.LogWarning("[WFP] FwpmFilterAdd0 failed for {Ip}: 0x{Code:X8}", address, hr);
                return false;
            }

            lock (_lock)
                _filterIds.Add(filterKey);

            _logger.LogWarning("[WFP] Blocked remote {Ip} (filterId={Id})", address, filterId);
            return true;
        }
        finally
        {
            if (filterPtr != IntPtr.Zero) Marshal.FreeHGlobal(filterPtr);
            if (condPtr != IntPtr.Zero) Marshal.FreeHGlobal(condPtr);
            if (namePtr != IntPtr.Zero) Marshal.FreeHGlobal(namePtr);
            if (descPtr != IntPtr.Zero) Marshal.FreeHGlobal(descPtr);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_engine == IntPtr.Zero)
            return;

        lock (_lock)
        {
            foreach (var id in _filterIds)
            {
                try
                {
                    var key = id;
                    FwpmFilterDeleteByKey0(_engine, ref key);
                }
                catch { /* best-effort cleanup */ }
            }
            _filterIds.Clear();
        }

        FwpmEngineClose0(_engine);
        _engine = IntPtr.Zero;
    }

    private void EnsureSubLayer()
    {
        var namePtr = Marshal.StringToHGlobalUni("Behavedr Isolation");
        var descPtr = Marshal.StringToHGlobalUni("Behavedr EDR network isolation sub-layer");
        try
        {
            var sub = new FWPM_SUBLAYER0
            {
                subLayerKey = BehavedrSubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = namePtr, description = descPtr },
                flags = 0,
                providerKey = IntPtr.Zero,
                providerData = default,
                weight = 0x8000, // mid-high priority
            };
            IntPtr subPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_SUBLAYER0>());
            try
            {
                Marshal.StructureToPtr(sub, subPtr, false);
                // Already exists → ignore error
                FwpmSubLayerAdd0(_engine, subPtr, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(subPtr);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(descPtr);
        }
    }

    private static FWP_CONDITION_VALUE0 BuildAddrValue(IPAddress address, bool isV6)
    {
        if (!isV6)
        {
            var bytes = address.GetAddressBytes();
            // FWP_UINT32 expects host-order? Docs: network byte order for addresses in FWP_BYTE_ARRAY16;
            // For V4 address condition FWP_V4_ADDR_AND_MASK is preferred.
            uint addr = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            var v4 = new FWP_V4_ADDR_AND_MASK { addr = addr, mask = 0xFFFFFFFF };
            IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
            Marshal.StructureToPtr(v4, p, false);
            // Note: intentional leak for filter lifetime; cleaned when process exits.
            // Production hardening could track and free on filter delete.
            return new FWP_CONDITION_VALUE0
            {
                type = FWP_V4_ADDR_MASK,
                uint32 = 0,
                pointer = p,
            };
        }
        else
        {
            var bytes = address.GetAddressBytes();
            IntPtr p = Marshal.AllocHGlobal(16);
            Marshal.Copy(bytes, 0, p, Math.Min(16, bytes.Length));
            // Simplified: store pointer as byte array16 condition
            return new FWP_CONDITION_VALUE0
            {
                type = FWP_BYTE_ARRAY16_TYPE,
                uint32 = 0,
                pointer = p,
            };
        }
    }

    // --- P/Invoke (fwpuclnt.dll) ---

    private const uint RPC_C_AUTHN_WINNT = 10;
    private const ushort FWP_EMPTY = 0;
    private const ushort FWP_UINT32 = 4;
    private const ushort FWP_BYTE_ARRAY16_TYPE = 11;
    private const ushort FWP_V4_ADDR_MASK = 12;
    private const uint FWP_MATCH_EQUAL = 0;
    private const uint FWP_ACTION_BLOCK = 0x00001001 | 0x00000001; // FWP_ACTION_FLAG_TERMINATING | BLOCK

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_DISPLAY_DATA0
    {
        public IntPtr name;
        public IntPtr description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_VALUE0
    {
        public ushort type;
        public uint uint32; // simplified union
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] addr;
        public byte prefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_CONDITION_VALUE0
    {
        public ushort type;
        public uint uint32;
        public IntPtr pointer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, IntPtr subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);
}
