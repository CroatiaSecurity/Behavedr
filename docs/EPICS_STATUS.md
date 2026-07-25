# Platform epics — honest status (0.3.3)

This document is the source of truth for what is **production code** vs what still needs
**host privileges / vendor enrollment**. No marketing.

## Summary

| Epic | Production code | Auto-on without extras | Field activation |
|------|-----------------|------------------------|------------------|
| Windows isolation | **Yes** — Firewall COM + WFP + netsh | **Yes** (SYSTEM) | Elevation (service) |
| Linux eBPF suite | **Yes** — suite BPF C + pin/map loader + shared suite | **No** | `.o` + bpftool + CAP_BPF |
| macOS EndpointSecurity | **Yes** — ring-buffer bridge + poll ABI | **No** | dylib + ES entitlement |
| macOS System Extension | **Yes** — ES host + JSONL publisher + build | **No** | Apple capability + approve |
| Android Play Integrity | **Yes** — reflection + fail-closed + opt-in NuGet | Soft | Cloud project / package |
| iOS full EDR | **No** (Apple policy) | Companion only | MDM + NE product SKU |
| Kernel callout / rootkit win | **No** | N/A | Out of scope (userland EDR) |
| OS Authenticode/notarize | Hooks only | No | Paid certs |

## What 0.3.3 fixed (proper, not scaffold)

### Linux eBPF
- Object: `native/linux/ebpf/behavedr_suite.bpf.c`
  - exec with kernel filename, openat user path, connect with peer `ip:port`
  - fixed 144-byte layout matching C#
- Loader: `LinuxEbpfLoader`
  - `bpftool prog loadall` with autoattach/pinmaps fallbacks
  - **`bpf(BPF_OBJ_GET)`** + **`BPF_MAP_LOOKUP_ELEM`**
  - cursor seeding (no stale flood); x64/arm64 syscall numbers
- Shared session: `LinuxEbpfSuite` — one load, one poller; exec/file/net drain by kind
- Monitors:
  - `LinuxEbpfExecMonitor` — suite EV_EXEC only
  - `LinuxEbpfFileMonitor` — suite EV_OPEN, else `/proc/*/fd` sample
  - `LinuxEbpfNetMonitor` — suite EV_CONNECT, else `/proc/net/*`
- Fallback remains **cn_proc / fanotify** when object/caps missing

### macOS EndpointSecurity
- Bridge: fixed **SPSC ring**, acquire/release atomics, `behavedr_es_poll`,
  AUTH only denies when `behavedr_es_set_auth_mode(1)` + denylist, stats export
- Managed monitor polls native ring (no GC callback from ES)
- System Extension host (`main.m`): real ES client, AUTH path, JSONL to
  `/var/run/behavedr/es.events`, publisher thread, version 0.3.3 bundle metadata

### Windows isolation
- **Primary:** `WindowsFirewallEngine` (HNetCfg.FwPolicy2 COM) — IP in/out + app block
- **Secondary:** `WindowsWfpEngine` dual-layer ALE (V4/V6), tracked native condition memory
- **Tertiary:** netsh
- Metrics on all success paths

## How to activate (operators)

```bash
# Linux
./native/build-native.sh dist/native          # on a Linux build host
sudo cp dist/native/behavedr_exec.bpf.o /opt/behavedr/
# ensure CAP_BPF CAP_PERFMON in systemd unit (already in packaging/unix/behavedr.service)

# macOS
./native/build-native.sh                      # on macOS
sudo cp dist/native/libbehavedr_es.dylib /opt/behavedr/
# sign agent with com.apple.developer.endpoint-security.client
# optional: BEHAVEDR_ES_AUTH=1 for conservative AUTH denylist
# optional: native/macos/SystemExtension/build.sh for SE packaging
# SE events: /var/run/behavedr/es.events (JSONL)
```

## What we will not claim

- That eBPF is active on every Linux install without the object file  
- That ES is active without Apple entitlement  
- That iOS is full EDR  
- That WFP callout drivers ship in this repo  
- That System Extension is “App Store ready” without Apple enrollment + notarization  

If a path is not field-active, the agent **soft-fails** and keeps older real-time sources.
