# Platform epics — honest status (0.3.5)

Source of truth for **production code** vs **field activation**. No marketing.

## Summary

| Epic | Production code | Auto-on without extras | Field activation |
|------|-----------------|------------------------|------------------|
| Windows isolation | **Yes** — Firewall COM + WFP + netsh | **Yes** (SYSTEM) | Elevation (service) |
| Linux eBPF suite | **Yes** — filtered suite + pin/map loader | **No** | `.o` + bpftool + CAP_BPF + unit allows bpffs |
| macOS EndpointSecurity (in-process) | **Yes** — dylib poll + framework subscribe | **No** | dylib + ES entitlement |
| macOS ES host → agent | **Yes** — JSONL fallback reader in agent | **No** | host publishing events |
| macOS System Extension *product* | **Partial** — host binary + bundle shell | **No** | Apple SE capability, OSSystemExtensionRequest, notarize, user approve |
| Android cert pin | **Yes** — fail-closed when unconfigured | Soft | `BEHAVEDR_ANDROID_CERT_SHA256` |
| Android Play Integrity | **Yes** — reflection + fail-closed + opt-in NuGet | Soft | Cloud project / package |
| iOS full EDR | **No** (Apple policy) | Companion only | MDM + NE product SKU |
| Kernel callout / rootkit win | **No** | N/A | Out of scope (userland EDR) |
| OS Authenticode/notarize | Hooks only | No | Paid certs |

## What 0.3.5 added

- deb/rpm can ship eBPF object; Recommends bpftool  
- Agent consumes SE host JSONL when in-process ES fails  
- Android no longer treats PLACEHOLDER fingerprints as trusted  

## What 0.3.4 fixed (audit)

### Linux eBPF
- systemd no longer blocks bpffs pin (`RestrictFileSystems=… bpf`, pin path RW)
- Atomic cursor; openat limited to sensitive paths; connect INET-only
- Cursor map required for active mode
- TGID as process id; quieter signals

### macOS ES
- `behavedr_es_subscribe_default` uses framework enums (fixed wrong managed IDs)
- AUTH_OPEN flags API; ring drop-newest (SPSC-safe)
- SE tree is an **ES host binary** + packaging shell — not a complete SE product

### Windows
- IPv6 peer extraction for isolation

## How to activate (operators)

```bash
# Linux
./native/build-native.sh dist/native
sudo cp dist/native/behavedr_exec.bpf.o /opt/behavedr/
# unit already grants CAP_BPF and bpffs write (0.3.4+)
sudo systemctl restart behavedr

# macOS (in-process agent)
./native/build-native.sh
sudo cp dist/native/libbehavedr_es.dylib /opt/behavedr/
# sign agent with com.apple.developer.endpoint-security.client
# optional AUTH_EXEC denylist: BEHAVEDR_ES_AUTH=1

# macOS ES host (optional, not auto-wired into agent)
native/macos/SystemExtension/build.sh
# run elevated; events → /var/run/behavedr/es.events
# full System Extension install is release-engineering + Apple enrollment
```

## What we will not claim

- That eBPF is active without the object file / bpftool / working pin path  
- That ES is active without Apple entitlement  
- That the System Extension folder is an App Store / MDM-ready SE product  
- That agent currently consumes SE JSONL (future XPC/reader)  
- That iOS is full EDR  
- That WFP callout drivers ship in this repo  

If a path is not field-active, the agent **soft-fails** and keeps older real-time sources.
