# Platform epics — honest status (0.3.8)

Source of truth for **production code** vs **field activation**. No marketing.

## Summary

| Epic | Production code | Auto-on without extras | Field activation |
|------|-----------------|------------------------|------------------|
| Windows isolation | **Yes** — Firewall COM + WFP + netsh + safety rails | **Yes** (SYSTEM) | Elevation (service) |
| Linux eBPF suite | **Yes** — filtered suite + pin/map loader | **No** | `.o` + bpftool + CAP_BPF + unit allows bpffs |
| macOS EndpointSecurity (in-process) | **Yes** — dylib poll + framework subscribe | **No** | dylib + ES entitlement |
| macOS ES host → agent | **Yes** — JSONL fallback reader in agent | **No** | host publishing events |
| macOS System Extension *product* | **Partial** — host binary + bundle shell | **No** | Apple SE capability, OSSystemExtensionRequest, notarize, user approve |
| Android cert pin + CI sign | **Yes** — real release pin + GH secrets auto-sign | Soft | Release workflow with keystore secrets (configured) |
| Android Play Integrity | **Yes** — reflection + fail-closed + opt-in NuGet | Soft | Cloud project / package |
| Response safety / anti-bypass | **Yes** — `ResponseSafety` + `ThreatHeuristics` (0.3.6) | **Yes** | Always on |
| iOS full EDR | **No** (Apple policy) | Companion only | MDM + NE product SKU |
| Kernel callout / rootkit win | **No** | N/A | Out of scope (userland EDR) |
| OS Authenticode/notarize | Hooks only | No | Paid certs |

## What 0.3.8 added

- Primary monitors (cn_proc, kqueue, Windows/Linux/macOS poll monitors) use path-aware `ThreatHeuristics`
- Android response uses shared safety rails + own-package protection

## What 0.3.7 added (kept)

- fanotify / cn_proc ABI documented from kernel uapi (no guessed flags)
- Linux isolation never UID-blocks the agent user; fanotify never denies agent install path  
- Fanotify + eBPF/ES continue rename-aware `ThreatHeuristics`

## What 0.3.6 added

- **ResponseSafety**: no self-kill, no agent quarantine/net-block, no spoofed system-name immunity under Temp  
- **ThreatHeuristics**: rename-aware scoring (staging path > tool name alone)  
- AUTH denylist: staging paths only; never deny `/opt/behavedr/`  
- Policy caps against kill-storm signed policies  

## What 0.3.5 added

- deb/rpm can ship eBPF object; Recommends bpftool  
- Agent consumes SE host JSONL when in-process ES fails  
- Android release keystore pin + CI auto-sign secrets  

## Field activation (operators)

```bash
# Linux eBPF
./native/build-native.sh dist/native
sudo cp dist/native/behavedr_exec.bpf.o /opt/behavedr/
sudo systemctl restart behavedr

# macOS ES (in-process)
sudo cp dist/native/libbehavedr_es.dylib /opt/behavedr/
# sign agent with com.apple.developer.endpoint-security.client

# Android release
# Secrets ANDROID_KEYSTORE_* already used by release.yml when set
```

## What we will not claim

- eBPF/ES active without host artifacts/entitlements  
- Full System Extension product  
- iOS full EDR  
- That name-based detection alone stops renamed tools (we use path/behavior for that)  
- That userland EDR stops kernel rootkits  

If a path is not field-active, the agent **soft-fails** and keeps older real-time sources.
