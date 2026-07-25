# Behavedr Operator Guide

**Version:** 0.2.8  

## Response modes

| Mode | Config | Behavior |
|------|--------|----------|
| **AlertOnly** (default) | `Response:Mode = AlertOnly` | Score, log, report — **no** kill/quarantine/isolate |
| **Active** | `Response:Mode = Active` | Executes registered response actions at thresholds |

Leave AlertOnly until you have baselined false positives for the environment.

### Thresholds

| Setting | Default | Meaning |
|---------|---------|---------|
| `AlertThreshold` | 50 | Log / report |
| `ResponseThreshold` | 75 | Isolation / quarantine class actions |
| President-kill | scoring config | Process kill class (desktop) |
| `MaxKillsPerMinute` | 15 | Kill-storm budget |

## Platform activation (0.2.8–0.2.8 depth)

| Feature | Enable |
|---------|--------|
| Windows WFP isolate | Run as SYSTEM; automatic when Active |
| Linux eBPF exec | `CAP_BPF`/`CAP_PERFMON` + optional `behavedr_exec.bpf.o` in `/opt/behavedr/` |
| macOS EndpointSecurity | `libbehavedr_es.dylib` + ES entitlement; `BEHAVEDR_ES_AUTH=1` for optional AUTH deny list |
| Android Play Integrity fail-closed | `BEHAVEDR_REQUIRE_PLAY_INTEGRITY=1` or non-zero cloud project number |
| Android VPN isolate | Active response + VPN permission / service running |
| iOS companion | MDM + optional Network Extension; local quarantine only in-app |

## Legal / safety

Active response can terminate processes and isolate network paths. Confirm authority and change control before enabling. Default AlertOnly exists for this reason.

## Audit trail

Response outcomes append to `logs/response-audit.jsonl` (HMAC when machine key available).
