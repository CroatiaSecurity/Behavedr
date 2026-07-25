# Platform ABI constants — sources of truth

**Policy:** do not invent ETW flags, Linux syscall numbers, or ES event IDs.
Cite kernel headers / Microsoft docs. Last verified: **2026-07-25**.

## Linux syscalls

Central code: `src/Behavedr.Core/Platform/LinuxSyscallNumbers.cs`

| Symbol | x86_64 | arm64 / generic | Source |
|--------|--------|-----------------|--------|
| `bpf` | **321** | **280** | `arch/x86/entry/syscalls/syscall_64.tbl`; `include/uapi/asm-generic/unistd.h` |
| `pidfd_send_signal` | **424** | **424** | same tables |
| `pidfd_open` | **434** | **434** | same tables |
| `landlock_create_ruleset` | **444** | **444** | same tables |
| `landlock_add_rule` | **445** | **445** | same tables |
| `landlock_restrict_self` | **446** | **446** | same tables |

bpf commands (`uapi/linux/bpf.h`): `BPF_MAP_LOOKUP_ELEM = 1`, `BPF_OBJ_GET = 7`.

Unsupported architectures return `-1` (soft-fail) — **no silent wrong number**.

## Windows ETW

| Constant | Value | Source |
|----------|-------|--------|
| `EVENT_TRACE_REAL_TIME_MODE` | `0x00000100` | [Logging Mode Constants](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants) |
| `EVENT_TRACE_FLAG_PROCESS` | `0x00000001` | [EVENT_TRACE_PROPERTIES / EnableFlags](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties) |
| Kernel-Process **ProcessStart** | Event ID **1** | Provider manifest `Microsoft-Windows-Kernel-Process` |

## macOS EndpointSecurity

Prefer **framework enums** in C (`behavedr_es_subscribe_default`) over hardcoded
managed integers. Apple enum order (10.15+): `AUTH_EXEC=0`, …, `NOTIFY_EXEC=9`,
`NOTIFY_OPEN=10`, `NOTIFY_FORK=11`, … (see SDK `ESTypes.h`).

## How to re-verify

```bash
# Syscalls
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl | grep -E 'bpf|pidfd|landlock'
curl -sL https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h | grep -E 'NR_bpf|NR_pidfd|NR_landlock'
```
