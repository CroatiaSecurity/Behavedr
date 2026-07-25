# Behavedr Linux eBPF (exec trace)

## Build

```bash
# Dependencies: clang, llvm, libbpf-dev, linux-headers / vmlinux.h (bpftool gen)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c exec_trace.bpf.c -o behavedr_exec.bpf.o
cp behavedr_exec.bpf.o /opt/behavedr/
```

## Runtime

`LinuxEbpfExecMonitor` looks for `behavedr_exec.bpf.o` beside the agent binary or in
`/opt/behavedr/`. When load/attach succeeds, exec events come from the eBPF ring buffer.
When eBPF is unavailable (no CAP_BPF, old kernel, missing object), the agent continues
with `LinuxProcessConnector` (cn_proc) â€” no capability loss, only reduced depth.

## Privileges

Prefer:

```
CapabilityBoundingSet=â€¦ CAP_BPF CAP_PERFMON â€¦
```

Older kernels may still need `CAP_SYS_ADMIN` for some attach paths.
// Additional attach points (build separate or multi-section object):
//   tp/syscalls/sys_enter_openat  — file opens (needs larger event struct)
//   tp/syscalls/sys_enter_connect — outbound connects
// Managed monitors LinuxEbpfFileMonitor / LinuxEbpfNetMonitor provide depth
// until these sections are linked into behavedr_exec.bpf.o.
