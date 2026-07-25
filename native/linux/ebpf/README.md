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
with `LinuxProcessConnector` (cn_proc) — no capability loss, only reduced depth.

## Privileges

Prefer:

```
CapabilityBoundingSet=… CAP_BPF CAP_PERFMON …
```

Older kernels may still need `CAP_SYS_ADMIN` for some attach paths.
