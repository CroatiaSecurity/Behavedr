# Behavedr Linux eBPF (production suite, 0.3.2)

## Object

Primary object name expected by the agent: **`behavedr_exec.bpf.o`**  
(built from `behavedr_suite.bpf.c` — exec + openat + connect → array map `events`)

## Build

```bash
# Root of repo
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-headers-$(uname -r)  # example
bpftool btf dump file /sys/kernel/btf/vmlinux format c > native/linux/ebpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I native/linux/ebpf \
  -c native/linux/ebpf/behavedr_suite.bpf.c \
  -o native/linux/ebpf/behavedr_exec.bpf.o
sudo mkdir -p /opt/behavedr
sudo cp native/linux/ebpf/behavedr_exec.bpf.o /opt/behavedr/
```

Or: `./native/build-native.sh dist/native`

## Runtime

`LinuxEbpfExecMonitor` + `LinuxEbpfLoader`:

1. Finds `behavedr_exec.bpf.o` beside agent or `/opt/behavedr/`
2. `bpftool prog loadall` into `/sys/fs/bpf/behavedr`
3. Attaches sched_process_exec / openat / connect
4. Polls `bpftool map dump` of `events`

Without object or CAP_BPF: soft-fail → **cn_proc** remains primary.

## Capabilities

```
CapabilityBoundingSet=… CAP_BPF CAP_PERFMON CAP_SYS_ADMIN …
```

## Additional attach points (future object versions)

Managed monitors `LinuxEbpfFileMonitor` / `LinuxEbpfNetMonitor` provide depth even when
only exec is attached; suite object covers all three when load succeeds.
