// Behavedr eBPF: sched_process_exec → ring buffer of {pid, tgid, comm}
// Build on Linux (clang + libbpf):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c exec_trace.bpf.c -o behavedr_exec.bpf.o
// The managed LinuxEbpfExecMonitor loads the object when present next to the agent,
// and falls back to cn_proc when eBPF is unavailable.
//
// Requires: CAP_BPF / CAP_PERFMON (or CAP_SYS_ADMIN on older kernels), BTF optional for CO-RE.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct exec_event {
    __u32 pid;
    __u32 tgid;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *e;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* filename may not be available on all kernels via this TP; zero if missing */
    __builtin_memset(e->filename, 0, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
