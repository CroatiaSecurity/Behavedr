// Behavedr production eBPF suite (0.3.2)
// Programs: exec, openat, connect → shared array map of recent events.
// Array maps are dumpable via bpftool without a ringbuf consumer.
//
// Build (Linux):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c behavedr_suite.bpf.c -o behavedr_exec.bpf.o
// Install: /opt/behavedr/behavedr_exec.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_EXEC 1
#define EV_OPEN 2
#define EV_CONNECT 3
#define MAX_SLOTS 256

struct behavedr_event {
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 pad;
    char comm[16];
    char path[112];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, struct behavedr_event);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cursor SEC(".maps");

static __always_inline void push_event(__u32 kind, char *path_buf)
{
    __u32 zero = 0;
    __u32 *idxp = bpf_map_lookup_elem(&cursor, &zero);
    __u32 idx = 0;
    if (idxp)
        idx = *idxp;

    struct behavedr_event ev = {};
    __u64 pt = bpf_get_current_pid_tgid();
    ev.kind = kind;
    ev.pid = (__u32)pt;
    ev.tgid = (__u32)(pt >> 32);
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    if (path_buf)
        __builtin_memcpy(&ev.path, path_buf, sizeof(ev.path));

    __u32 slot = idx % MAX_SLOTS;
    bpf_map_update_elem(&events, &slot, &ev, BPF_ANY);

    __u32 next = idx + 1;
    bpf_map_update_elem(&cursor, &zero, &next, BPF_ANY);
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    (void)ctx;
    push_event(EV_EXEC, NULL);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    char buf[112] = {};
    const char *filename = (const char *)ctx->args[1];
    if (filename)
        bpf_probe_read_user_str(buf, sizeof(buf), filename);
    push_event(EV_OPEN, buf);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    push_event(EV_CONNECT, NULL);
    return 0;
}
