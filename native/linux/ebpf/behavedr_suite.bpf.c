// Behavedr production eBPF suite (0.3.3)
// Event layout MUST match LinuxEbpfLoader.EventSize / field offsets:
//   kind u32 @0, pid u32 @4, tgid u32 @8, pad u32 @12,
//   comm[16] @16, path[112] @32  →  144 bytes total
//
// Programs:
//   tp/sched/sched_process_exec  → EV_EXEC  (kernel filename when available)
//   tp/syscalls/sys_enter_openat → EV_OPEN  (user pathname)
//   tp/syscalls/sys_enter_connect→ EV_CONNECT (AF_INET / AF_INET6 peer as text)
//
// Build on Linux (see README.md):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
//     -c behavedr_suite.bpf.c -o behavedr_exec.bpf.o
// Install:
//   sudo cp behavedr_exec.bpf.o /opt/behavedr/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_EXEC 1
#define EV_OPEN 2
#define EV_CONNECT 3
#define MAX_SLOTS 256
#define AF_INET 2
#define AF_INET6 10

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

/* Minimal wire layouts — avoid vmlinux sockaddr_* field-name variance. */
struct behavedr_sockaddr_hdr {
	__u16 family;
};

struct behavedr_sockaddr_in {
	__u16 family;
	__u16 port;   /* network order */
	__u32 addr;   /* network order */
};

/* Linux sockaddr_in6: family, port, flowinfo, addr[16], scope_id */
struct behavedr_sockaddr_in6 {
	__u16 family;
	__u16 port;
	__u32 flowinfo;
	__u8 addr[16];
};

/* ---- small decimal helpers (no libc in BPF) ---- */

static __always_inline int write_u32_dec(char *dst, int pos, int max, __u32 v)
{
	char tmp[10];
	int n = 0;

	if (pos >= max)
		return pos;
	if (v == 0) {
		if (pos < max)
			dst[pos++] = '0';
		return pos;
	}
	while (v > 0 && n < 10) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (n > 0 && pos < max)
		dst[pos++] = tmp[--n];
	return pos;
}

static __always_inline void format_ipv4_port(char *dst, int max, __u32 addr_be, __u16 port_be)
{
	__u32 a = bpf_ntohl(addr_be);
	__u16 p = bpf_ntohs(port_be);
	int pos = 0;

	__builtin_memset(dst, 0, max);
	pos = write_u32_dec(dst, pos, max - 1, (a >> 24) & 0xff);
	if (pos < max - 1)
		dst[pos++] = '.';
	pos = write_u32_dec(dst, pos, max - 1, (a >> 16) & 0xff);
	if (pos < max - 1)
		dst[pos++] = '.';
	pos = write_u32_dec(dst, pos, max - 1, (a >> 8) & 0xff);
	if (pos < max - 1)
		dst[pos++] = '.';
	pos = write_u32_dec(dst, pos, max - 1, a & 0xff);
	if (pos < max - 1)
		dst[pos++] = ':';
	write_u32_dec(dst, pos, max - 1, p);
}

static __always_inline void format_ipv6_port(char *dst, int max, const __u8 *addr, __u16 port_be)
{
	/* Compact: first 4 + last 4 bytes hex + port (fits path[112]) */
	static const char hex[] = "0123456789abcdef";
	__u16 p = bpf_ntohs(port_be);
	int i, pos = 0;

	__builtin_memset(dst, 0, max);
	if (pos < max - 1)
		dst[pos++] = '[';
	#pragma unroll
	for (i = 0; i < 4 && pos + 2 < max; i++) {
		dst[pos++] = hex[(addr[i] >> 4) & 0xf];
		dst[pos++] = hex[addr[i] & 0xf];
	}
	if (pos + 2 < max) {
		dst[pos++] = '.';
		dst[pos++] = '.';
	}
	#pragma unroll
	for (i = 12; i < 16 && pos + 2 < max; i++) {
		dst[pos++] = hex[(addr[i] >> 4) & 0xf];
		dst[pos++] = hex[addr[i] & 0xf];
	}
	if (pos < max - 1)
		dst[pos++] = ']';
	if (pos < max - 1)
		dst[pos++] = ':';
	write_u32_dec(dst, pos, max - 1, p);
}

static __always_inline void push_event(__u32 kind, const char *path_src, int path_is_user)
{
	__u32 zero = 0;
	__u32 *idxp = bpf_map_lookup_elem(&cursor, &zero);
	__u32 idx = idxp ? *idxp : 0;
	struct behavedr_event ev = {};
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 slot, next;

	ev.kind = kind;
	ev.pid = (__u32)pt;
	ev.tgid = (__u32)(pt >> 32);
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

	if (path_src) {
		if (path_is_user)
			bpf_probe_read_user_str(&ev.path, sizeof(ev.path), path_src);
		else
			bpf_probe_read_kernel_str(&ev.path, sizeof(ev.path), path_src);
	}

	slot = idx % MAX_SLOTS;
	next = idx + 1;
	bpf_map_update_elem(&events, &slot, &ev, BPF_ANY);
	bpf_map_update_elem(&cursor, &zero, &next, BPF_ANY);
}

static __always_inline void push_event_path_copy(__u32 kind, const char *path_stack, int path_len)
{
	__u32 zero = 0;
	__u32 *idxp = bpf_map_lookup_elem(&cursor, &zero);
	__u32 idx = idxp ? *idxp : 0;
	struct behavedr_event ev = {};
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 slot, next;
	int n = path_len;

	ev.kind = kind;
	ev.pid = (__u32)pt;
	ev.tgid = (__u32)(pt >> 32);
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
	if (n > (int)sizeof(ev.path) - 1)
		n = (int)sizeof(ev.path) - 1;
	if (n > 0)
		__builtin_memcpy(ev.path, path_stack, n);

	slot = idx % MAX_SLOTS;
	next = idx + 1;
	bpf_map_update_elem(&events, &slot, &ev, BPF_ANY);
	bpf_map_update_elem(&cursor, &zero, &next, BPF_ANY);
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	/*
	 * __data_loc_filename: low 16 bits = byte offset from start of ctx.
	 * Filename lives in the tracepoint dynamic payload (kernel address).
	 */
	unsigned int data_loc = 0;
	char *filename = NULL;

	data_loc = BPF_CORE_READ(ctx, __data_loc_filename);
	if (data_loc) {
		filename = (char *)ctx + (data_loc & 0xffff);
		push_event(EV_EXEC, filename, /*path_is_user=*/0);
	} else {
		push_event(EV_EXEC, NULL, 0);
	}
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];

	push_event(EV_OPEN, filename, /*path_is_user=*/1);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	const void *usa = (const void *)ctx->args[1];
	struct behavedr_sockaddr_hdr hdr = {};
	char path[112] = {};

	if (!usa)
		goto emit;

	if (bpf_probe_read_user(&hdr, sizeof(hdr), usa) < 0)
		goto emit;

	if (hdr.family == AF_INET) {
		struct behavedr_sockaddr_in sin = {};

		if (bpf_probe_read_user(&sin, sizeof(sin), usa) == 0)
			format_ipv4_port(path, sizeof(path), sin.addr, sin.port);
	} else if (hdr.family == AF_INET6) {
		struct behavedr_sockaddr_in6 sin6 = {};

		if (bpf_probe_read_user(&sin6, sizeof(sin6), usa) == 0)
			format_ipv6_port(path, sizeof(path), sin6.addr, sin6.port);
	}

emit:
	push_event_path_copy(EV_CONNECT, path, 112);
	return 0;
}
