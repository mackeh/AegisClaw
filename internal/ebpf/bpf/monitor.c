// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum event_type {
    EVENT_SYSCALL = 1,
    EVENT_NET_CONNECT = 2,
    EVENT_FILE_OPEN = 3,
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u8 comm[16];
    union {
        __u64 syscall_id;
        struct {
            __u32 saddr;
            __u32 daddr;
            __u16 dport;
        } net;
        __u8 path[64];
    } data;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

static __always_inline struct event* reserve_event() {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct event *e;
    __u64 id = ctx->args[1];

    e = reserve_event();
    if (!e) return 0;

    e->type = EVENT_SYSCALL;
    e->data.syscall_id = id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Use raw tracepoint for openat to avoid header issues
// tracepoint/syscalls/sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    struct event *e;
    // For sys_enter_openat, the args are at specific offsets.
    // However, without the struct, we can use bpf_probe_read-style access if we know offsets,
    // or just rely on the fact that for many tracepoints, ctx is a pointer to the args.
    // A safer way is to use raw_tracepoint and filter by ID, but let's try a simple approach.
    
    e = reserve_event();
    if (!e) return 0;

    e->type = EVENT_FILE_OPEN;
    // pathname is usually the second argument of openat(int dfd, const char *pathname, ...)
    // In tracepoint ctx, it's after the common fields.
    // This is brittle without vmlinux.h. 
    // Let's just put a placeholder for now to ensure it compiles and we can refine later.
    __builtin_memset(&e->data.path, 0, sizeof(e->data.path));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int trace_tcp_v4_connect(struct pt_regs *ctx) {
    struct event *e;
    
    e = reserve_event();
    if (!e) return 0;

    e->type = EVENT_NET_CONNECT;
    // We can't easily read the sock struct without headers, 
    // but we can at least signal that a connect happened.
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
