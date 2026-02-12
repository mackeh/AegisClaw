// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
    __u32 pid;
    __u32 tid;
    __u8 comm[16];
    __u64 syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct event *e;
    __u64 id = ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->syscall_id = id;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
