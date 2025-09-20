// Minimal eBPF program skeleton for TCP connect events
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/inet.h>

struct net_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct net_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // simplified for illustration
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
