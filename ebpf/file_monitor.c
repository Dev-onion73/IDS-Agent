// Minimal eBPF program skeleton (BCC/libbpf can be used in Python)
// Hooks into syscalls like openat/unlink for file monitoring
#include <uapi/linux/ptrace.h>

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, int mode) {
    struct file_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.filename, sizeof(event.filename), filename);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
