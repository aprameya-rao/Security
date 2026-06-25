// Include standard Linux kernel types and eBPF helper functions
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_TYPE_EXEC 1

struct event {
    __u32 type;       // Event type identifier
    __u32 pid;        // Process ID
    __u32 uid;        // User ID (Who executed it?)
    char comm[16];    // Command/Process Name (max 16 chars in Linux)
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // Step A: Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; 
    }

    e->type = EVENT_TYPE_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    
    // --- THE FIX IS HERE ---
    // Instead of getting the current process name (bash), 
    // we read the 1st argument (args[0]) passed to execve, which is the filename!
    bpf_probe_read_user_str(&e->comm, sizeof(e->comm), (void *)ctx->args[0]);

    // Step C: Submit to the ring buffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";