// Include standard Linux kernel types and eBPF helper functions
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2
#define AF_INET 2
#define AF_INET6 10
#define MAX_ARGS 8
#define ARGS_SIZE 256

struct event {
    __u32 type;       // Event type identifier
    __u32 pid;        // Process ID
    __u32 uid;        // User ID (Who executed it?)
    char comm[16];    // Command/Process Name (max 16 chars in Linux)
    char args[ARGS_SIZE];
    __u16 family;
    __u16 destination_port;
    __u8 destination_address[16];
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
    
    bpf_probe_read_user_str(&e->comm, sizeof(e->comm), (void *)ctx->args[0]);

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg;
        int offset = i * 32;

        if (offset >= ARGS_SIZE - 1)
            break;
        if (bpf_probe_read_user(&arg, sizeof(arg), (void *)(ctx->args[1] + i * sizeof(arg))) < 0 || !arg)
            break;
        if (bpf_probe_read_user_str(&e->args[offset], ARGS_SIZE - offset, arg) < 0)
            break;
    }

    // Step C: Submit to the ring buffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    void *user_address = (void *)ctx->args[1];
    __u16 family;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (bpf_probe_read_user(&family, sizeof(family), user_address) < 0)
        goto discard;

    e->family = family;
    if (family == AF_INET) {
        struct sockaddr_in address4;
        if (bpf_probe_read_user(&address4, sizeof(address4), user_address) < 0)
            goto discard;
        __builtin_memcpy(e->destination_address, &address4.sin_addr, sizeof(address4.sin_addr));
        e->destination_port = address4.sin_port;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 address6;
        if (bpf_probe_read_user(&address6, sizeof(address6), user_address) < 0)
            goto discard;
        __builtin_memcpy(e->destination_address, &address6.sin6_addr, sizeof(address6.sin6_addr));
        e->destination_port = address6.sin6_port;
    } else {
        goto discard;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;

discard:
    bpf_ringbuf_discard(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
