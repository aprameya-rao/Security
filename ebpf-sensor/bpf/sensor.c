// Include standard Linux kernel types and eBPF helper functions
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define our event types so the Go application knows what it is reading
#define EVENT_TYPE_EXEC 1

// -----------------------------------------------------------------------------
// 1. The Data Structure (The Payload)
// This must perfectly match the struct we will eventually write in Go.
// -----------------------------------------------------------------------------
struct event {
    __u32 type;       // Event type identifier
    __u32 pid;        // Process ID
    __u32 uid;        // User ID (Who executed it?)
    char comm[16];    // Command/Process Name (max 16 chars in Linux)
};

// -----------------------------------------------------------------------------
// 2. The BPF Map (The Ring Buffer)
// This is the memory bridge between the kernel and user space.
// -----------------------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // Allocate a 256 KB memory buffer
} events SEC(".maps");

// -----------------------------------------------------------------------------
// 3. The Hook (The Tracepoint)
// We are attaching this function to the exact moment 'execve' is called.
// -----------------------------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // Step A: Reserve space in the ring buffer for our event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // If the buffer is full (system is under heavy load), drop the event safely
        return 0; 
    }

    // Step B: Gather the telemetry from the kernel
    e->type = EVENT_TYPE_EXEC;
    
    // bpf_get_current_pid_tgid() returns a 64-bit integer. 
    // The top 32 bits are the PID, the bottom 32 are the Thread ID. 
    // We bit-shift by 32 to extract just the PID.
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    // Extract the User ID
    e->uid = bpf_get_current_uid_gid();
    
    // Extract the name of the process that made the call (e.g., "bash", "python3")
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Step C: Submit the populated struct to the ring buffer for Go to read
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// eBPF programs MUST be licensed under GPL to access certain kernel helper functions
char LICENSE[] SEC("license") = "GPL";