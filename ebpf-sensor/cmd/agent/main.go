package main

// Instruct the Go compiler to compile the C code and generate Go bindings.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/sensor.c -- -I../../bpf/headers

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// 1. The Payload Blueprint (Go Version)
// This MUST perfectly match the memory layout of the C struct in sensor.c
type Event struct {
	Type uint32
	Pid  uint32
	Uid  uint32
	Comm [16]byte
}

func main() {
	// Listen for standard termination signals (like Ctrl+C) to exit cleanly
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 2. Load the compiled eBPF bytecode into the Kernel
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close() // Ensure we clean up kernel memory when the program exits

	// 3. Attach the program to the 'execve' tracepoint
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer kp.Close()

	// 4. Open the Ring Buffer Reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	log.Println("🛡️ eBPF Sensor successfully loaded! Listening for process executions...")

	// 5. The Extraction Loop
	go func() {
		var event Event
		for {
			// Read the raw binary data off the conveyor belt
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// Parse the raw C binary into our structured Go variable
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to parse ringbuf event: %v", err)
				continue
			}

			// Clean up the C-string (remove null terminators)
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			log.Printf("[🚨 EXEC] PID: %d | UID: %d | Command: %s", event.Pid, event.Uid, comm)
		}
	}()

	// Keep the main function alive until we press Ctrl+C
	<-stopper
	log.Println("Received stop signal, detaching sensor...")
}