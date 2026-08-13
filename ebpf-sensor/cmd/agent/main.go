package main

// Instruct the Go compiler to compile the C code and generate Go bindings.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/sensor.c -- -I../../bpf/headers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ebpf-sensor/pkg/config"
	"ebpf-sensor/pkg/pipeline"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// 1. The Payload Blueprint (Go Version)
// This MUST perfectly match the memory layout of the C struct in sensor.c
type Event struct {
	Type               uint32
	Pid                uint32
	Uid                uint32
	Comm               [16]byte
	Args               [256]byte
	Family             uint16
	DestinationPort    uint16
	DestinationAddress [16]byte
}

const (
	eventTypeExec    = 1
	eventTypeConnect = 2
)

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

	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		log.Fatalf("Failed to attach connect tracepoint: %v", err)
	}
	defer connectLink.Close()

	// 4. Open the Ring Buffer Reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	config.Load()
	kafkaBroker := config.Get("KAFKA_BROKER", "192.168.1.16:9092")
	kafkaTopic := config.Get("KAFKA_TOPIC", "xdr-telemetry")

	log.Printf("🛡️ eBPF Sensor successfully loaded! Listening for process executions...")
	log.Printf("📡 Publishing telemetry to Kafka broker: %s | topic: %s", kafkaBroker, kafkaTopic)

	producer := pipeline.NewKafkaProducer(kafkaBroker, kafkaTopic)
	defer producer.Close()

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

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			telemetry := pipeline.Telemetry{PID: event.Pid, UID: event.Uid, Command: comm, Timestamp: time.Now().UnixMilli()}
			switch event.Type {
			case eventTypeExec:
				telemetry.EventName = "execve"
				telemetry.Args = string(bytes.TrimRight(event.Args[:], "\x00"))
			case eventTypeConnect:
				telemetry.EventName = "connect"
				telemetry.DestinationIP = formatAddress(event.Family, event.DestinationAddress)
				telemetry.DestinationPort = event.DestinationPort
				telemetry.Protocol = "tcp"
			default:
				log.Printf("Ignoring unknown eBPF event type: %d", event.Type)
				continue
			}

			producer.Publish(telemetry)

			// We will keep the print statement just for lab visibility
			if telemetry.EventName == "connect" {
				log.Printf("[🌐 CONNECT] PID: %d | UID: %d | Command: %s | Destination: %s:%d", event.Pid, event.Uid, comm, telemetry.DestinationIP, telemetry.DestinationPort)
			} else {
				log.Printf("[🚨 EXEC] PID: %d | UID: %d | Command: %s | Args: %s", event.Pid, event.Uid, comm, telemetry.Args)
			}
		}
	}()

	// Keep the main function alive until we press Ctrl+C
	<-stopper
	log.Println("Received stop signal, detaching sensor...")
}

func formatAddress(family uint16, address [16]byte) string {
	if family == 2 {
		return net.IPv4(address[0], address[1], address[2], address[3]).String()
	}
	if family == 10 {
		return net.IP(address[:]).String()
	}
	return fmt.Sprintf("unknown-family-%d", family)
}
