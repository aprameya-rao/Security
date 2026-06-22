package pipeline

import (
	"context"
	"encoding/json"
	"log"

	"github.com/segmentio/kafka-go"
)

// Telemetry is the clean, JSON-friendly struct we will send to the Brain
type Telemetry struct {
	EventName string `json:"event_name"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	Command   string `json:"command"`
	Timestamp int64  `json:"timestamp"`
}

// KafkaProducer wraps the Kafka network writer
type KafkaProducer struct {
	writer *kafka.Writer
}

// NewKafkaProducer initializes the connection to VM 2
func NewKafkaProducer(brokerURL, topic string) *KafkaProducer {
	w := &kafka.Writer{
		Addr:     kafka.TCP(brokerURL),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
		
		// CRITICAL FOR SECURITY SENSORS:
		// Async=true means the sensor fires the packet and immediately goes back 
		// to listening. It does NOT wait for the network to respond. 
		// This prevents network lag from slowing down the host machine.
		Async: true, 
	}
	log.Printf("📡 Kafka Producer initialized, targeting broker: %s", brokerURL)
	return &KafkaProducer{writer: w}
}

// Publish converts the data to JSON and shoots it into the queue
func (kp *KafkaProducer) Publish(data Telemetry) {
	// 1. Convert the Go struct into a JSON byte array
	payload, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to format JSON: %v", err)
		return
	}

	// 2. Package it into a Kafka message
	msg := kafka.Message{
		Key:   []byte("sys_execve"), // Helps Kafka organize the data
		Value: payload,
	}

	// 3. Send it over the network
	err = kp.writer.WriteMessages(context.Background(), msg)
	if err != nil {
		log.Printf("Failed to write to Kafka: %v", err)
	}
}

// Close gracefully shuts down the network connection when the sensor stops
func (kp *KafkaProducer) Close() {
	kp.writer.Close()
}