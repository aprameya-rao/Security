import json
from confluent_kafka import Consumer, KafkaError

# 1. Configure the Kafka Consumer
settings = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'xdr-python-pipeline', # Identifies this script to Kafka
    'auto.offset.reset': 'latest'      # Only read new logs, ignore old ones
}

consumer = Consumer(settings)
consumer.subscribe(['xdr-telemetry'])

print("🧠 Python Brain is online. Listening for telemetry...")

# 2. The Infinite Listening Loop
try:
    while True:
        # Wait for a message
        msg = consumer.poll(1.0)

        if msg is None:
            continue
        if msg.error():
            print(f"Consumer error: {msg.error()}")
            continue

        # 3. Decode the JSON packet
        try:
            raw_data = msg.value().decode('utf-8')
            telemetry = json.loads(raw_data)
            
            pid = telemetry.get('pid')
            command = telemetry.get('command')
            
            # --- FILTERING LOGIC GOES HERE ---
            # For now, we just print everything
            print(f"[INGESTED] PID: {pid} | Command: {command}")
            
        except json.JSONDecodeError:
            print("Received malformed JSON")

except KeyboardInterrupt:
    print("\nShutting down pipeline...")
finally:
    consumer.close()
