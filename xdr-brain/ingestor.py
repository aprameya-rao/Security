import json
import logging
from confluent_kafka import Consumer,Producer, KafkaException
import clickhouse_connect
from datetime import datetime
from engine import enricher


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Ingestor")

# Storage Client
client = clickhouse_connect.get_client(
    host='localhost', 
    port=8123, 
    username='default', 
    password='admin'  # <--- ADD THIS
)

# Consumer Configuration
consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'pipeline-worker',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': True
})

producer = Producer({
    'bootstrap.servers': 'localhost:9092'
})


def process_message(msg):
    """
    Handles the incoming telemetry packet.
    """
    try:
        data = json.loads(msg.value().decode('utf-8'))
        enriched_data = enricher.enrich_event(data)
    
        # Prepare datetime
        ts_float = enriched_data.get('timestamp', 0) / 1000
        dt_object = datetime.fromtimestamp(ts_float)

        # Insert enriched data
        client.insert('security_logs.execve_events', [(
            dt_object, 
            enriched_data.get('event_name', 'unknown'), 
            enriched_data.get('pid', 0), 
            enriched_data.get('uid', 0), 
            enriched_data.get('command', 'unknown'),
            # Add new columns to your table schema!
            enriched_data.get('is_root', False),
            enriched_data.get('is_suspicious', False),
            enriched_data.get('is_tmp_execution', False),
            enriched_data.get('is_known_threat', False)
        )])
        
        if enriched_data.get('is_known_threat'):
            kill_payload = {
                "pid": int(enriched_data.get('pid', 0)),
                "command": enriched_data.get('command', 'unknown'),
                "is_known_threat": True
            }
            # Send the order using confluent_kafka's .produce() method
            producer.produce('kill_commands', value=json.dumps(kill_payload).encode('utf-8'))
            producer.flush() # Force it to send immediately
            print(f"🔫 ASSASSINATION ORDER SENT FOR PID: {kill_payload['pid']} ({kill_payload['command']})")
        
        logger.info(f"Ingested: {data.get('command', 'unknown')}")
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON message")
    except Exception as e:
        logger.error(f"Error inserting into ClickHouse: {e}")

# Subscribe and Start Listening
try:
    consumer.subscribe(['xdr-telemetry'])
    logger.info("🚀 Event-Driven Ingestor Active: Kafka -> ClickHouse")
    
    while True:
        # poll(timeout) is the event-driven entry point
        msg = consumer.poll(timeout=1.0)
        
        if msg is None: continue
        if msg.error():
            if msg.error().code() == -191: # _PARTITION_EOF
                continue
            else:
                raise KafkaException(msg.error())
        
        # Trigger the event handler
        process_message(msg)

except KeyboardInterrupt:
    logger.info("Shutting down...")
finally:
    consumer.close()
