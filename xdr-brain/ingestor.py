import json
import logging
from confluent_kafka import Consumer, KafkaException
import clickhouse_connect

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Ingestor")

# Storage Client
client = clickhouse_connect.get_client(host='localhost', port=8123, username='default')

# Consumer Configuration
consumer = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'pipeline-worker',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': True
})

def process_message(msg):
    """
    Handles the incoming telemetry packet.
    """
    try:
        data = json.loads(msg.value().decode('utf-8'))
        
        # Insert raw telemetry into ClickHouse
        # We perform NO filtering here to maintain 100% data fidelity for AI training
        client.insert('security_logs.execve_events', [(
            data.get('timestamp', 0) / 1000, 
            data.get('event_name', 'unknown'), 
            data.get('pid', 0), 
            data.get('uid', 0), 
            data.get('command', 'unknown')
        )])
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