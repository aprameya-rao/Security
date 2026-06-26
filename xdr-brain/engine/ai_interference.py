import json
import torch
import joblib
import numpy as np
import warnings
from kafka import KafkaConsumer,KafkaProducer
from autoencoder import ZeroDayAutoencoder, device

warnings.filterwarnings('ignore')
print("[*] Waking up the AI Brain...")

cmd_encoder = joblib.load('engine/cmd_encoder.pkl')
args_vectorizer = joblib.load('engine/args_vectorizer.pkl')
scaler = joblib.load('engine/scaler.pkl')

model = ZeroDayAutoencoder(input_dim=3).to(device)
model.load_state_dict(torch.load('engine/models/autoencoder.pt', map_location=device))
model.eval()

consumer = KafkaConsumer(
    'xdr-telemetry',
    bootstrap_servers=['localhost:9092'],
    group_id='ai-brain-group',
    auto_offset_reset='latest'
)

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# With the math fixed, normal commands will score 0.1 to 1.0. 
# Anything above 2.0 is an anomaly!
ANOMALY_THRESHOLD = 15.0 

print(f"[+] AI Brain Online. Hardware: {device.type.upper()}")
print(f"[+] Listening to live eBPF stream...\n")

for message in consumer:
    try:
        event = json.loads(message.value.decode('utf-8'))
    except Exception:
        continue 

    uid = event.get('uid', 1000)
    raw_cmd = event.get('command', 'unknown').strip().replace('\x00', '')
    args_str = 'none' 

    try:
        encoded_cmd = cmd_encoder.transform([raw_cmd])[0]
    except ValueError:
        encoded_cmd = 9999 # Unseen command gets the massive penalty

    encoded_args = args_vectorizer.transform([args_str]).toarray()[0]
    
    # THE FIX: Apply the same strict mathematical scaling
    raw_numerical = np.array([[uid, encoded_cmd]])
    scaled_numerical = scaler.transform(raw_numerical)[0]

    feature_vector = np.hstack((scaled_numerical, encoded_args))
    tensor_data = torch.FloatTensor(feature_vector).unsqueeze(0).to(device)

    with torch.no_grad():
        reconstructed = model(tensor_data)
        loss = torch.nn.functional.mse_loss(reconstructed, tensor_data).item()

    if loss > ANOMALY_THRESHOLD:
        print(f"[🚨 ZERO-DAY DETECTED] Killing PID: {event.get('pid')}...")

        # This sends the order to the Rust Responder!
        producer.send('kill_commands', {
            'pid': event.get('pid'),
            'command': raw_cmd,
            'is_known_threat': True
        })
    else:
        print(f"[✅ NORMAL] Score: {loss:.2f} | Command: {raw_cmd}")
