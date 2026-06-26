import json
import torch
import joblib
import numpy as np
from kafka import KafkaConsumer
from autoencoder import ZeroDayAutoencoder, device

print("[*] Waking up the AI Brain...")

# 1. Load the Preprocessors (The Translators)
try:
    cmd_encoder = joblib.load('engine/cmd_encoder.pkl')
    args_vectorizer = joblib.load('engine/args_vectorizer.pkl')
    scaler = joblib.load('engine/scaler.pkl')
except Exception as e:
    print(f"[!] Critical Error: Missing preprocessors. Did you run feature_extractor.py? {e}")
    exit(1)

# 2. Load the Trained Neural Network
# We use 3 input dimensions because that is what our extractor currently outputs
model = ZeroDayAutoencoder(input_dim=3).to(device)
model.load_state_dict(torch.load('engine/models/autoencoder.pt', map_location=device))
model.eval() # Set to evaluation mode (no more training)

# 3. Connect to the Live Kafka Stream
consumer = KafkaConsumer(
    'edr-telemetry', # Change this if your Kafka topic is named differently!
    bootstrap_servers=['localhost:9092'],
    auto_offset_reset='latest',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

# 4. Set the Sensitivity Threshold
# Based on your training, normal loss was around 38.6. 
# Anything significantly higher than this is an anomaly.
ANOMALY_THRESHOLD = 45.0 

print(f"[+] AI Brain Online. Hardware: {device.type.upper()}")
print(f"[+] Listening to live eBPF stream... Waiting for executions.\n")

for message in consumer:
    event = message.value
    
    # Extract data safely
    uid = event.get('uid', 1000)
    raw_cmd = event.get('command', 'unknown')
    
    # We bypass args for now just like we did in training
    args_str = 'none' 

    # --- LIVE PREPROCESSING ---
    # Handle Unseen Commands (Zero-Days often use tools the server has never seen)
    try:
        encoded_cmd = cmd_encoder.transform([raw_cmd])[0]
    except ValueError:
        # If the AI has never seen this command before, assign it a massive outlier number
        encoded_cmd = 9999 

    encoded_uid = scaler.transform([[uid]])[0][0]
    encoded_args = args_vectorizer.transform([args_str]).toarray()[0]

    # Build the math matrix
    feature_vector = np.hstack(([encoded_uid], [encoded_cmd], encoded_args))
    tensor_data = torch.FloatTensor(feature_vector).unsqueeze(0).to(device)

    # --- NEURAL NETWORK INFERENCE ---
    with torch.no_grad(): # Don't train, just predict
        reconstructed = model(tensor_data)
        
        # Calculate how badly the AI failed to reconstruct the log
        loss = torch.nn.functional.mse_loss(reconstructed, tensor_data).item()

    # --- DECISION ENGINE ---
    if loss > ANOMALY_THRESHOLD:
        print(f"[🚨 ZERO-DAY ANOMALY DETECTED] Score: {loss:.2f} | User: {uid} | Command: {raw_cmd}")
        # Next month, this is where we will trigger the Rust/Go Local Responder to block the IP!
    else:
        print(f"[✅ NORMAL] Score: {loss:.2f} | Command: {raw_cmd}")
