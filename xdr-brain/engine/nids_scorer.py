"""Detect-only live scorer for network connect telemetry."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import torch
from clickhouse_connect import get_client
from kafka import KafkaConsumer, KafkaProducer

from network_features import ConnectionState, FEATURE_NAMES, FEATURE_VERSION, NetworkFeatureError, extract_features
from train_nids import NIDSAutoencoder


INPUT_TOPIC = os.getenv("NIDS_INPUT_TOPIC", "xdr-telemetry")
ALERT_TOPIC = os.getenv("NIDS_ALERT_TOPIC", "nids-alerts")
BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
GROUP_ID = os.getenv("NIDS_CONSUMER_GROUP", "nids-scorer")
MODEL_PATH = Path(os.getenv("NIDS_MODEL_PATH", "engine/models/nids_autoencoder.pt"))
SCALER_PATH = Path(os.getenv("NIDS_SCALER_PATH", "engine/models/nids_scaler.pkl"))
METADATA_PATH = Path(os.getenv("NIDS_METADATA_PATH", "engine/models/nids_feature_metadata.json"))
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "admin")
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def event_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    timestamp = float(value)
    if timestamp > 10_000_000_000:
        timestamp /= 1000.0
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).replace(tzinfo=None)


def load_artifacts() -> tuple[NIDSAutoencoder, object, dict]:
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    if metadata.get("feature_version") != FEATURE_VERSION:
        raise RuntimeError("NIDS feature version does not match the trained metadata")
    if metadata.get("feature_names") != FEATURE_NAMES:
        raise RuntimeError("NIDS feature order does not match the trained metadata")
    if metadata.get("model_input_dim") != len(FEATURE_NAMES):
        raise RuntimeError("NIDS model input dimension is inconsistent with feature metadata")

    scaler = joblib.load(SCALER_PATH)
    if getattr(scaler, "n_features_in_", len(FEATURE_NAMES)) != len(FEATURE_NAMES):
        raise RuntimeError("NIDS scaler input dimension is inconsistent with feature metadata")
    model = NIDSAutoencoder(len(FEATURE_NAMES)).to(DEVICE)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE, weights_only=True))
    model.eval()
    return model, scaler, metadata


def score_event(model: NIDSAutoencoder, scaler: object, event: dict, state: ConnectionState) -> dict:
    extracted = extract_features(event, state)
    values = np.asarray([extracted["features"]], dtype=np.float32)
    scaled = scaler.transform(values).astype(np.float32)
    source = torch.from_numpy(scaled).to(DEVICE)
    with torch.no_grad():
        reconstructed = model(source)
        score = torch.mean((reconstructed - source) ** 2, dim=1).item()
    return {
        **event,
        "score": float(score),
        "features": extracted["feature_map"],
        "context": extracted["context"],
    }


def insert_alert(client: object, alert: dict, threshold: float, anomaly: bool, model_version: str) -> None:
    context = alert["context"]
    client.insert(
        "security_logs.network_anomalies",
        [[
            event_datetime(context["timestamp"]),
            context["uid"],
            int(alert.get("pid", 0)),
            context["command"],
            context["destination_ip"],
            context["destination_port"],
            context["protocol"],
            alert["score"],
            threshold,
            anomaly,
            "nids_autoencoder",
            model_version,
            json.dumps(alert["features"], separators=(",", ":")),
        ]],
        column_names=[
            "ts", "uid", "pid", "command", "destination_ip", "destination_port",
            "protocol", "score", "threshold", "is_anomaly", "detector", "model_version",
            "features_json",
        ],
    )


def main() -> None:
    model, scaler, metadata = load_artifacts()
    threshold = float(os.getenv("NIDS_ANOMALY_THRESHOLD", metadata["anomaly_threshold"]))
    consumer = KafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=[BOOTSTRAP],
        group_id=GROUP_ID,
        auto_offset_reset=os.getenv("NIDS_AUTO_OFFSET_RESET", "latest"),
        enable_auto_commit=True,
    )
    producer = KafkaProducer(
        bootstrap_servers=[BOOTSTRAP],
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )
    client = get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, password=CLICKHOUSE_PASSWORD)
    state = ConnectionState()
    model_version = metadata.get("model_version", "unknown")
    print(f"NIDS scorer online: model={model_version}, features={len(FEATURE_NAMES)}, threshold={threshold:.6f}")
    print(f"Input={INPUT_TOPIC}, alerts={ALERT_TOPIC}, mode=detect-only, device={DEVICE.type.upper()}")

    try:
        for message in consumer:
            try:
                event = json.loads(message.value.decode("utf-8"))
                if event.get("event_name") != "connect":
                    continue
                scored = score_event(model, scaler, event, state)
                is_anomaly = scored["score"] > threshold
                if not is_anomaly:
                    print(f"[NIDS NORMAL] score={scored['score']:.6f} command={scored['context']['command']}")
                    continue
                alert = {
                    "event_name": "network_anomaly",
                    "original_event": "connect",
                    "pid": int(event.get("pid", 0)),
                    "uid": scored["context"]["uid"],
                    "command": scored["context"]["command"],
                    "destination_ip": scored["context"]["destination_ip"],
                    "destination_port": scored["context"]["destination_port"],
                    "protocol": scored["context"]["protocol"],
                    "score": scored["score"],
                    "threshold": threshold,
                    "is_anomaly": True,
                    "detector": "nids_autoencoder",
                    "model_version": model_version,
                    "features": scored["features"],
                    "timestamp": event.get("timestamp"),
                }
                producer.send(ALERT_TOPIC, alert)
                producer.flush()
                insert_alert(client, scored, threshold, True, model_version)
                print(f"[NIDS ANOMALY] score={scored['score']:.6f} command={alert['command']} destination={alert['destination_ip']}:{alert['destination_port']}")
            except (json.JSONDecodeError, NetworkFeatureError, KeyError, TypeError, ValueError) as exc:
                print(f"NIDS event rejected: {exc}")
            except Exception as exc:
                print(f"NIDS event processing error: {exc}")
    finally:
        consumer.close()
        producer.close()


if __name__ == "__main__":
    main()
