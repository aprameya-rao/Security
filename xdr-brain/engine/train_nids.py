"""Train the network autoencoder from benign connect telemetry."""

from __future__ import annotations

import argparse
import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from clickhouse_driver import Client
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from network_features import ConnectionState, FEATURE_NAMES, FEATURE_VERSION, extract_features


DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
DEFAULT_MODEL_PATH = Path("engine/models/nids_autoencoder.pt")
DEFAULT_SCALER_PATH = Path("engine/models/nids_scaler.pkl")
DEFAULT_METADATA_PATH = Path("engine/models/nids_feature_metadata.json")


class NIDSAutoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        hidden = max(16, min(64, input_dim * 2))
        bottleneck = max(4, min(16, input_dim // 2))
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, bottleneck),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, hidden),
            nn.ReLU(),
            nn.Linear(hidden, input_dim),
        )

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(values))


def fetch_events(client: Client, limit: int | None) -> list[dict]:
    limit_clause = f" LIMIT {int(limit)}" if limit else ""
    rows = client.execute(
        """
        SELECT ts AS timestamp, pid, uid, command, destination_ip, destination_port, protocol
        FROM security_logs.network_events
        WHERE is_known_threat = 0
          AND destination_ip != ''
          AND destination_port BETWEEN 1 AND 65535
        ORDER BY ts
        """ + limit_clause
    )
    columns = [
        "timestamp",
        "pid",
        "uid",
        "command",
        "destination_ip",
        "destination_port",
        "protocol",
    ]
    return [dict(zip(columns, row)) for row in rows]


def build_matrix(events: list[dict]) -> tuple[np.ndarray, int]:
    state = ConnectionState()
    vectors = []
    rejected = 0
    for event in events:
        try:
            vectors.append(extract_features({"event_name": "connect", **event}, state)["features"])
        except (TypeError, ValueError, KeyError):
            rejected += 1
    if not vectors:
        raise RuntimeError("No valid network events were available for training")
    return np.asarray(vectors, dtype=np.float32), rejected


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def reconstruction_errors(model: NIDSAutoencoder, values: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        source = torch.from_numpy(values).to(DEVICE)
        output = model(source)
        return torch.mean((output - source) ** 2, dim=1).cpu().numpy()


def train_model(
    matrix: np.ndarray,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    seed: int,
) -> tuple[NIDSAutoencoder, StandardScaler, np.ndarray]:
    set_seed(seed)
    if len(matrix) < 10:
        raise RuntimeError("At least 10 valid network events are required for training")

    train_values, validation_values = train_test_split(
        matrix, test_size=0.2, random_state=seed, shuffle=True
    )
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_values).astype(np.float32)
    validation_scaled = scaler.transform(validation_values).astype(np.float32)

    model = NIDSAutoencoder(train_scaled.shape[1]).to(DEVICE)
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()
    source = torch.from_numpy(train_scaled).to(DEVICE)

    model.train()
    for epoch in range(epochs):
        permutation = torch.randperm(source.size(0), device=DEVICE)
        for start in range(0, source.size(0), batch_size):
            batch = source[permutation[start : start + batch_size]]
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        if (epoch + 1) % max(1, epochs // 5) == 0 or epoch == 0:
            print(f"Epoch [{epoch + 1}/{epochs}], loss={loss.item():.6f}")

    return model, scaler, validation_scaled


def save_artifacts(
    model: NIDSAutoencoder,
    scaler: StandardScaler,
    validation_errors: np.ndarray,
    total_events: int,
    rejected_events: int,
    paths: tuple[Path, Path, Path],
    seed: int,
) -> None:
    model_path, scaler_path, metadata_path = paths
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), model_path)
    joblib.dump(scaler, scaler_path)
    threshold = float(np.percentile(validation_errors, 99))
    metadata = {
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "model_input_dim": len(FEATURE_NAMES),
        "model_type": "nids_autoencoder",
        "model_version": "nids-v1",
        "training_events": total_events,
        "rejected_events": rejected_events,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "validation_count": int(len(validation_errors)),
        "validation_loss_mean": float(np.mean(validation_errors)),
        "validation_loss_p95": float(np.percentile(validation_errors, 95)),
        "validation_loss_p99": threshold,
        "anomaly_threshold": threshold,
        "threshold_rule": "validation_loss_p99",
        "raw_ip_used_for_model": False,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Saved model: {model_path}")
    print(f"Saved scaler: {scaler_path}")
    print(f"Saved metadata: {metadata_path}")
    print(f"Validation P99 threshold: {threshold:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--clickhouse-host", default=os.getenv("CLICKHOUSE_HOST", "localhost"))
    parser.add_argument("--clickhouse-port", type=int, default=int(os.getenv("CLICKHOUSE_NATIVE_PORT", "9000")))
    args = parser.parse_args()
    if args.epochs < 1 or args.batch_size < 1 or args.learning_rate <= 0:
        parser.error("epochs and batch-size must be positive, and learning-rate must be greater than zero")

    print(f"NIDS training device: {DEVICE.type.upper()}")
    client = Client(host=args.clickhouse_host, port=args.clickhouse_port, user="default", password="admin")
    events = fetch_events(client, args.limit)
    matrix, rejected = build_matrix(events)
    print(f"Loaded {len(events)} events; valid={len(matrix)}, rejected={rejected}")
    model, scaler, validation_scaled = train_model(
        matrix, args.epochs, args.batch_size, args.learning_rate, args.seed
    )
    validation_errors = reconstruction_errors(model, validation_scaled)
    save_artifacts(
        model,
        scaler,
        validation_errors,
        len(events),
        rejected,
        (DEFAULT_MODEL_PATH, DEFAULT_SCALER_PATH, DEFAULT_METADATA_PATH),
        args.seed,
    )


if __name__ == "__main__":
    main()
