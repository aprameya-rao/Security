"""Feature contract for connect events used by the future NIDS model."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


FEATURE_NAMES = [
    "uid",
    "destination_port",
    "is_tcp",
    "is_ipv4",
    "is_ipv6",
    "is_loopback",
    "is_private",
    "is_link_local",
    "is_global",
    "is_privileged_port",
    "destination_prefix_hash",
    "command_hash",
    "connections_10s",
    "connections_60s",
    "unique_destinations_60s",
    "unique_ports_60s",
    "seconds_since_previous",
    "hour_sin",
    "hour_cos",
]

FEATURE_VERSION = "nids-features-v1"
WINDOW_SECONDS = 60.0
SHORT_WINDOW_SECONDS = 10.0
HASH_BUCKETS = 64


class NetworkFeatureError(ValueError):
    """Raised when a connect event cannot be represented safely."""


class ConnectionState:
    """Bounded per-process history for short-term connection features."""

    def __init__(self, max_entries: int = 1024):
        self.max_entries = max_entries
        self.events: dict[tuple[int, str], deque[tuple[float, str, int]]] = defaultdict(
            lambda: deque(maxlen=self.max_entries)
        )

    def observe(self, key: tuple[int, str], timestamp: float, destination: str, port: int) -> dict[str, float]:
        history = self.events[key]
        cutoff = timestamp - WINDOW_SECONDS
        while history and history[0][0] < cutoff:
            history.popleft()

        previous = history[-1][0] if history else None
        short_cutoff = timestamp - SHORT_WINDOW_SECONDS
        recent_short = [event for event in history if event[0] >= short_cutoff]
        features = {
            "connections_10s": float(len(recent_short) + 1),
            "connections_60s": float(len(history) + 1),
            "unique_destinations_60s": float(len({event[1] for event in history} | {destination})),
            "unique_ports_60s": float(len({event[2] for event in history} | {port})),
            "seconds_since_previous": 0.0 if previous is None else max(0.0, timestamp - previous),
        }
        history.append((timestamp, destination, port))
        return features


def _hash_bucket(value: str) -> float:
    digest = hashlib.blake2b(value.encode("utf-8"), digest_size=8).digest()
    return float(int.from_bytes(digest, "big") % HASH_BUCKETS) / HASH_BUCKETS


def _timestamp(event: dict[str, Any]) -> float:
    raw_timestamp = event.get("timestamp")
    if raw_timestamp is None:
        return time.time()
    if hasattr(raw_timestamp, "timestamp"):
        return float(raw_timestamp.timestamp())
    value = float(raw_timestamp)
    return value / 1000.0 if value > 10_000_000_000 else value


def _parse_event(event: dict[str, Any]) -> tuple[ipaddress._BaseAddress, int, str, int, float]:
    if event.get("event_name") != "connect":
        raise NetworkFeatureError("event is not a connect event")
    try:
        address = ipaddress.ip_address(str(event["destination_ip"]))
        port = int(event["destination_port"])
        uid = int(event.get("uid", 0))
    except (KeyError, TypeError, ValueError) as exc:
        raise NetworkFeatureError("invalid connect event fields") from exc
    if not 0 <= port <= 65535:
        raise NetworkFeatureError("destination port is outside the valid range")
    if uid < 0:
        raise NetworkFeatureError("uid cannot be negative")
    command = str(event.get("command", "unknown")).strip().replace("\x00", "") or "unknown"
    return address, port, command, uid, _timestamp(event)


def extract_features(event: dict[str, Any], state: ConnectionState | None = None) -> dict[str, Any]:
    """Return a stable feature mapping plus normalized context for an event."""
    address, port, command, uid, timestamp = _parse_event(event)
    protocol = str(event.get("protocol", "tcp")).lower()
    destination = address.compressed
    prefix = str(ipaddress.ip_network(f"{destination}/{24 if address.version == 4 else 64}", strict=False))
    temporal = {
        "connections_10s": 1.0,
        "connections_60s": 1.0,
        "unique_destinations_60s": 1.0,
        "unique_ports_60s": 1.0,
        "seconds_since_previous": 0.0,
    }
    if state is not None:
        temporal = state.observe((uid, command), timestamp, destination, port)

    hour = (timestamp % 86400.0) / 3600.0
    angle = 2.0 * math.pi * hour / 24.0
    features = {
        "uid": float(uid),
        "destination_port": float(port),
        "is_tcp": float(protocol == "tcp"),
        "is_ipv4": float(address.version == 4),
        "is_ipv6": float(address.version == 6),
        "is_loopback": float(address.is_loopback),
        "is_private": float(address.is_private),
        "is_link_local": float(address.is_link_local),
        "is_global": float(address.is_global),
        "is_privileged_port": float(0 < port < 1024),
        "destination_prefix_hash": _hash_bucket(prefix),
        "command_hash": _hash_bucket(command.lower()),
        **temporal,
        "hour_sin": math.sin(angle),
        "hour_cos": math.cos(angle),
    }
    return {
        "features": [features[name] for name in FEATURE_NAMES],
        "feature_map": features,
        "context": {
            "destination_ip": destination,
            "destination_port": port,
            "protocol": protocol,
            "command": command,
            "uid": uid,
            "timestamp": timestamp,
        },
    }


def write_metadata(path: str | Path) -> None:
    metadata = {
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "hash_buckets": HASH_BUCKETS,
        "short_window_seconds": SHORT_WINDOW_SECONDS,
        "window_seconds": WINDOW_SECONDS,
        "raw_ip_used_for_model": False,
    }
    Path(path).write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    output = Path("engine/models/nids_feature_metadata.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    write_metadata(output)
    print(f"Wrote {output} with {len(FEATURE_NAMES)} features")
