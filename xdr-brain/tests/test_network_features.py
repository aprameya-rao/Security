import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest

from engine.network_features import ConnectionState, FEATURE_NAMES, NetworkFeatureError, extract_features


def event(ip="2001:db8::10", port=443, timestamp=1_700_000_000_000):
    return {
        "event_name": "connect",
        "uid": 1000,
        "command": "curl",
        "destination_ip": ip,
        "destination_port": port,
        "protocol": "tcp",
        "timestamp": timestamp,
    }


def test_ipv6_features_are_normalized():
    result = extract_features(event(), ConnectionState())
    assert len(result["features"]) == len(FEATURE_NAMES)
    assert result["context"]["destination_ip"] == "2001:db8::10"
    assert result["feature_map"]["is_ipv6"] == 1.0
    assert result["feature_map"]["is_ipv4"] == 0.0


def test_temporal_features_count_prior_connections():
    state = ConnectionState()
    extract_features(event(ip="192.0.2.10", timestamp=1_700_000_000_000), state)
    result = extract_features(event(ip="192.0.2.11", timestamp=1_700_000_005_000), state)
    assert result["feature_map"]["connections_10s"] == 2.0
    assert result["feature_map"]["unique_destinations_60s"] == 2.0
    assert result["feature_map"]["seconds_since_previous"] == 5.0


def test_non_connect_events_are_rejected():
    with pytest.raises(NetworkFeatureError):
        extract_features({"event_name": "execve"})


def test_invalid_port_is_rejected():
    with pytest.raises(NetworkFeatureError):
        extract_features(event(port=70000))
