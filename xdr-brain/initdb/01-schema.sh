#!/bin/bash
set -e

clickhouse-client --password "$CLICKHOUSE_PASSWORD" -q "
CREATE DATABASE IF NOT EXISTS security_logs;

CREATE TABLE IF NOT EXISTS security_logs.execve_events
(
    ts                DateTime,
    event_name        String,
    pid               UInt32,
    uid               UInt32,
    command           String,
    args              String,
    is_root           UInt8,
    is_suspicious     UInt8,
    is_tmp_execution  UInt8,
    is_known_threat   UInt8
)
ENGINE = MergeTree()
ORDER BY ts;

CREATE TABLE IF NOT EXISTS security_logs.network_events
(
    ts                DateTime,
    event_name        String,
    pid               UInt32,
    uid               UInt32,
    command           String,
    destination_ip    String,
    destination_port  UInt16,
    protocol          String,
    is_root           UInt8,
    is_suspicious     UInt8,
    is_known_threat   UInt8
)
ENGINE = MergeTree()
ORDER BY ts;
"
