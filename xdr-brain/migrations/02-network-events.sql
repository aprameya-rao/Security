ALTER TABLE security_logs.execve_events
    ADD COLUMN IF NOT EXISTS args String AFTER command;

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
