CREATE TABLE IF NOT EXISTS security_logs.network_anomalies
(
    ts                DateTime,
    uid               UInt32,
    pid               UInt32,
    command           String,
    destination_ip    String,
    destination_port  UInt16,
    protocol          String,
    score             Float32,
    threshold         Float32,
    is_anomaly        UInt8,
    detector          String,
    model_version     String,
    features_json     String
)
ENGINE = MergeTree()
ORDER BY ts;
