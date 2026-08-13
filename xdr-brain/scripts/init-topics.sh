#!/usr/bin/env bash
set -u
BROKER="kafka:29092"
TOPICS="xdr-telemetry kill_commands kill_confirmations nids-alerts"
RE="$(echo "$TOPICS" | tr ' ' '|')"
for i in $(seq 1 60); do
  for t in $TOPICS; do
    kafka-topics --bootstrap-server "$BROKER" \
      --create --if-not-exists --topic "$t" --partitions 1 --replication-factor 1 >/dev/null 2>&1
  done
  n=$(kafka-topics --bootstrap-server "$BROKER" --list 2>/dev/null | grep -xE "$RE" | wc -l)
  if [ "$n" -eq 4 ]; then
    echo "topics OK: $(kafka-topics --bootstrap-server "$BROKER" --list)"
    exit 0
  fi
  echo "waiting for kafka ($n/4 topics)..."
  sleep 2
done
echo "FAILED to create topics on kafka"
exit 1
