# ioc_learner.py — learns confirmed-bad commands into Redis threat_intel:learned.
# Confirmation sources ONLY:
#   - re-infection evidence: same zero-day token killed again within a window
#   - human triage: operator approves via ioc_approve.py
# A single successful kill is NOT treated as confirmation.
import json
import logging
import os
import time
from collections import defaultdict

from confluent_kafka import Consumer, KafkaException

import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IOCLearner")

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
LEARNED_SET = "threat_intel:learned"
PENDING_LIST = "threat_intel:pending_approval"
KAFKA_BOOTSTRAP = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')
ACK_TOPIC = os.getenv('IOC_ACK_TOPIC', 'kill_confirmations')
REINFECT_WINDOW_S = int(os.getenv('REINFECT_WINDOW_S', '300'))
REINFECT_KILLS = int(os.getenv('REINFECT_KILLS', '2'))

try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    r.ping()
except redis.ConnectionError:
    r = None
    logger.warning("Redis unreachable; outputs will only be logged.")

consumer = Consumer({
    'bootstrap.servers': KAFKA_BOOTSTRAP,
    'group.id': 'ioc-learner-group',
    'auto.offset.reset': 'earliest',
    'enable.auto.commit': True,
})

# token -> kill timestamps, pruned to the re-infection window
kills = defaultdict(list)


def tokenize(command):
    s = command.strip().replace('\x00', '').lower()
    if not s:
        return None
    s = s.split()[0] if ' ' in s else s
    if len(s) < 3 or len(s) > 64:
        return None
    return s


def re_infected(token):
    t = time.time()
    kills[token] = [ts for ts in kills[token] if t - ts <= REINFECT_WINDOW_S]
    return len(kills[token]) >= REINFECT_KILLS


def learn(token, pid, reason):
    if r is None:
        logger.info("[redis-down] would-learn '%s' (%s)", token, reason)
        return
    r.sadd(LEARNED_SET, token)
    logger.info("Learned IOC: '%s' (pid=%s, %s)", token, pid, reason)


def queue_triage(token, pid):
    if r is None:
        logger.info("[redis-down] would-queue '%s' for triage", token)
        return
    if r.sismember(LEARNED_SET, token):
        return
    if r.lpos(PENDING_LIST, token) is None:
        r.lpush(PENDING_LIST, token)
    logger.info("Queued '%s' (pid=%s) for operator triage", token, pid)


def handle_ack(msg):
    try:
        ack = json.loads(msg.value().decode('utf-8'))
    except json.JSONDecodeError:
        logger.error("Bad ack JSON: %s", msg.value())
        return
    if not ack.get('succeeded'):
        logger.info("Kill failed for pid=%s; not learning.", ack.get('pid'))
        return
    if ack.get('source') == 'known_ioc':
        return
    token = tokenize(ack.get('command', ''))
    if not token:
        return
    if ack.get('source') == 'zero_day':
        kills[token].append(time.time())
        if re_infected(token):
            learn(token, ack.get('pid'), 're-infection evidence')
            kills[token].clear()
        else:
            queue_triage(token, ack.get('pid'))
    else:
        queue_triage(token, ack.get('pid'))


def main():
    consumer.subscribe([ACK_TOPIC])
    logger.info("IOC Learner online: %s -> %s", ACK_TOPIC, LEARNED_SET)
    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == -191:  # _PARTITION_EOF
                    continue
                raise KafkaException(msg.error())
            handle_ack(msg)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        consumer.close()


if __name__ == '__main__':
    main()