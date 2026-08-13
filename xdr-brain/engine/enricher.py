# engine/enricher.py
import os
import redis

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')

try:
    ti_cache = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
    ti_cache.ping() # Test connection
except redis.ConnectionError:
    print("⚠️  Warning: Threat Intel Cache (Redis) is unreachable.")
# A set of commands that are commonly used in attacks
SUSPICIOUS_COMMANDS = {
    # Networking
    "nc", "ncat", "netcat", "socat", "telnet",

    # Downloaders
    "wget", "curl", "fetch",

    # Shell execution
    "sh -c",
    "bash -c",
    "bash -i",
    "/bin/sh",
    "/bin/bash",
    "dash",
    "zsh",
    "ksh",

    # Encoding/obfuscation
    "base64",
    "xxd",
    "openssl enc",
    "python -c",
    "perl -e",
    "ruby -e",
    "php -r",

    # Scripting interpreters
    "python",
    "python3",
    "perl",
    "php",
    "ruby",
    "lua",
    "node",
    "pwsh",
    "powershell",

    # Process execution
    "exec",
    "nohup",
    "setsid",

    # Reconnaissance
    "whoami",
    "id",
    "uname",
    "hostname",
    "ifconfig",
    "ip addr",
    "ip route",
    "arp",
    "netstat",
    "ss",
    "lsof",
    "ps aux",

    # File discovery
    "find",
    "locate",
    "which",
    "whereis",

    # Privilege-related
    "sudo",
    "su",

    # Compression/archiving
    "tar",
    "gzip",
    "zip",
    "unzip",

    # File transfer
    "scp",
    "sftp",
    "rsync",

    # SSH
    "ssh",
    "sshpass",

    # Scheduling/persistence
    "crontab",
    "at",

    # Container/runtime
    "docker",
    "podman",
    "kubectl",

    # Miscellaneous
    "env",
    "printenv",
    "mkfifo",
    "tee",
}

def enrich_event(data):
    """
    Takes raw telemetry, returns enriched data with security flags & Threat Intel.
    """
    command = data.get('command', '').lower()
    uid = data.get('uid', 1000)
    destination_ip = data.get('destination_ip', '').lower()

    # Standard Rule-Based Flags
    data['is_root'] = (uid == 0)
    data['is_suspicious'] = any(cmd in command for cmd in SUSPICIOUS_COMMANDS)
    data['is_tmp_execution'] = ("/tmp" in command or "/dev/shm" in command)

    # --- Substring Threat Intel Lookup (fed IOCs + learner feedback) ---
    data['is_known_threat'] = False  # Default to False
    try:
        # 1. Pull the entire list of known bad domains/signatures from Redis,
        #    plus confirmed-bad commands learned through the kill feedback loop.
        known_iocs = ti_cache.smembers("threat_intel:iocs") | ti_cache.smembers("threat_intel:learned")

        # 2. Match command text and network destinations against the same IOC sets.
        for ioc in known_iocs:
            if ioc in command or (destination_ip and ioc == destination_ip):
                data['is_known_threat'] = True
                print(f"🚨 THREAT INTEL MATCH: '{ioc}' matched event")
                break  # Stop checking once we confirm it's bad
                
    except Exception as e:
        print(f"Redis Error: {e}")

    return data
