# engine/enricher.py

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
    Takes raw telemetry, returns enriched data with security flags.
    """
    command = data.get('command', '').lower()
    uid = data.get('uid', 1000)

    # Flag 1: Privilege
    data['is_root'] = (uid == 0)

    # Flag 2: Suspicious pattern matching
    data['is_suspicious'] = any(cmd in command for cmd in SUSPICIOUS_COMMANDS)

    # Flag 3: Potential path manipulation (if command mentions /tmp)
    data['is_tmp_execution'] = ("/tmp" in command or "/dev/shm" in command)

    return data