#!/usr/bin/env python3

import os
import re
import time
import json
import socket
import hashlib
import yaml
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


CONFIG_PATH = Path(__file__).parent / "config.yaml"

HOSTNAME = socket.gethostname()
AGENT_ID = hashlib.sha256(HOSTNAME.encode()).hexdigest()[:8]

# regex patterns for severity
SEVERITY_PATTERNS = [
    ("critical", re.compile(r"\b(panic|fatal|critical|emerg)\b", re.I)),
    ("error",    re.compile(r"\b(error|fail(ed|ure)?|denied|invalid|refused)\b", re.I)),
    ("warning",  re.compile(r"\b(warn(ing)?|deprecated|timeout)\b", re.I)),
]

# regex patterns for tags
TAG_PATTERNS = [
    ("auth_failure", re.compile(r"(failed password|authentication failure|invalid user)", re.I)),
    ("auth_success", re.compile(r"(accepted password|accepted publickey|session opened)", re.I)),
    ("sudo",         re.compile(r"\bsudo\b", re.I)),
    ("firewall",     re.compile(r"\b(ufw|iptables|nft)\b", re.I)),
    ("kernel",       re.compile(r"\bkernel\b", re.I)),
]

# demo alert rule
ALERT_RULES = [
    ("demo_ssh_localhost", re.compile(r"ssh\s+test@localhost", re.I),
     "demo trigger: 'ssh test@localhost' observed"),
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# brute force tracking
ssh_failures = defaultdict(list)
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def classify_severity(line):
    for sev, pattern in SEVERITY_PATTERNS:
        if pattern.search(line):
            return sev
    return "info"


def extract_tags(line):
    return [tag for tag, pattern in TAG_PATTERNS if pattern.search(line)]


def check_brute_force(ip):
    now = time.time()
    ssh_failures[ip].append(now)
    ssh_failures[ip] = [t for t in ssh_failures[ip] if now - t <= BRUTE_FORCE_WINDOW]
    return len(ssh_failures[ip]) >= BRUTE_FORCE_THRESHOLD


def enrich(line, source):
    payload = {
        "timestamp": now_iso(),
        "host": HOSTNAME,
        "agent_id": AGENT_ID,
        "source": source,
        "message": line,
        "severity": classify_severity(line),
        "checksum": hashlib.sha256(line.encode()).hexdigest()[:12],
    }

    tags = extract_tags(line)
    ips = IP_RE.findall(line)

    if ips:
        payload["ips"] = ips

    if tags:
        payload["tags"] = tags

    # check for brute force
    alerts = []
    if "auth_failure" in tags and ips:
        for ip in ips:
            if check_brute_force(ip):
                alerts.append({
                    "rule": "ssh_brute_force",
                    "detail": f"{BRUTE_FORCE_THRESHOLD}+ auth failures from {ip} within {BRUTE_FORCE_WINDOW}s",
                    "ip": ip,
                })

    # check demo alert rules
    for rule, pattern, detail in ALERT_RULES:
        if pattern.search(line):
            alerts.append({"rule": rule, "detail": detail})

    if alerts:
        payload["alerts"] = alerts
        payload["severity"] = "critical"

    return payload


def send_log(host, port, payload):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            s.sendall(json.dumps(payload).encode("utf-8") + b"\n")
    except (ConnectionRefusedError, OSError) as e:
        print(f"[{now_iso()}] send failed: {e}")


def tail_file(path, offset, inode):
    """Read new lines from a file, returns (lines, new_offset, new_inode)"""
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return [], offset, inode

    # handle log rotation or truncation
    if inode and stat.st_ino != inode:
        offset = 0
    if stat.st_size < offset:
        offset = 0

    lines = []
    with open(path, "r") as f:
        f.seek(offset)
        for _ in range(100):
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if line:
                lines.append(line)
        offset = f.tell()

    return lines, offset, stat.st_ino


def main():
    with open(CONFIG_PATH, "r") as f:
        cfg = yaml.safe_load(f)

    host = cfg["agent"]["host"]
    port = cfg["agent"]["port"]
    interval = cfg["agent"]["scan_interval"]

    # set up file tracking (offset and inode per file)
    files = {}
    for path in cfg.get("log_sources", {}).get("files", []):
        if os.path.exists(path):
            stat = os.stat(path)
            files[path] = {"offset": stat.st_size, "inode": stat.st_ino}
            print(f"[{now_iso()}] tailing: {path}")
        else:
            print(f"[{now_iso()}] skipping (not found): {path}")

    print(f"[{now_iso()}] agent started -> {host}:{port}, interval={interval}s\n")

    while True:
        sent = 0

        for path, state in files.items():
            lines, new_offset, new_inode = tail_file(path, state["offset"], state["inode"])
            state["offset"] = new_offset
            state["inode"] = new_inode

            for line in lines:
                payload = enrich(line, path)
                send_log(host, port, payload)
                sent += 1

        if sent:
            print(f"[{now_iso()}] shipped {sent} log lines")

        time.sleep(interval)


if __name__ == "__main__":
    main()
