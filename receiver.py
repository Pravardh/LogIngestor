#!/usr/bin/env python3

import os
import json
import socket
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet


HOST = "127.0.0.1"
PORT = 1134
STORE_DIR = Path(__file__).parent / "encrypted_logs"
KEY_FILE = Path(__file__).parent / ".fernet.key"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def notify(title, body):
    """Send a desktop notification for alerts"""
    try:
        subprocess.run(
            ["notify-send", "-u", "critical", "-a", "SOC Receiver", title, body],
            timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        pass


def load_or_create_key():
    """Load existing Fernet key or generate a new one"""
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
        print(f"[{now_iso()}] loaded key from {KEY_FILE}")
    else:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        os.chmod(KEY_FILE, 0o600)
        print(f"[{now_iso()}] generated new key: {KEY_FILE}")

    return Fernet(key)


def handle_client(conn, addr, fernet):
    """Handle a single incoming log"""
    with conn:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

    if not data.strip():
        return

    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        print(f"[{now_iso()}] bad json from {addr}")
        return

    message = payload.get("message", "")
    source = payload.get("source", "unknown")
    severity = payload.get("severity", "info")
    alerts = payload.get("alerts") or []

    # print alerts or normal log
    if alerts:
        for a in alerts:
            rule = a.get("rule", "unknown")
            detail = a.get("detail", "")
            print(f"[{now_iso()}] !! ALERT !! [{rule}] {detail} | src={source}")
            notify(f"ALERT: {rule}", f"{detail}\nsource: {source}")
    else:
        print(f"[{now_iso()}] LOG | src={source} | sev={severity} | {message[:120]}")

    # encrypt and store
    encrypted = fernet.encrypt(json.dumps(payload).encode("utf-8"))
    ts = payload.get("timestamp", now_iso())
    safe_ts = ts.replace(":", "-").replace("+", "").replace(".", "-")[:26]
    filename = STORE_DIR / f"{safe_ts}.enc"
    filename.write_bytes(encrypted)


def main():
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    fernet = load_or_create_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    print(f"[{now_iso()}] receiver listening on {HOST}:{PORT}")
    print(f"[{now_iso()}] encrypted logs -> {STORE_DIR}\n")

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, fernet), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
