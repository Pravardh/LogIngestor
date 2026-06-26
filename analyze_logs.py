#!/usr/bin/env python3
# usage: python3 analyze_logs.py
#        python3 analyze_logs.py --last 20
#        python3 analyze_logs.py --all

import os
import sys
import json
import argparse
from pathlib import Path
from cryptography.fernet import Fernet

try:
    from openai import OpenAI
except ImportError:
    print("missing dependency: pip install openai")
    sys.exit(1)


KEY_FILE = Path(__file__).parent / ".fernet.key"
STORE_DIR = Path(__file__).parent / "encrypted_logs"

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"


def decrypt_all(fernet: Fernet, limit: int | None = None) -> list[dict]:
    files = sorted(STORE_DIR.glob("*.enc"))
    if limit:
        files = files[-limit:]

    logs = []
    for f in files:
        try:
            raw = fernet.decrypt(f.read_bytes())
            logs.append(json.loads(raw.decode()))
        except Exception as e:
            print(f"[!] failed to decrypt {f.name}: {e}")
    return logs


def filter_critical(logs: list[dict]) -> list[dict]:
    critical = []
    for log in logs:
        if log.get("severity") == "critical" or log.get("alerts"):
            critical.append(log)
    return critical


def analyze_with_deepseek(logs: list[dict]) -> str:
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("[!] DEEPSEEK_API_KEY environment variable not set")
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)

    prompt = (
        "You are a senior SOC analyst reviewing enriched logs from a "
        "SIEM pipeline. These logs were flagged as critical or triggered "
        "alert rules during ingestion.\n\n"
        "Here are the logs:\n\n"
        + json.dumps(logs, indent=2) +
        "\n\nGive me a breakdown:\n"
        "1. What is happening? Summarize the activity.\n"
        "2. What looks suspicious and why exactly?\n"
        "3. What should a SOC analyst do next? Be specific with actions."
    )

    response = client.chat.completions.create(
        model=DEEPSEEK_MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def main():
    parser = argparse.ArgumentParser(description="AI-powered log analysis using DeepSeek")
    parser.add_argument("--last", type=int, default=None,
                        help="only analyze the last N log files")
    parser.add_argument("--all", action="store_true",
                        help="analyze all logs, not just critical ones")
    args = parser.parse_args()

    if not KEY_FILE.exists():
        print("[!] no fernet key found -- has the receiver run at least once?")
        sys.exit(1)

    if not STORE_DIR.exists():
        print("[!] no encrypted_logs directory found")
        sys.exit(1)

    fernet = Fernet(KEY_FILE.read_bytes())

    print("[*] decrypting stored logs...")
    all_logs = decrypt_all(fernet, limit=args.last)
    print(f"[*] decrypted {len(all_logs)} log entries")

    if args.all:
        to_analyze = all_logs
    else:
        to_analyze = filter_critical(all_logs)

    if not to_analyze:
        print("[*] no critical/alert logs found -- nothing to analyze")
        return

    print(f"[*] sending {len(to_analyze)} logs to DeepSeek for analysis...\n")

    try:
        summary = analyze_with_deepseek(to_analyze)
    except Exception as e:
        print(f"[!] DeepSeek API error: {e}")
        sys.exit(1)

    print("=" * 60)
    print("  AI ANALYSIS REPORT")
    print("=" * 60)
    print()
    print(summary)
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
