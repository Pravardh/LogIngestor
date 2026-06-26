# Encrypted Log Shipping Agent with AI-Powered Analysis

A lightweight Python based log collection tool that tails Linux log files, enriches them with detection logic, encrypts them at rest, and uses DeepSeek's API to generate analyst-ready summaries of critical events.

## How it works

- **agent.py** : tails log files (auth.log, syslog, etc.), enriches each line with severity, tags, IP extraction, and brute-force detection, then ships it to the receiver over TCP
- **receiver.py** : listens for incoming logs, encrypts them with Fernet, stores them as `.enc` files, and sends desktop notifications for alerts
- **analyze_logs.py** : decrypts stored logs, filters for critical/alert-level entries, and sends them to DeepSeek for a plain-English breakdown of what happened and what to do next
- **decrypt_log.py** : utility to decrypt and view stored logs manually

## Setup

```
pip install pyyaml cryptography openai
```

## Usage

```bash
# Terminal 1: start the receiver
python3 receiver.py

# Terminal 2: start the agent (needs sudo for log access)
sudo python3 agent.py

# Terminal 3: run AI analysis
export DEEPSEEK_API_KEY="your-key-here"
python3 analyze_logs.py
```

## Configuration

Edit `config.yaml` to set the receiver address, scan interval, and which log files to tail.

```yaml
agent:
  host: "127.0.0.1"
  port: 1134
  scan_interval: 2
  max_lines_per_scan: 100

log_sources:
  files:
    - /var/log/auth.log
    - /var/log/syslog
```

## Testing alerts

Trigger the demo alert rule:
```bash
ssh test@localhost
```

Trigger brute-force detection (5+ failed attempts in 60s):
```bash
for i in $(seq 1 6); do ssh baduser@127.0.0.1; done
```
