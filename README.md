# 🛡 TG Threat Intel Monitor

A lightweight Python tool that passively monitors public Telegram channels for cybersecurity threat intelligence — CVEs, malware hashes, IPs, domains, and other IOCs — and logs them to a local database with optional VirusTotal enrichment.

Built by **Sycosmile** (https://github.com/Sycosmile) as part of a cybersecurity portfolio project.

---

## Features

- 📡 Monitors multiple public Telegram channels simultaneously
- 🔍 Extracts IOCs: IPv4, MD5/SHA1/SHA256 hashes, CVE IDs, domains, URLs, emails
- 🎯 Keyword watchlist — get flagged when your target terms appear
- 🦠 Optional VirusTotal enrichment for hashes and IPs
- 🗄 SQLite logging with severity tagging (HIGH / MEDIUM / LOW)
- 📊 One-command HTML report generation
- 🖥 Clean terminal output with color-coded severity

---

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/David1798-tech/tg-threat-monitor.git
cd tg-threat-monitor
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Get Telegram API credentials
- Go to [https://my.telegram.org](https://my.telegram.org)
- Log in → API Development Tools → Create App
- Copy your `api_id` and `api_hash`

### 4. Configure
```bash
cp config.example.py config.py
```
Edit `config.py` and fill in:
- `API_ID` and `API_HASH`
- `TARGET_CHANNELS` — public channel usernames to monitor
- `WATCHLIST` — keywords/domains to flag (optional)
- `VT_API_KEY` — VirusTotal API key (optional, free tier available)

---

## Usage

### Start monitoring
```bash
python main.py monitor
```

### Generate HTML report
```bash
python main.py report
```

### View stats
```bash
python main.py stats
```

---

## Project Structure

```
tg-threat-monitor/
├── main.py              # Entry point & CLI
├── config.py            # Your credentials & settings (gitignored)
├── requirements.txt
├── core/
│   ├── monitor.py       # Telethon channel listener
│   ├── parser.py        # IOC extraction & severity scoring
│   ├── database.py      # SQLite logging
│   ├── reporter.py      # HTML report generator
│   └── virustotal.py    # VT API enrichment
├── data/                # SQLite DB & logs (gitignored)
└── output/              # Generated reports (gitignored)
```

---

## Example Output

```
[HIGH] @vxunderground | 2025-01-15 14:32:01
  SHA256: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
  CVE: CVE-2024-12345
  [WATCHLIST HIT] mycompany.com
```

---

## Disclaimer

This tool is intended for **authorized security research and threat intelligence purposes only**. Only monitor public channels. Do not use against private accounts or groups without authorization. The author assumes no liability for misuse.

---

## License

MIT License
