# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Config Example
#  Copy this to config.py and fill in your values
#  DO NOT commit config.py to GitHub
# ─────────────────────────────────────────────

API_ID = ""        # From https://my.telegram.org
API_HASH = ""      # From https://my.telegram.org
SESSION_NAME = "threat_monitor"

TARGET_CHANNELS = [
    "cybersecuritynews",
    "malwarehunterteam",
    "vxunderground",
]

VT_API_KEY = ""    # Optional — https://virustotal.com

WATCHLIST = [
    # "yourdomain.com",
    # "your@email.com",
]

DB_PATH = "data/threats.db"
LOG_PATH = "data/monitor.log"
REPORT_PATH = "output/report.html"

EXTRACT_IPS = True
EXTRACT_HASHES = True
EXTRACT_CVES = True
EXTRACT_DOMAINS = True
EXTRACT_EMAILS = True
EXTRACT_URLS = True
