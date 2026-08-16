# TG Threat Monitor configuration - SAFE DEFAULTS
# Replace values with your real API credentials locally. Do NOT commit real secrets.

# Telegram API credentials (placeholder)
API_ID = 0
API_HASH = ""

# Telethon session name
SESSION_NAME = "tg_threat_monitor"

# List of target channels to monitor (usernames or IDs)
TARGET_CHANNELS = []

# Paths
LOG_PATH = "logs/app.log"
DB_PATH = "data/threats.db"
REPORT_PATH = "report.html"

# Optional VirusTotal API key for enrichment
VT_API_KEY = ""

# Extraction toggles
EXTRACT_IPS = True
EXTRACT_HASHES = True
EXTRACT_CVES = True
EXTRACT_EMAILS = True
EXTRACT_URLS = True
EXTRACT_DOMAINS = True

# Watchlist: terms that should raise severity to HIGH if found
WATCHLIST = []
