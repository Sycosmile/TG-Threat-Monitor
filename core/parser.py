# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — IOC Parser
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import re
from dataclasses import dataclass, field
from typing import List

# ── IOC Patterns ──────────────────────────────
PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s\"\'<>]+"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|xyz|ru|cn|tk|top|info|biz|cc|pw|su)\b"
    ),
}

# Severity heuristics
HIGH_RISK_KEYWORDS = [
    "ransomware",
    "0day",
    "zero-day",
    "rce",
    "remote code execution",
    "critical",
    "exploit",
    "leaked",
    "breach",
    "dump",
    "shell",
    "backdoor",
]
MEDIUM_RISK_KEYWORDS = [
    "malware",
    "phishing",
    "trojan",
    "stealer",
    "botnet",
    "dropper",
    "c2",
    "c&c",
    "vulnerability",
    "cve",
    "credential",
]


@dataclass
class ParsedMessage:
    channel: str
    message_id: int
    timestamp: str
    raw_text: str
    iocs: dict = field(default_factory=dict)
    severity: str = "LOW"
    watchlist_hits: List[str] = field(default_factory=list)


def extract_iocs(text: str, cfg) -> dict:
    """Extract all IOCs from a message body."""
    found = {}

    if cfg.EXTRACT_IPS:
        ips = PATTERNS["ipv4"].findall(text)
        # Filter out common false positives (version numbers etc.)
        ips = [ip for ip in ips if not ip.startswith("0.") and ip not in ("127.0.0.1",)]
        if ips:
            found["ipv4"] = list(set(ips))

    if cfg.EXTRACT_HASHES:
        for h in ("md5", "sha1", "sha256"):
            hits = PATTERNS[h].findall(text)
            if hits:
                found[h] = list(set(hits))

    if cfg.EXTRACT_CVES:
        cves = PATTERNS["cve"].findall(text)
        if cves:
            found["cve"] = list(set(cves))

    if cfg.EXTRACT_EMAILS:
        emails = PATTERNS["email"].findall(text)
        if emails:
            found["email"] = list(set(emails))

    if cfg.EXTRACT_URLS:
        urls = PATTERNS["url"].findall(text)
        if urls:
            found["url"] = list(set(urls))

    if cfg.EXTRACT_DOMAINS:
        domains = PATTERNS["domain"].findall(text)
        # Remove domains already captured in URLs/emails to reduce noise
        if domains:
            found["domain"] = list(set(domains))

    return found


def assess_severity(text: str) -> str:
    """Assign severity based on keyword heuristics."""
    lower = text.lower()
    for kw in HIGH_RISK_KEYWORDS:
        if kw in lower:
            return "HIGH"
    for kw in MEDIUM_RISK_KEYWORDS:
        if kw in lower:
            return "MEDIUM"
    return "LOW"


def check_watchlist(text: str, watchlist: list) -> List[str]:
    """Return any watchlist terms found in the message."""
    hits = []
    lower = text.lower()
    for term in watchlist:
        if term.lower() in lower:
            hits.append(term)
    return hits


def parse_message(
    channel: str, msg_id: int, timestamp: str, text: str, cfg
) -> ParsedMessage:
    """Full pipeline: extract IOCs, assess severity, check watchlist."""
    iocs = extract_iocs(text, cfg)
    severity = assess_severity(text)
    watchlist_hits = check_watchlist(text, cfg.WATCHLIST)

    # Upgrade severity if watchlist hit
    if watchlist_hits and severity != "HIGH":
        severity = "HIGH"

    return ParsedMessage(
        channel=channel,
        message_id=msg_id,
        timestamp=timestamp,
        raw_text=text,
        iocs=iocs,
        severity=severity,
        watchlist_hits=watchlist_hits,
    )
