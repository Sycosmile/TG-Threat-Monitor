# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — VirusTotal Lookup
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import time
import requests

VT_BASE = "https://www.virustotal.com/api/v3"

def vt_headers(key: str) -> dict:
    return {
        "x-apikey": key,
        "Accept": "application/json"
    }

TYPE_ENDPOINTS = {
    "ipv4":   "ip_addresses",
    "domain": "domains",
    "url":    "urls",
    "md5":    "files",
    "sha1":   "files",
    "sha256": "files",
}


def lookup(ioc: str, ioc_type: str, api_key: str) -> dict:
    """Query VirusTotal for a given IOC. Returns a summary dict."""
    if not api_key:
        return {}

    endpoint = TYPE_ENDPOINTS.get(ioc_type)
    if not endpoint:
        return {}

    try:
        url = f"{VT_BASE}/{endpoint}/{ioc}"
        resp = requests.get(url, headers=vt_headers(api_key), timeout=10)

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", None),
            }
        elif resp.status_code == 429:
            print("[VT] Rate limit hit — waiting 60s...")
            time.sleep(60)
            return lookup(ioc, ioc_type, api_key)
        else:
            return {"error": resp.status_code}

    except Exception as e:
        return {"error": str(e)}


def is_malicious(vt_result: dict, threshold: int = 3) -> bool:
    """Return True if VT flags the IOC as malicious above threshold."""
    return vt_result.get("malicious", 0) >= threshold
