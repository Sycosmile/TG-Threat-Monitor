# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — VirusTotal Lookup (async)
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import asyncio
from typing import Dict, Any
import httpx

VT_BASE = "https://www.virustotal.com/api/v3"


TYPE_ENDPOINTS = {
    "ipv4": "ip_addresses",
    "domain": "domains",
    "url": "urls",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
}


def vt_headers(key: str) -> Dict[str, str]:
    return {"x-apikey": key, "Accept": "application/json"}


async def lookup(
    ioc: str,
    ioc_type: str,
    api_key: str,
    max_retries: int = 3,
    backoff_base: float = 1.0,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Async lookup of an IOC on VirusTotal. Returns a summary dict."""
    if not api_key:
        return {}
    endpoint = TYPE_ENDPOINTS.get(ioc_type)
    if not endpoint:
        return {}

    url = f"{VT_BASE}/{endpoint}/{ioc}"
    headers = vt_headers(api_key)
    backoff = backoff_base

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(1, max_retries + 1):
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": data.get("reputation", None),
                    }
                if resp.status_code == 429:
                    # rate limited — backoff and retry
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                # other HTTP errors: return status for caller to inspect
                return {"error": resp.status_code}
            except httpx.HTTPError as e:
                if attempt == max_retries:
                    return {"error": str(e)}
                await asyncio.sleep(backoff)
                backoff *= 2

    return {}


def is_malicious(vt_result: dict, threshold: int = 3) -> bool:
    """Return True if VT flags the IOC as malicious above threshold."""
    return vt_result.get("malicious", 0) >= threshold
