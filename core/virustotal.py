# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — VirusTotal Lookup (async)
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import asyncio
from typing import Dict, Any, Optional
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


async def _safe_json(resp: httpx.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {}


async def lookup(
    ioc: str,
    ioc_type: str,
    api_key: str,
    max_retries: int = 3,
    backoff_base: float = 1.0,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Async lookup of an IOC on VirusTotal. Returns a summary dict.

    Special handling for URLs: VT requires submitting the URL (POST /urls)
    and then fetching the analysis resource (GET /urls/{id}). This function
    preserves the same result shape as the previous implementation.
    """
    if not api_key:
        return {}
    endpoint = TYPE_ENDPOINTS.get(ioc_type)
    if not endpoint:
        return {}

    headers = vt_headers(api_key)
    backoff = backoff_base

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(1, max_retries + 1):
            try:
                # URL handling requires a POST to create the resource, then GET by id
                if ioc_type == "url":
                    post_url = f"{VT_BASE}/urls"
                    resp = await client.post(post_url, data={"url": ioc}, headers=headers)
                    if resp.status_code == 200 or resp.status_code == 201:
                        data = await _safe_json(resp)
                        vid = (data or {}).get("data", {}).get("id")
                        if not vid:
                            return {"error": "no_url_id"}
                        # fetch the URL resource by id
                        get_url = f"{VT_BASE}/urls/{vid}"
                        resp2 = await client.get(get_url, headers=headers)
                        if resp2.status_code == 200:
                            data2 = await _safe_json(resp2)
                            attrs = (data2 or {}).get("data", {}).get("attributes", {})
                            stats = attrs.get("last_analysis_stats", {})
                            return {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "harmless": stats.get("harmless", 0),
                                "undetected": stats.get("undetected", 0),
                                "reputation": attrs.get("reputation", None),
                            }
                        if resp2.status_code == 429:
                            await asyncio.sleep(backoff)
                            backoff *= 2
                            continue
                        return {"error": resp2.status_code}

                    if resp.status_code == 429:
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    return {"error": resp.status_code}

                # non-URL types: standard GET on the endpoint
                url = f"{VT_BASE}/{endpoint}/{ioc}"
                resp = await client.get(url, headers=headers)

                if resp.status_code == 200:
                    data = await _safe_json(resp)
                    attrs = (data or {}).get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attrs.get("reputation", None),
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
