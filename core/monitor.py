# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Channel Monitor
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import logging
from datetime import datetime
from telethon import TelegramClient, events
from telethon.tl.functions.channels import JoinChannelRequest

from core.parser import parse_message
from core.database import save_threat, save_vt_result
from core import virustotal as vt

logger = logging.getLogger("monitor")


async def join_channels(client: TelegramClient, channels: list):
    """Attempt to join all target public channels."""
    for ch in channels:
        try:
            await client(JoinChannelRequest(ch))
            logger.info(f"[+] Joined: {ch}")
        except Exception as e:
            logger.warning(f"[!] Could not join {ch}: {e}")


async def start(cfg):
    """Main monitoring loop."""
    client = TelegramClient(cfg.SESSION_NAME, cfg.API_ID, cfg.API_HASH)

    await client.start()
    logger.info("[*] Client started. Monitoring channels...")

    await join_channels(client, cfg.TARGET_CHANNELS)

    @client.on(events.NewMessage(chats=cfg.TARGET_CHANNELS))
    async def handler(event):
        msg = event.message
        text = msg.message or ""

        if not text.strip():
            return

        channel = ""
        try:
            entity = await event.get_chat()
            channel = getattr(entity, "username", None) or str(entity.id)
        except Exception:
            channel = "unknown"

        timestamp = msg.date.strftime("%Y-%m-%d %H:%M:%S") if msg.date else str(datetime.utcnow())

        parsed = parse_message(
            channel=channel,
            msg_id=msg.id,
            timestamp=timestamp,
            text=text,
            cfg=cfg
        )

        # Only log messages with IOCs or watchlist hits
        if not parsed.iocs and not parsed.watchlist_hits:
            return

        save_threat(cfg.DB_PATH, parsed)

        # Console output
        sev_color = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        reset = "\033[0m"
        color = sev_color.get(parsed.severity, "")
        print(f"\n{color}[{parsed.severity}]{reset} @{channel} | {timestamp}")
        for ioc_type, vals in parsed.iocs.items():
            print(f"  {ioc_type.upper()}: {', '.join(vals[:3])}{'...' if len(vals) > 3 else ''}")
        if parsed.watchlist_hits:
            print(f"  \033[91m[WATCHLIST HIT]\033[0m {parsed.watchlist_hits}")

        # Optional VirusTotal enrichment
        if cfg.VT_API_KEY:
            for ioc_type in ("sha256", "md5", "ipv4", "domain"):
                for ioc_val in parsed.iocs.get(ioc_type, [])[:2]:  # Max 2 per type
                    result = vt.lookup(ioc_val, ioc_type, cfg.VT_API_KEY)
                    if result:
                        save_vt_result(cfg.DB_PATH, ioc_val, ioc_type, result)
                        if vt.is_malicious(result):
                            print(f"  \033[91m[VT MALICIOUS]\033[0m {ioc_val} — {result.get('malicious')} engines")

    logger.info("[*] Listening for new messages. Press Ctrl+C to stop.")
    await client.run_until_disconnected()
