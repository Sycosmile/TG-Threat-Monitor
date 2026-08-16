# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Entry Point
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import asyncio
import logging
import argparse
import sys
import os

import config
from core.database import init_db, fetch_stats
from core.reporter import generate as generate_report
from core.monitor import start as start_monitor


def setup_logging(log_path: str):
    dirpath = os.path.dirname(log_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(sys.stdout),
        ],
    )


def banner():
    print("""
 ╔══════════════════════════════════════════════╗
 ║   TG Threat Intel Monitor  v1.0              ║
 ║   Author : Sycosmile                         ║
 ║   Use for authorized research only           ║
 ╚══════════════════════════════════════════════╝
 """)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Telegram Threat Intelligence Monitor",
    )
    subparsers = parser.add_subparsers(dest="command")

    # monitor command
    subparsers.add_parser(
        "monitor", help="Start monitoring configured Telegram channels"
    )

    # report command
    rp = subparsers.add_parser(
        "report", help="Generate HTML threat report from logged data"
    )
    rp.add_argument(
        "--output",
        default=config.REPORT_PATH,
        help="Output HTML file path",
    )

    # stats command
    subparsers.add_parser("stats", help="Print summary statistics from the database")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Validate credentials for monitor command
    if args.command == "monitor":
        if not config.API_ID or not config.API_HASH:
            print("[!] ERROR: API_ID and API_HASH are not set in config.py")
            print("    Get them from https://my.telegram.org")
            sys.exit(1)
        if not config.TARGET_CHANNELS:
            print("[!] ERROR: No TARGET_CHANNELS defined in config.py")
            sys.exit(1)

    setup_logging(config.LOG_PATH)
    init_db(config.DB_PATH)

    if args.command == "monitor":
        print(f"[*] Monitoring {len(config.TARGET_CHANNELS)} channel(s)...")
        print(f"[*] Database → {config.DB_PATH}")
        if config.VT_API_KEY:
            print("[*] VirusTotal enrichment: ENABLED")
        else:
            print("[*] VirusTotal enrichment: DISABLED (no API key set)")
        print("[*] Press Ctrl+C to stop.\n")
        asyncio.run(start_monitor(config))

    elif args.command == "report":
        output = getattr(args, "output", config.REPORT_PATH)
        generate_report(config.DB_PATH, output)

    elif args.command == "stats":
        stats = fetch_stats(config.DB_PATH)
        print("\n── Threat Intel Stats ──────────────")
        print(f"  Total logged   : {stats.get('TOTAL', 0)}")
        print(f"  HIGH severity  : {stats.get('HIGH', 0)}")
        print(f"  MEDIUM severity: {stats.get('MEDIUM', 0)}")
        print(f"  LOW severity   : {stats.get('LOW', 0)}")
        print(f"  Channels seen  : {stats.get('CHANNELS', 0)}")
        print("────────────────────────────────────\n")


if __name__ == "__main__":
    main()
