# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Report Generator
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────

import json
import os
from datetime import datetime
from core.database import fetch_all, fetch_stats


def generate(db_path: str, output_path: str):
    """Generate a clean HTML threat intelligence report."""
    dirpath = os.path.dirname(output_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)

    rows = fetch_all(db_path)
    stats = fetch_stats(db_path)
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    rows_html = ""
    for r in rows:
        iocs = json.loads(r.get("iocs") or "{}")
        watchlist = json.loads(r.get("watchlist") or "[]")
        ioc_lines = ""
        for ioc_type, vals in iocs.items():
            ioc_lines += f'<span class="tag">{ioc_type.upper()}</span> '
            ioc_lines += ", ".join(f"<code>{v}</code>" for v in vals[:4])
            if len(vals) > 4:
                ioc_lines += f" <em>+{len(vals)-4} more</em>"
            ioc_lines += "<br>"

        sev = r.get("severity", "LOW")
        sev_class = {
            "HIGH": "sev-high",
            "MEDIUM": "sev-med",
            "LOW": "sev-low",
        }.get(sev, "sev-low")

        watchlist_badge = ""
        if watchlist:
            # keep this line under 79 chars
            wl_text = ", ".join(watchlist)
            watchlist_badge = (
                f'<span class="watchlist-badge">⚠ WATCHLIST: {wl_text}</span>'
            )

        rows_html += (
            "        <tr>\n"
            f"          <td><span class=\"sev {sev_class}\">{sev}</span></td>\n"
            f"          <td>@{r.get('channel', '')}</td>\n"
            f"          <td>{r.get('timestamp', '')}</td>\n"
            f"          <td>{ioc_lines}{watchlist_badge}</td>\n"
            f"          <td class=\"raw-text\">{r.get('raw_text', '')[:200]}...</td>\n"
            "        </tr>"
        )

    # Avoid extremely long lines in the large HTML template by building
    # the variable parts first and then interpolating them.
    body_rows = (
        rows_html
        if rows_html
        else (
            '<tr><td colspan="5" style="text-align:center;'
            'color:#a0aec0;padding:2rem;">No threats logged yet.'
            "</td></tr>"
        )
    )

    footer_line = (
        "<footer>"
        "TG Threat Intel Monitor &mdash; by Sycosmile "
        "(https://github.com/Sycosmile) &mdash; For authorized "
        "security research only"
        "</footer>"
    )

    html = (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width,"
        " initial-scale=1.0\">\n"
        "  <title>TG Threat Intel Report</title>\n"
        "  <style>\n"
        "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "    body {\n"
        "      font-family: 'Segoe UI', sans-serif;\n"
        "      background: #f4f5f7;\n"
        "      color: #2d3748;\n"
        "      padding: 2rem;\n"
        "    }\n"
        "    header {\n"
        "      background: #1a202c;\n"
        "      color: #fff;\n"
        "      padding: 1.5rem 2rem;\n"
        "      border-radius: 8px;\n"
        "      margin-bottom: 1.5rem;\n"
        "    }\n"
        "    header h1 { font-size: 1.4rem; font-weight: 600; "
        "letter-spacing: 0.05em; }\n"
        "    header p  { font-size: 0.8rem; color: #a0aec0; "
        "margin-top: 0.3rem; }\n"
        "    .stats { display: flex; gap: 1rem; margin-bottom: 1.5rem; "
        "flex-wrap: wrap; }\n"
        "    .stat-card { background: #fff; border-radius: 8px; "
        "padding: 1rem 1.5rem; flex: 1; min-width: 120px; "
        "border-left: 4px solid #cbd5e0; }\n"
        "    .stat-card.high  { border-color: #e53e3e; }\n"
        "    .stat-card.med   { border-color: #dd6b20; }\n"
        "    .stat-card.low   { border-color: #3182ce; }\n"
        "    .stat-card .num  { font-size: 2rem; font-weight: 700; }\n"
        "    .stat-card .lbl  { font-size: 0.75rem; color: #718096; "
        "text-transform: uppercase; }\n"
        "    table { width: 100%; border-collapse: collapse; "
        "background: #fff; border-radius: 8px; overflow: hidden; }\n"
        "    th { background: #2d3748; color: #fff; text-align: left; "
        "padding: 0.75rem 1rem; font-size: 0.8rem; text-transform: "
        "uppercase; letter-spacing: 0.05em; }\n"
        "    td { padding: 0.75rem 1rem; border-bottom: 1px solid #edf2f7; "
        "font-size: 0.85rem; vertical-align: top; }\n"
        "    tr:hover td { background: #f7fafc; }\n"
        "    .sev { display: inline-block; padding: 0.2rem 0.6rem; "
        "border-radius: 4px; font-size: 0.75rem; font-weight: 600; }\n"
        "    .sev-high { background: #fff5f5; color: #c53030; }\n"
        "    .sev-med  { background: #fffaf0; color: #c05621; }\n"
        "    .sev-low  { background: #ebf8ff; color: #2b6cb0; }\n"
        "    .tag { background: #e2e8f0; color: #4a5568; border-radius: 3px; "
        "padding: 0.1rem 0.4rem; font-size: 0.7rem; font-weight: 600; "
        "margin-right: 0.3rem; }\n"
        "    code { font-family: monospace; font-size: 0.8rem; color: #553c9a; }\n"
        "    .watchlist-badge { display: inline-block; margin-top: 0.4rem; "
        "background: #fff5f5; color: #c53030; border: 1px solid #fed7d7; "
        "border-radius: 4px; padding: 0.2rem 0.5rem; font-size: 0.75rem; }\n"
        "    .raw-text { color: #718096; font-size: 0.78rem; max-width: 300px; "
        "word-break: break-word; }\n"
        "    footer { text-align: center; margin-top: 2rem; color: #a0aec0; "
        "font-size: 0.75rem; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        "  <h1>🛡 Telegram Threat Intelligence Report</h1>\n"
        f"  <p>Generated: {generated_at} &nbsp;|&nbsp; Total Events: "
        f"{stats.get('TOTAL', 0)} &nbsp;|&nbsp; Channels Monitored: "
        f"{stats.get('CHANNELS', 0)}</p>\n"
        "</header>\n"
        "\n"
        "<div class=\"stats\">\n"
        "  <div class=\"stat-card high\"><div class=\"num\">"
        f"{stats.get('HIGH', 0)}</div><div class=\"lbl\">High Severity</div>"
        "</div>\n"
        "  <div class=\"stat-card med\"> <div class=\"num\">"
        f"{stats.get('MEDIUM', 0)}</div><div class=\"lbl\">Medium Severity</div>"
        "</div>\n"
        "  <div class=\"stat-card low\"> <div class=\"num\">"
        f"{stats.get('LOW', 0)}</div><div class=\"lbl\">Low Severity</div>"
        "</div>\n"
        "  <div class=\"stat-card\">     <div class=\"num\">"
        f"{stats.get('TOTAL', 0)}</div><div class=\"lbl\">Total Logged</div>"
        "</div>\n"
        "</div>\n"
        "\n"
        "<table>\n"
        "  <thead>\n"
        "    <tr>\n"
        "      <th>Severity</th>\n"
        "      <th>Channel</th>\n"
        "      <th>Timestamp</th>\n"
        "      <th>IOCs Detected</th>\n"
        "      <th>Message Preview</th>\n"
        "    </tr>\n"
        "  </thead>\n"
        "  <tbody>\n"
        f"    {body_rows}\n"
        "  </tbody>\n"
        "</table>\n"
        "\n"
        f"{footer_line}\n"
        "</body>\n"
        "</html>"
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report saved → {output_path}")
