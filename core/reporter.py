# ─────────────────────────────────────────────
#  TG Threat Intel Monitor — Report Generator
#  Author: Sycosmile (https://github.com/Sycosmile)
# ─────────────────────────────────────────────
"""Generates a static HTML threat intelligence report from the database."""

import json
import os
import html as html_lib
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
            ioc_lines += (
                f'<span class="tag">{html_lib.escape(ioc_type.upper())}</span> '
            )
            ioc_lines += ", ".join(
                f"<code>{html_lib.escape(str(v))}</code>" for v in vals[:4]
            )
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
            wl_text = ", ".join(html_lib.escape(str(w)) for w in watchlist)
            watchlist_badge = (
                f'<span class="watchlist-badge">⚠ WATCHLIST: {wl_text}</span>'
            )

        rows_html += (
            "        <tr>\n"
            f'          <td><span class="sev {sev_class}">'
            f"{html_lib.escape(sev)}</span></td>\n"
            f"          <td>@{html_lib.escape(str(r.get('channel', '')))}"
            "</td>\n"
            f"          <td>{html_lib.escape(str(r.get('timestamp', '')))}"
            "</td>\n"
            f"          <td>{ioc_lines}{watchlist_badge}</td>\n"
            '          <td class="raw-text">'
            f"{html_lib.escape(str(r.get('raw_text', ''))[:200])}...</td>\n"
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

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TG Threat Intel Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', sans-serif;
      background: #f4f5f7;
      color: #2d3748;
      padding: 2rem;
    }}
    header {{
      background: #1a202c;
      color: #fff;
      padding: 1.5rem 2rem;
      border-radius: 8px;
      margin-bottom: 1.5rem;
    }}
    header h1 {{
      font-size: 1.4rem; font-weight: 600; letter-spacing: 0.05em;
    }}
    header p  {{ font-size: 0.8rem; color: #a0aec0; margin-top: 0.3rem; }}
    .stats {{
      display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap;
    }}
    .stat-card {{
      background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
      flex: 1; min-width: 120px; border-left: 4px solid #cbd5e0;
    }}
    .stat-card.high  {{ border-color: #e53e3e; }}
    .stat-card.med   {{ border-color: #dd6b20; }}
    .stat-card.low   {{ border-color: #3182ce; }}
    .stat-card .num  {{ font-size: 2rem; font-weight: 700; }}
    .stat-card .lbl  {{
      font-size: 0.75rem; color: #718096; text-transform: uppercase;
    }}
    table {{
      width: 100%; border-collapse: collapse; background: #fff;
      border-radius: 8px; overflow: hidden;
    }}
    th {{
      background: #2d3748; color: #fff; text-align: left;
      padding: 0.75rem 1rem; font-size: 0.8rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    td {{
      padding: 0.75rem 1rem; border-bottom: 1px solid #edf2f7;
      font-size: 0.85rem; vertical-align: top;
    }}
    tr:hover td {{ background: #f7fafc; }}
    .sev {{
      display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
      font-size: 0.75rem; font-weight: 600;
    }}
    .sev-high {{ background: #fff5f5; color: #c53030; }}
    .sev-med  {{ background: #fffaf0; color: #c05621; }}
    .sev-low  {{ background: #ebf8ff; color: #2b6cb0; }}
    .tag {{
      background: #e2e8f0; color: #4a5568; border-radius: 3px;
      padding: 0.1rem 0.4rem; font-size: 0.7rem; font-weight: 600;
      margin-right: 0.3rem;
    }}
    code {{ font-family: monospace; font-size: 0.8rem; color: #553c9a; }}
    .watchlist-badge {{
      display: inline-block; margin-top: 0.4rem; background: #fff5f5;
      color: #c53030; border: 1px solid #fed7d7; border-radius: 4px;
      padding: 0.2rem 0.5rem; font-size: 0.75rem;
    }}
    .raw-text {{
      color: #718096; font-size: 0.78rem; max-width: 300px;
      word-break: break-word;
    }}
    footer {{
      text-align: center; margin-top: 2rem; color: #a0aec0;
      font-size: 0.75rem;
    }}
  </style>
</head>
<body>
<header>
  <h1>🛡 Telegram Threat Intelligence Report</h1>
  <p>Generated: {generated_at} &nbsp;|&nbsp;
     Total Events: {stats.get('TOTAL', 0)} &nbsp;|&nbsp;
     Channels Monitored: {stats.get('CHANNELS', 0)}</p>
</header>

<div class="stats">
  <div class="stat-card high">
    <div class="num">{stats.get('HIGH', 0)}</div>
    <div class="lbl">High Severity</div>
  </div>
  <div class="stat-card med">
    <div class="num">{stats.get('MEDIUM', 0)}</div>
    <div class="lbl">Medium Severity</div>
  </div>
  <div class="stat-card low">
    <div class="num">{stats.get('LOW', 0)}</div>
    <div class="lbl">Low Severity</div>
  </div>
  <div class="stat-card">
    <div class="num">{stats.get('TOTAL', 0)}</div>
    <div class="lbl">Total Logged</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Channel</th>
      <th>Timestamp</th>
      <th>IOCs Detected</th>
      <th>Message Preview</th>
    </tr>
  </thead>
  <tbody>
    {body_rows}
  </tbody>
</table>

{footer_line}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report saved → {output_path}")
