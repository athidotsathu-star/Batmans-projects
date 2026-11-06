"""Self-contained HTML investigation report rendering."""
from __future__ import annotations
from datetime import datetime, timezone
from html import escape
def build_html(title: str, summary: dict, details: list, notes: str="") -> str:
    rows="".join("<tr><th>"+escape(str(k))+"</th><td>"+escape(str(v))+"</td></tr>" for k,v in summary.items())
    cards=[]
    for i,item in enumerate(details,1):
        body="".join("<p><b>"+escape(str(k))+"</b>: "+escape(str(v))+"</p>" for k,v in item.items())
        cards.append(f'<article><h3>Evidence {i}</h3>{body}</article>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{escape(title)}</title>
<style>body{{font:15px system-ui;background:#0b1018;color:#e9eef5;margin:0;padding:32px}}main{{max-width:1000px;margin:auto}}header,section,article{{background:#131d29;border:1px solid #334154;border-radius:12px;padding:22px;margin:16px 0}}h1,h2{{color:#f2c230}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #344153}}th{{width:32%;color:#c7d2df}}p{{overflow-wrap:anywhere;color:#d0d9e4}}small{{color:#93a2b5}}.notice{{border-left:4px solid #f2c230;padding:12px;background:#201a0c}}</style></head>
<body><main><header><small>BATCOMPUTER / BATMAN BUG HUNTER X</small><h1>{escape(title)}</h1><small>Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</small></header>
<section><h2>Executive summary</h2><table>{rows}</table></section><section><h2>Evidence and findings</h2>{''.join(cards) or '<p>No evidence items recorded.</p>'}</section>
<section><h2>Analyst notes</h2><p>{escape(notes) or 'No analyst notes supplied.'}</p><p class="notice">Automated observations are not proof of compromise. Validate findings, preserve original evidence and follow written authorization.</p></section></main></body></html>"""
