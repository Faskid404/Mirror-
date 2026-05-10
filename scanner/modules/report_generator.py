#!/usr/bin/env python3
"""
Report Generator — builds a rich, downloadable HTML report from all scan JSON files.

Usage:
    python report_generator.py [target_label]

Reads:  reports/*.json
Writes: reports/report.html   (self-contained, no external dependencies)
"""
import json
import time
import sys
import os
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}
SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#eff6ff",
    "INFO":     "#f9fafb",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Mirror Security Scan Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0f172a;color:#e2e8f0;min-height:100vh}}
.topbar{{background:#1e293b;border-bottom:1px solid #334155;padding:18px 32px;
         display:flex;align-items:center;justify-content:space-between}}
.topbar h1{{font-size:1.4rem;font-weight:700;color:#f8fafc;letter-spacing:-0.5px}}
.topbar .meta{{font-size:.8rem;color:#94a3b8}}
.content{{max-width:1200px;margin:0 auto;padding:32px 24px}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
               gap:16px;margin-bottom:32px}}
.scard{{background:#1e293b;border:1px solid #334155;border-radius:12px;
        padding:20px;text-align:center}}
.scard .count{{font-size:2.4rem;font-weight:800;line-height:1}}
.scard .label{{font-size:.75rem;color:#94a3b8;margin-top:6px;text-transform:uppercase;
               letter-spacing:.5px}}
.scard.critical .count{{color:#dc2626}}
.scard.high     .count{{color:#ea580c}}
.scard.medium   .count{{color:#d97706}}
.scard.low      .count{{color:#2563eb}}
.scard.info     .count{{color:#6b7280}}
.scard.total    .count{{color:#f8fafc}}
.controls{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;align-items:center}}
.controls input{{background:#1e293b;border:1px solid #334155;border-radius:8px;
                 padding:8px 14px;color:#e2e8f0;font-size:.9rem;width:260px;outline:none}}
.controls input::placeholder{{color:#64748b}}
.controls input:focus{{border-color:#3b82f6}}
.filter-btns{{display:flex;gap:8px;flex-wrap:wrap}}
.fbtn{{border:1px solid #334155;background:#1e293b;color:#94a3b8;border-radius:6px;
       padding:6px 14px;cursor:pointer;font-size:.8rem;transition:all .15s}}
.fbtn:hover,.fbtn.active{{background:#334155;color:#f8fafc}}
.fbtn.active{{border-color:#3b82f6}}
.section-title{{font-size:1.1rem;font-weight:600;color:#f1f5f9;
                margin:28px 0 12px;display:flex;align-items:center;gap:8px}}
.section-title .badge{{background:#334155;color:#94a3b8;border-radius:4px;
                       padding:2px 8px;font-size:.7rem;font-weight:500}}
.chain-card{{background:#1e293b;border:1px solid #7c3aed;border-radius:10px;
             padding:16px 20px;margin-bottom:12px}}
.chain-card .chain-name{{font-weight:700;color:#a78bfa;margin-bottom:6px}}
.chain-card .chain-cves{{font-size:.85rem;color:#94a3b8}}
.finding{{background:#1e293b;border:1px solid #334155;border-radius:10px;
          margin-bottom:10px;overflow:hidden;transition:border-color .15s}}
.finding:hover{{border-color:#475569}}
.finding-header{{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer}}
.sev-badge{{border-radius:5px;padding:3px 10px;font-size:.72rem;font-weight:700;
            text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}}
.finding-title{{font-weight:600;font-size:.9rem;flex:1;color:#f1f5f9}}
.finding-url{{font-size:.75rem;color:#64748b;text-align:right;max-width:300px;
              overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.conf-pill{{background:#0f172a;border-radius:20px;padding:2px 8px;font-size:.7rem;
            color:#64748b;white-space:nowrap}}
.finding-body{{display:none;padding:0 18px 14px;border-top:1px solid #1e293b}}
.finding-body.open{{display:block;border-top-color:#334155}}
.finding-body table{{width:100%;border-collapse:collapse;margin-top:10px;font-size:.82rem}}
.finding-body td{{padding:5px 10px;border:1px solid #334155;vertical-align:top}}
.finding-body td:first-child{{color:#94a3b8;width:130px;white-space:nowrap}}
.finding-body td:last-child{{color:#e2e8f0;word-break:break-all}}
.rem{{background:#0f172a;border-left:3px solid #3b82f6;padding:10px 14px;
      border-radius:0 6px 6px 0;margin-top:10px;font-size:.82rem;color:#93c5fd}}
.empty{{text-align:center;color:#475569;padding:48px 24px;font-size:.95rem}}
.download-bar{{display:flex;justify-content:flex-end;margin-bottom:16px}}
.dl-btn{{background:#2563eb;color:#fff;border:none;border-radius:8px;
         padding:9px 20px;cursor:pointer;font-size:.85rem;font-weight:600}}
.dl-btn:hover{{background:#1d4ed8}}
@media print{{body{{background:#fff;color:#000}}
  .topbar,.controls,.download-bar{{display:none}}
  .finding-body{{display:block!important}}}}
</style>
</head>
<body>
<div class="topbar">
  <h1>&#x1F6E1; Mirror Security Scan Report</h1>
  <div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {generated}</div>
</div>
<div class="content">
  <div class="download-bar">
    <button class="dl-btn" onclick="window.print()">&#x1F5A8; Print / Save PDF</button>
  </div>

  <!-- Summary cards -->
  <div class="summary-grid">
    <div class="scard total"><div class="count">{total}</div><div class="label">Total Findings</div></div>
    <div class="scard critical"><div class="count">{cnt_critical}</div><div class="label">Critical</div></div>
    <div class="scard high"><div class="count">{cnt_high}</div><div class="label">High</div></div>
    <div class="scard medium"><div class="count">{cnt_medium}</div><div class="label">Medium</div></div>
    <div class="scard low"><div class="count">{cnt_low}</div><div class="label">Low</div></div>
    <div class="scard info"><div class="count">{cnt_info}</div><div class="label">Info</div></div>
  </div>

  <!-- Controls -->
  <div class="controls">
    <input id="search" placeholder="Search findings..." oninput="applyFilters()"/>
    <div class="filter-btns">
      <button class="fbtn active" data-sev="ALL" onclick="setSev(this)">All</button>
      <button class="fbtn" data-sev="CRITICAL" onclick="setSev(this)" style="color:#dc2626">Critical</button>
      <button class="fbtn" data-sev="HIGH"     onclick="setSev(this)" style="color:#ea580c">High</button>
      <button class="fbtn" data-sev="MEDIUM"   onclick="setSev(this)" style="color:#d97706">Medium</button>
      <button class="fbtn" data-sev="LOW"      onclick="setSev(this)" style="color:#2563eb">Low</button>
      <button class="fbtn" data-sev="INFO"     onclick="setSev(this)" style="color:#6b7280">Info</button>
    </div>
  </div>

  <!-- Attack chains -->
  {chains_section}

  <!-- Findings -->
  <div class="section-title">Findings <span class="badge" id="shown-count">{total} shown</span></div>
  <div id="findings-list">
    {findings_html}
  </div>
  <div class="empty" id="empty-msg" style="display:none">No findings match your filter.</div>
</div>

<script>
let activeSev = 'ALL';

function setSev(btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeSev = btn.dataset.sev;
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  const cards = document.querySelectorAll('.finding');
  let shown = 0;
  cards.forEach(card => {{
    const sev = card.dataset.sev;
    const text = card.textContent.toLowerCase();
    const sevOk = activeSev === 'ALL' || sev === activeSev;
    const qOk = !q || text.includes(q);
    card.style.display = sevOk && qOk ? '' : 'none';
    if (sevOk && qOk) shown++;
  }});
  document.getElementById('shown-count').textContent = shown + ' shown';
  document.getElementById('empty-msg').style.display = shown === 0 ? '' : 'none';
}}

function toggleBody(el) {{
  const body = el.nextElementSibling;
  if (body && body.classList.contains('finding-body')) {{
    body.classList.toggle('open');
  }}
}}
</script>
</body>
</html>"""


def sev_badge(sev):
    color = SEV_COLOR.get(sev, "#6b7280")
    bg    = SEV_BG.get(sev, "#f9fafb")
    return (f'<span class="sev-badge" '
            f'style="background:{bg};color:{color}">{sev}</span>')


def finding_card(f, idx):
    sev   = f.get('severity', 'INFO')
    title = f.get('name') or f.get('type', 'Unknown')
    url   = f.get('url', f.get('endpoint', ''))
    conf  = f.get('confidence', 0)
    cl    = f.get('confidence_label', '')

    rows = []
    skip = {'severity', 'confidence_label', 'name', 'type'}
    for k, v in f.items():
        if k in skip or v is None or v == '':
            continue
        if k == 'remediation':
            continue
        rows.append(f"<tr><td>{k}</td><td>{str(v)[:400]}</td></tr>")

    rem = f.get('remediation', '')
    rem_html = f'<div class="rem">&#128274; <strong>Remediation:</strong> {rem}</div>' if rem else ''

    return f"""
<div class="finding" data-sev="{sev}" id="f{idx}">
  <div class="finding-header" onclick="toggleBody(this)">
    {sev_badge(sev)}
    <span class="finding-title">{title}</span>
    <span class="conf-pill">{conf}% {cl}</span>
    <span class="finding-url" title="{url}">{url}</span>
  </div>
  <div class="finding-body">
    <table>{''.join(rows)}</table>
    {rem_html}
  </div>
</div>"""


def build_report(target_label="(unknown)"):
    all_findings = []
    chains       = []

    if not REPORTS_DIR.exists():
        print("[!] No reports directory found.")
        return

    for jf in sorted(REPORTS_DIR.glob("*.json")):
        if jf.name.startswith("_"):
            continue
        try:
            data = json.loads(jf.read_text())
            if isinstance(data, list):
                all_findings.extend(data)
            elif isinstance(data, dict):
                all_findings.extend(data.get('findings', []))
                chains.extend(data.get('chains', []))
        except Exception as e:
            print(f"  [warn] Could not read {jf.name}: {e}")

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get('severity', 'INFO'), 5))

    cnt = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in all_findings:
        cnt[f.get('severity', 'INFO')] = cnt.get(f.get('severity', 'INFO'), 0) + 1

    # Chains section
    chains_html = ""
    if chains:
        inner = "".join(
            f'<div class="chain-card"><div class="chain-name">&#9888; {c["name"]}</div>'
            f'<div class="chain-cves">{c["detail"]}</div></div>'
            for c in chains
        )
        chains_html = f'<div class="section-title">Attack Chains</div>{inner}'

    # Findings HTML
    if all_findings:
        findings_html = "".join(finding_card(f, i) for i, f in enumerate(all_findings))
    else:
        findings_html = '<div class="empty">No findings recorded.</div>'

    generated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    html = HTML_TEMPLATE.format(
        target=target_label,
        generated=generated,
        total=len(all_findings),
        cnt_critical=cnt["CRITICAL"],
        cnt_high=cnt["HIGH"],
        cnt_medium=cnt["MEDIUM"],
        cnt_low=cnt["LOW"],
        cnt_info=cnt["INFO"],
        chains_section=chains_html,
        findings_html=findings_html,
    )

    out = REPORTS_DIR / "report.html"
    out.write_text(html, encoding='utf-8')
    print(f"[+] Report written to {out}  ({len(all_findings)} findings, {len(chains)} chains)")
    return out


if __name__ == "__main__":
    target_label = sys.argv[1] if len(sys.argv) > 1 else "(unknown target)"
    build_report(target_label)
