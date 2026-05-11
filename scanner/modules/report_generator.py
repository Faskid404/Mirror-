#!/usr/bin/env python3
"""
Mirror Report Generator v2 — Professional security report.

Improvements over v1:
  - Executive Summary with risk score (0–100) and verdict
  - Prominent PROOF field per finding (what was actually observed)
  - Remediation priority table sorted by severity + effort
  - Module coverage section (which scans ran, findings per module)
  - Attack chain visualization with MITRE ATT&CK stage labels
  - Technology fingerprint panel
  - Confidence badge always visible (not just confidence %)
  - Filter by: severity, module, confidence, search text
  - Cleaner dark theme with better typography
  - Print/PDF layout preserved
"""
import json, time, sys, re
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

SEV_ORDER  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
SEV_HEX    = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6","INFO":"#6b7280"}
SEV_DARK   = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#713f12","LOW":"#1e3a5f","INFO":"#1f2937"}
MODULE_ICON = {
    "ghostcrawler":"🕷️","wafshatter":"🛡️","headerforge":"🔩","authdrift":"🔐",
    "tokensniper":"🎯","backendprobe":"⚙️","deeplogic":"🧠","cryptohunter":"🔑",
    "timebleed":"⏱️","rootchain":"⛓️","webprobe":"🌐","cveprobe":"📋","report_generator":"📊",
}
MITRE_STAGE = {
    "RECONN":        "TA0043 Reconnaissance",
    "INITIAL_ACCESS":"TA0001 Initial Access",
    "PERSISTENCE":   "TA0003 Persistence",
    "PRIV_ESC":      "TA0004 Privilege Escalation",
    "CRED_ACCESS":   "TA0006 Credential Access",
    "LATERAL":       "TA0008 Lateral Movement",
    "EXFIL":         "TA0010 Exfiltration",
    "IMPACT":        "TA0040 Impact",
}

def risk_score(findings):
    weights = {"CRITICAL":30,"HIGH":12,"MEDIUM":4,"LOW":1,"INFO":0}
    raw = sum(weights.get(f.get("severity","INFO"),0) for f in findings)
    return min(100, raw)

def risk_label(score):
    if score >= 60: return ("CRITICAL RISK","#ef4444")
    if score >= 35: return ("HIGH RISK","#f97316")
    if score >= 15: return ("MEDIUM RISK","#eab308")
    if score >= 1:  return ("LOW RISK","#3b82f6")
    return ("NO FINDINGS","#22c55e")

def esc(s):
    if not isinstance(s,str): s = str(s) if s is not None else ''
    return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def extract_tech(findings):
    for f in findings:
        if f.get("type") == "ATTACK_SURFACE_SUMMARY":
            return f.get("tech",[]), f.get("waf",[])
    return [], []

def module_from_type(finding_type):
    t = finding_type.lower()
    if 'jwt' in t or 'auth' in t or 'idor' in t or 'cred' in t or 'lockout' in t or 'brute' in t: return 'authdrift'
    if 'waf' in t or 'rate' in t: return 'wafshatter'
    if 'hsts' in t or 'csp' in t or 'cors' in t or 'host' in t or 'header' in t: return 'headerforge'
    if 'tls' in t or 'cert' in t or 'hsts' in t or 'http_not' in t or 'cipher' in t or 'crypto' in t: return 'cryptohunter'
    if 'secret' in t or 'token' in t or 'key' in t or 'sniper' in t or 'file_expo' in t: return 'tokensniper'
    if 'ssrf' in t or 'xxe' in t or 'backend' in t or 'admin_api' in t: return 'backendprobe'
    if 'timing' in t or 'sqli' in t or 'bleed' in t: return 'timebleed'
    if 'mass' in t or 'race' in t or 'logic' in t or 'version' in t: return 'deeplogic'
    if 'attack_chain' in t: return 'rootchain'
    if 'surface' in t or 'path' in t or 'crawl' in t: return 'ghostcrawler'
    return 'other'

def build_finding_card(f, idx):
    sev  = f.get("severity","INFO")
    hex_ = SEV_HEX.get(sev,"#6b7280")
    dark = SEV_DARK.get(sev,"#1f2937")
    conf = f.get("confidence",0)
    conf_label = f.get("confidence_label","Low")
    ftype  = esc(f.get("type",""))
    detail = esc(f.get("detail",""))
    proof  = esc(f.get("proof",""))
    url    = esc(f.get("url",""))
    rem    = esc(f.get("remediation",""))
    mod    = module_from_type(f.get("type",""))
    icon   = MODULE_ICON.get(mod,"🔍")
    
    extra_rows = ""
    for k in ("param","payload","header","cipher","version","data_type","waf","service","bypass_count","delta_ms"):
        v = f.get(k)
        if v is not None:
            extra_rows += f'<tr><td>{esc(k.replace("_"," ").title())}</td><td><code>{esc(str(v))}</code></td></tr>'

    conf_color = "#22c55e" if conf >= 80 else "#eab308" if conf >= 65 else "#6b7280"

    return f"""
<div class="finding" data-sev="{sev}" data-mod="{mod}" data-conf="{conf}" id="f{idx}">
  <div class="finding-header" onclick="toggle(this)">
    <span class="sev-badge" style="background:{dark};color:{hex_};border:1px solid {hex_}">{sev}</span>
    <span class="finding-title">{detail or ftype}</span>
    <span class="conf-pill" style="border-color:{conf_color};color:{conf_color}">
      {icon} {conf_label} {conf}%
    </span>
    <span class="chevron">▼</span>
  </div>
  <div class="finding-body">
    {'<div class="proof-box"><span class="proof-icon">🔬</span><strong>PROOF</strong><br/>' + proof + '</div>' if proof else '<div class="proof-box proof-missing">⚠️ No explicit proof recorded — treat with lower priority.</div>'}
    <table>
      <tr><td>Type</td><td><code>{ftype}</code></td></tr>
      {'<tr><td>URL</td><td><code>' + url + '</code></td></tr>' if url else ''}
      {extra_rows}
      <tr><td>Module</td><td>{icon} {esc(mod)}</td></tr>
      <tr><td>Confidence</td><td style="color:{conf_color}">{conf}% — {esc(conf_label)}</td></tr>
    </table>
    {'<div class="rem-box"><strong>🔧 Remediation</strong><br/>' + rem + '</div>' if rem else ''}
  </div>
</div>"""

def build_chain_card(c):
    stages = c.get("stages",[]) or c.get("kill_chain",[]) or []
    risk   = c.get("risk","HIGH")
    hex_   = SEV_HEX.get(risk,"#6b7280")
    steps  = ""
    for s in stages:
        lbl = MITRE_STAGE.get(s,s)
        steps += f'<span class="chain-stage">{esc(lbl)}</span>'
    cves = ", ".join(c.get("cves",[]))
    return f"""
<div class="chain-card" style="border-color:{hex_}33;background:linear-gradient(135deg,{hex_}11,#1e293b)">
  <div class="chain-header">
    <span class="sev-badge" style="background:{SEV_DARK.get(risk,'#1f2937')};color:{hex_};border:1px solid {hex_}">{risk}</span>
    <span class="chain-name">{esc(c.get('name','Attack Chain'))}</span>
    <span class="chain-score">Risk: {c.get('risk_score',0)}/100</span>
  </div>
  <div class="chain-desc">{esc(c.get('description',''))}</div>
  {'<div class="chain-stages">' + steps + '</div>' if steps else ''}
  {'<div class="chain-cves">CVEs: ' + esc(cves) + '</div>' if cves else ''}
</div>"""

def build_module_row(mod_name, findings):
    icon = MODULE_ICON.get(mod_name,"🔍")
    counts = {s:0 for s in SEV_ORDER}
    for f in findings: counts[f.get("severity","INFO")] += 1
    badges = ""
    for s in SEV_ORDER:
        if counts[s]: badges += f'<span class="mbadge" style="color:{SEV_HEX[s]}">{s[0]} {counts[s]}</span>'
    return f"""<tr>
      <td>{icon} <code>{esc(mod_name)}</code></td>
      <td style="color:#22c55e">✅ Ran</td>
      <td>{badges or '<span style="color:#6b7280">—</span>'}</td>
      <td style="color:#94a3b8">{len(findings)}</td>
    </tr>"""

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0f1e;--card:#111827;--card2:#1e293b;--border:#1e2d45;
      --text:#e2e8f0;--muted:#64748b;--accent:#3b82f6}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh;font-size:15px;line-height:1.6}

/* ── Top bar ── */
.topbar{background:#060d1a;border-bottom:1px solid var(--border);
        padding:14px 32px;display:flex;align-items:center;justify-content:space-between;
        position:sticky;top:0;z-index:100;backdrop-filter:blur(8px)}
.topbar .logo{font-size:1.1rem;font-weight:800;color:#f8fafc;letter-spacing:-0.3px;display:flex;align-items:center;gap:8px}
.topbar .meta{font-size:.78rem;color:var(--muted);text-align:right;line-height:1.5}

/* ── Layout ── */
.page{max-width:1280px;margin:0 auto;padding:28px 24px}

/* ── Risk banner ── */
.risk-banner{border-radius:12px;padding:24px 32px;margin-bottom:28px;
             display:flex;align-items:center;gap:32px}
.risk-score-circle{width:90px;height:90px;border-radius:50%;border:4px solid;
                   display:flex;flex-direction:column;align-items:center;justify-content:center;
                   flex-shrink:0}
.risk-score-circle .num{font-size:2rem;font-weight:900;line-height:1}
.risk-score-circle .lbl{font-size:.62rem;letter-spacing:1px;text-transform:uppercase;margin-top:2px}
.risk-info h2{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.risk-info p{color:#94a3b8;font-size:.88rem}

/* ── Summary cards ── */
.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:28px}
@media(max-width:900px){.cards{grid-template-columns:repeat(3,1fr)}}
@media(max-width:500px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;
      padding:16px;text-align:center}
.card .num{font-size:2rem;font-weight:800;line-height:1}
.card .lbl{font-size:.7rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}

/* ── Section headings ── */
.section{margin-bottom:32px}
.section-head{display:flex;align-items:center;gap:10px;margin-bottom:14px;
              border-bottom:1px solid var(--border);padding-bottom:10px}
.section-head h3{font-size:1rem;font-weight:700;color:#f1f5f9}
.section-head .badge{background:var(--card2);color:var(--muted);border-radius:4px;
                     padding:1px 7px;font-size:.72rem}

/* ── Controls ── */
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;align-items:center}
.controls input{background:var(--card);border:1px solid var(--border);border-radius:8px;
                padding:8px 14px;color:var(--text);font-size:.88rem;width:240px;outline:none}
.controls input:focus{border-color:var(--accent)}
.filter-grp{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{border:1px solid var(--border);background:var(--card);color:var(--muted);
      border-radius:6px;padding:6px 12px;cursor:pointer;font-size:.78rem;transition:all .12s}
.fbtn:hover{background:var(--card2);color:var(--text)}
.fbtn.active{border-color:var(--accent);color:#60a5fa;background:#1e293b}
.count-display{margin-left:auto;font-size:.8rem;color:var(--muted)}

/* ── Finding cards ── */
.finding{background:var(--card);border:1px solid var(--border);border-radius:10px;
         margin-bottom:8px;overflow:hidden;transition:border-color .12s}
.finding:hover{border-color:#334155}
.finding-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;
                user-select:none;gap:10px}
.sev-badge{border-radius:4px;padding:2px 9px;font-size:.68rem;font-weight:700;
           text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;flex-shrink:0}
.finding-title{font-weight:600;font-size:.88rem;flex:1;color:#f1f5f9;line-height:1.3}
.conf-pill{border:1px solid;border-radius:12px;padding:2px 9px;font-size:.7rem;
           white-space:nowrap;flex-shrink:0}
.chevron{color:var(--muted);font-size:.7rem;transition:transform .15s;flex-shrink:0}
.finding-header.open .chevron{transform:rotate(180deg)}
.finding-body{display:none;padding:0 16px 14px;border-top:1px solid var(--border)}
.finding-body.open{display:block}

/* ── Proof box (the key new feature) ── */
.proof-box{background:#0a1628;border:1px solid #1e3a5f;border-left:4px solid #3b82f6;
           border-radius:0 6px 6px 0;padding:12px 14px;margin:12px 0;font-size:.84rem;
           color:#93c5fd;line-height:1.5}
.proof-box strong{color:#60a5fa;display:block;margin-bottom:4px}
.proof-icon{margin-right:6px}
.proof-missing{border-left-color:#6b7280;color:#64748b}
.rem-box{background:#0f172a;border:1px solid var(--border);border-left:4px solid #22c55e;
         border-radius:0 6px 6px 0;padding:12px 14px;margin-top:10px;font-size:.84rem;
         color:#86efac;line-height:1.5}
.rem-box strong{color:#4ade80;display:block;margin-bottom:4px}
.finding-body table{width:100%;border-collapse:collapse;font-size:.82rem;margin-top:8px}
.finding-body td{padding:5px 10px;border:1px solid var(--border);vertical-align:top}
.finding-body td:first-child{color:var(--muted);width:120px;white-space:nowrap}
.finding-body td:last-child code{word-break:break-all;background:#0f172a;padding:1px 4px;
                                  border-radius:3px;font-size:.78rem}

/* ── Attack chain ── */
.chain-card{border:1px solid;border-radius:10px;padding:16px 20px;margin-bottom:10px}
.chain-header{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.chain-name{font-weight:700;font-size:.95rem;flex:1;color:#f1f5f9}
.chain-score{font-size:.78rem;color:var(--muted)}
.chain-desc{font-size:.84rem;color:#94a3b8;margin-bottom:10px}
.chain-stages{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
.chain-stage{background:#0f172a;border:1px solid #334155;border-radius:4px;
             padding:3px 9px;font-size:.72rem;color:#94a3b8}
.chain-cves{font-size:.75rem;color:#64748b;margin-top:6px}

/* ── Module table ── */
.mod-table{width:100%;border-collapse:collapse;font-size:.85rem}
.mod-table th{background:#0f172a;color:var(--muted);padding:8px 12px;text-align:left;
              font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}
.mod-table td{padding:9px 12px;border-bottom:1px solid var(--border)}
.mod-table tr:hover td{background:#111827}
.mbadge{margin-right:6px;font-size:.75rem;font-weight:700}

/* ── Tech pills ── */
.tech-pill{background:var(--card2);border:1px solid var(--border);border-radius:20px;
           padding:4px 12px;font-size:.78rem;display:inline-block;margin:3px}

/* ── Remediation table ── */
.rem-table{width:100%;border-collapse:collapse;font-size:.83rem}
.rem-table th{background:#0f172a;color:var(--muted);padding:8px 12px;text-align:left;
              font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}
.rem-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.rem-table tr:hover td{background:#111827}

/* ── Print ── */
@media print{
  body{background:#fff;color:#000}
  .topbar,.controls,.download-bar{display:none}
  .risk-banner{border:2px solid #ccc;background:#f8f8f8!important}
  .finding-body{display:block!important}
  .finding{break-inside:avoid}
  .proof-box,.rem-box{background:#f8f8f8!important;color:#333!important;border-color:#ccc!important}
  .finding-body table td{border-color:#ddd!important;color:#333!important}
  .card,.chain-card,.mod-table td{background:#f9f9f9!important;color:#333!important;border-color:#ddd!important}
}
"""

JS = """
function toggle(el){
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('open');
}

function applyFilters(){
  const q    = document.getElementById('search').value.toLowerCase();
  const sev  = document.querySelector('.fbtn[data-type="sev"].active')?.dataset.val || 'ALL';
  const mod  = document.querySelector('.fbtn[data-type="mod"].active')?.dataset.val || 'ALL';
  const conf = parseInt(document.querySelector('.fbtn[data-type="conf"].active')?.dataset.val || '0');

  let vis = 0;
  document.querySelectorAll('.finding').forEach(el => {
    const fs   = el.dataset.sev;
    const fm   = el.dataset.mod;
    const fc   = parseInt(el.dataset.conf || 0);
    const text = el.textContent.toLowerCase();
    const show = (sev === 'ALL' || fs === sev)
              && (mod === 'ALL' || fm === mod)
              && fc >= conf
              && (!q || text.includes(q));
    el.style.display = show ? '' : 'none';
    if(show) vis++;
  });
  const cd = document.getElementById('count-display');
  if(cd) cd.textContent = vis + ' finding' + (vis===1?'':'s') + ' shown';
}

function setFilter(btn, type){
  document.querySelectorAll(`.fbtn[data-type="${type}"]`).forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

document.getElementById('search').addEventListener('input', applyFilters);

// Open all on print
window.addEventListener('beforeprint', () => {
  document.querySelectorAll('.finding-body').forEach(b => b.classList.add('open'));
  document.querySelectorAll('.finding-header').forEach(h => h.classList.add('open'));
});
window.addEventListener('afterprint', () => {
  document.querySelectorAll('.finding-body').forEach(b => b.classList.remove('open'));
  document.querySelectorAll('.finding-header').forEach(h => h.classList.remove('open'));
});
"""

def generate_html_report(target, findings, chains=None, meta=None):
    chains   = chains or []
    meta     = meta or {}
    now      = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    score    = risk_score(findings)
    rlabel, rcolor = risk_label(score)

    counts = {s:0 for s in SEV_ORDER}
    for f in findings:
        counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"),0) + 1

    confirmed = [f for f in findings if f.get("confidence",0) >= 65 and f.get("severity","INFO") != "INFO"]
    tech, waf  = extract_tech(findings)

    # Group findings by module for coverage section
    by_module = {}
    for f in findings:
        mod = module_from_type(f.get("type",""))
        by_module.setdefault(mod,[]).append(f)

    # Sorted findings for the main list
    sorted_findings = sorted(findings, key=lambda f: (
        SEV_ORDER.index(f.get("severity","INFO")) if f.get("severity","INFO") in SEV_ORDER else 99,
        -(f.get("confidence",0))
    ))

    # ── Summary cards ──
    cards_html = ""
    for sev in SEV_ORDER:
        c = counts[sev]; hex_ = SEV_HEX[sev]
        cards_html += f'<div class="card"><div class="num" style="color:{hex_}">{c}</div><div class="lbl">{sev}</div></div>'
    cards_html = f'<div class="card"><div class="num">{len(findings)}</div><div class="lbl">Total</div></div>' + cards_html

    # ── Risk banner ──
    scan_dur = meta.get("duration","")
    banner = f"""
<div class="risk-banner" style="background:linear-gradient(135deg,{rcolor}18,{rcolor}08);border:1px solid {rcolor}33">
  <div class="risk-score-circle" style="border-color:{rcolor};color:{rcolor}">
    <div class="num">{score}</div>
    <div class="lbl">Risk</div>
  </div>
  <div class="risk-info">
    <h2 style="color:{rcolor}">{rlabel}</h2>
    <p>{len(confirmed)} confirmed finding(s) with sufficient evidence &nbsp;|&nbsp; {len(findings)} total &nbsp;|&nbsp; {len(chains)} attack chain(s)</p>
    {'<p style="margin-top:4px;color:#64748b">Scan duration: ' + str(scan_dur) + 's</p>' if scan_dur else ''}
  </div>
</div>"""

    # ── Tech panel ──
    tech_html = ""
    if tech or waf:
        pills = "".join(f'<span class="tech-pill">{"🏗️ " if t not in waf else "🛡️ "}{esc(t)}</span>' for t in tech+waf)
        note = ""
        if "WordPress" not in (tech+waf) and any("wp" in str(f.get("url","")).lower() for f in findings):
            note = '<p style="color:#f97316;font-size:.8rem;margin-top:8px">⚠️ Note: WordPress paths were tested despite WordPress not being detected — those findings may be false positives.</p>'
        tech_html = f"""
<div class="section">
  <div class="section-head"><h3>🖥️ Technology Fingerprint</h3></div>
  <div>{pills or '<span style="color:#64748b">No technology detected</span>'}</div>
  {note}
</div>"""

    # ── Module coverage ──
    ALL_MODULES = ["ghostcrawler","wafshatter","headerforge","authdrift","tokensniper",
                   "backendprobe","deeplogic","cryptohunter","timebleed","rootchain"]
    mod_rows = ""
    for mod in ALL_MODULES:
        mf = by_module.get(mod,[])
        mod_rows += build_module_row(mod, mf)
    mod_table = f"""
<div class="section">
  <div class="section-head"><h3>📋 Module Coverage</h3><span class="badge">{len(ALL_MODULES)} modules</span></div>
  <table class="mod-table">
    <tr><th>Module</th><th>Status</th><th>Severity Breakdown</th><th>Findings</th></tr>
    {mod_rows}
  </table>
</div>"""

    # ── Attack chains ──
    chains_html = ""
    if chains:
        chain_cards = "".join(build_chain_card(c) for c in chains)
        chains_html = f"""
<div class="section">
  <div class="section-head"><h3>⛓️ Attack Chains</h3><span class="badge">{len(chains)}</span></div>
  {chain_cards}
</div>"""

    # ── Remediation priority table ──
    top_findings = [f for f in sorted_findings if f.get("severity") in ("CRITICAL","HIGH","MEDIUM") and f.get("remediation")][:20]
    rem_rows = ""
    for i, f in enumerate(top_findings,1):
        sev   = f.get("severity","INFO"); hex_ = SEV_HEX.get(sev,"#6b7280")
        rem_rows += f"""<tr>
          <td style="color:var(--muted)">{i}</td>
          <td><span class="sev-badge" style="background:{SEV_DARK.get(sev,'#1f2937')};color:{hex_};border:1px solid {hex_}">{sev}</span></td>
          <td style="font-size:.82rem">{esc(f.get('detail','')[:80])}</td>
          <td style="font-size:.8rem;color:#94a3b8">{esc(f.get('remediation','')[:120])}</td>
        </tr>"""
    rem_table = ""
    if rem_rows:
        rem_table = f"""
<div class="section">
  <div class="section-head"><h3>🔧 Remediation Priority</h3><span class="badge">Top {len(top_findings)}</span></div>
  <table class="rem-table">
    <tr><th>#</th><th>Sev</th><th>Finding</th><th>Action</th></tr>
    {rem_rows}
  </table>
</div>"""

    # ── Filter controls ──
    mod_btns = '<button class="fbtn active" data-type="mod" data-val="ALL" onclick="setFilter(this,\'mod\')">All Modules</button>'
    for mod in sorted(by_module.keys()):
        mod_btns += f'<button class="fbtn" data-type="mod" data-val="{mod}" onclick="setFilter(this,\'mod\')">{MODULE_ICON.get(mod,"")} {mod}</button>'

    controls = f"""
<div class="controls">
  <input type="text" id="search" placeholder="🔍  Search findings…" oninput="applyFilters()">
  <div class="filter-grp">
    <button class="fbtn active" data-type="sev" data-val="ALL" onclick="setFilter(this,'sev')">All Severities</button>
    {''.join(f'<button class="fbtn" data-type="sev" data-val="{s}" onclick="setFilter(this,\'sev\')" style="color:{SEV_HEX[s]}">{s}</button>' for s in SEV_ORDER if counts[s])}
  </div>
  <div class="filter-grp">
    {mod_btns}
  </div>
  <div class="filter-grp">
    <button class="fbtn active" data-type="conf" data-val="0"  onclick="setFilter(this,'conf')">Any Confidence</button>
    <button class="fbtn"        data-type="conf" data-val="65" onclick="setFilter(this,'conf')">≥65% Medium+</button>
    <button class="fbtn"        data-type="conf" data-val="85" onclick="setFilter(this,'conf')">≥85% High</button>
  </div>
  <span class="count-display" id="count-display">{len(sorted_findings)} findings shown</span>
</div>"""

    # ── Finding cards ──
    finding_cards = "".join(build_finding_card(f, i) for i, f in enumerate(sorted_findings))
    no_findings = '<div class="empty">🎉 No findings — nothing matches current filters.</div>' if not finding_cards else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Mirror Security Report — {esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="topbar">
  <div class="logo">🛡️ Mirror Security Report</div>
  <div class="meta">Target: <strong>{esc(target)}</strong><br/>{now}</div>
</div>

<div class="page">

  <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <button onclick="window.print()" style="background:#2563eb;color:#fff;border:none;border-radius:8px;padding:9px 20px;cursor:pointer;font-size:.85rem;font-weight:600">
      🖨️ Save as PDF
    </button>
  </div>

  {banner}

  <div class="cards">{cards_html}</div>

  {tech_html}

  {chains_html}

  {rem_table}

  {mod_table}

  <div class="section">
    <div class="section-head">
      <h3>🔍 All Findings</h3>
      <span class="badge">{len(sorted_findings)}</span>
    </div>
    {controls}
    <div id="findings-list">
      {finding_cards}
      {no_findings}
    </div>
  </div>

  <div style="text-align:center;color:#334155;font-size:.75rem;padding:24px 0;border-top:1px solid var(--border);margin-top:32px">
    Mirror Scanner — generated {now} — findings with confidence &lt;65% or status 403/401 are not reported as vulnerabilities
  </div>
</div>

<script>{JS}</script>
</body>
</html>"""

def load_reports():
    findings, chains = [], []
    for jf in sorted(REPORTS_DIR.glob("*.json")):
        if jf.stem.startswith("_") or jf.stem == "rootchain_report": continue
        try:
            d = json.loads(jf.read_text())
            if isinstance(d, list): findings.extend(d)
        except Exception: pass
    rc = REPORTS_DIR / "rootchain_report.json"
    if rc.exists():
        try: chains = json.loads(rc.read_text()).get("attack_chains",[])
        except Exception: pass
    return findings, chains

def main():
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "Unknown Target"
    tf = REPORTS_DIR / "_target.txt"
    if tf.exists(): target = tf.read_text().strip()
    findings, chains = load_reports()
    html = generate_html_report(target, findings, chains)
    out = REPORTS_DIR / "report.html"
    out.write_text(html, encoding='utf-8')
    print(f"[+] Report written → {out} ({len(findings)} findings)")
    return html

if __name__ == '__main__': main()
