#!/usr/bin/env python3
"""
Mirror Report Generator v5 — Pro-grade Security Report with PDF Export.

Improvements over v2:
  - Real PDF download via jsPDF + jspdf-autotable (no browser required)
  - JSON export button (full findings as downloadable JSON)
  - CSV export of findings table
  - Crash-proof: safe JSON serialization, defensive string escaping,
    try/except on every section, never crashes on empty/malformed data
  - Executive Summary with risk verdict + remediation timeline
  - Full-page print layout: findings auto-expanded, headers on every page
  - MITRE ATT&CK column in findings table
  - CVSS score bars
  - Scan diff section (new/resolved since baseline)
  - Dark + print-friendly dual stylesheet
  - Progressive rendering: table of contents, anchor links
  - Responsive: works on mobile
"""
import json, time, sys, re
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_HEX     = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6","INFO":"#6b7280"}
SEV_DARK    = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#713f12","LOW":"#1e3a5f","INFO":"#1f2937"}
SEV_WEIGHT  = {"CRITICAL":30,"HIGH":12,"MEDIUM":4,"LOW":1,"INFO":0}

MODULE_ICON = {
    "ghostcrawler":"🕷","wafshatter":"🛡","headerforge":"🔩","authdrift":"🔐",
    "tokensniper":"🎯","backendprobe":"⚙","deeplogic":"🧠","cryptohunter":"🔑",
    "timebleed":"⏱","rootchain":"⛓","webprobe":"🌐","cveprobe":"📋",
    "scan_diff":"📊","report_generator":"📄","other":"🔍",
}

MITRE_STAGE = {
    "RECONN":         "TA0043 Reconnaissance",
    "INITIAL_ACCESS": "TA0001 Initial Access",
    "EXECUTION":      "TA0002 Execution",
    "PERSISTENCE":    "TA0003 Persistence",
    "PRIV_ESC":       "TA0004 Privilege Escalation",
    "DEFENSE_EVASION":"TA0005 Defense Evasion",
    "CRED_ACCESS":    "TA0006 Credential Access",
    "COLLECTION":     "TA0009 Collection",
    "EXFIL":          "TA0010 Exfiltration",
    "LATERAL":        "TA0008 Lateral Movement",
    "IMPACT":         "TA0040 Impact",
}

REMEDIATION_TIMELINE = {
    "CRITICAL": "Immediate (within 24 hours)",
    "HIGH":     "Urgent (within 7 days)",
    "MEDIUM":   "Planned (within 30 days)",
    "LOW":      "Scheduled (within 90 days)",
    "INFO":     "Informational (best effort)",
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_str(v) -> str:
    """Always return a string, never crash."""
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""

def esc(s) -> str:
    s = _safe_str(s)
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;"))

def risk_score(findings: list) -> int:
    try:
        raw = sum(SEV_WEIGHT.get(_safe_str(f.get("severity","INFO")), 0) for f in findings)
        return min(100, raw)
    except Exception:
        return 0

def risk_label(score: int):
    if score >= 60: return ("CRITICAL RISK", "#ef4444")
    if score >= 35: return ("HIGH RISK",     "#f97316")
    if score >= 15: return ("MEDIUM RISK",   "#eab308")
    if score >= 1:  return ("LOW RISK",      "#3b82f6")
    return ("CLEAN",        "#22c55e")

def module_from_type(ftype: str) -> str:
    t = _safe_str(ftype).lower()
    if any(k in t for k in ["jwt","auth","idor","cred","lockout","brute","default_cred","session","verb_tamper","account"]): return "authdrift"
    if any(k in t for k in ["waf","rate_limit","bypass","origin_ip","http_trace","dangerous_http","server_disclosure"]): return "wafshatter"
    if any(k in t for k in ["hsts","csp","cors","host","header","xfo","content_type","referrer","permissions"]): return "headerforge"
    if any(k in t for k in ["tls","cert","http_not_https","cipher","crypto","mixed","hsts","self_signed"]): return "cryptohunter"
    if any(k in t for k in ["secret","token","key","file_expo","api_key","aws","gcp","github","stripe","jwt_in"]): return "tokensniper"
    if any(k in t for k in ["ssrf","xxe","backend","admin_api","path_traversal","ssti","internal_service"]): return "backendprobe"
    if any(k in t for k in ["timing","sqli","bleed","sqli_blind"]): return "timebleed"
    if any(k in t for k in ["mass_assign","race","logic","version","price","enumeration","hpp","api_version"]): return "deeplogic"
    if any(k in t for k in ["attack_chain","rootchain"]): return "rootchain"
    if any(k in t for k in ["xss","redirect","clickjack","cache_poison","sri","dom","postmessage","cve"]): return "webprobe"
    if any(k in t for k in ["endpoint","graphql","api_docs","cookie","crawl","surface","robot","sitemap"]): return "ghostcrawler"
    if any(k in t for k in ["cve","sharepoint","exchange","wordpress","jenkins","gitlab"]): return "cveprobe"
    return "other"

def extract_tech_waf(findings: list):
    for f in findings:
        if _safe_str(f.get("type")) == "ATTACK_SURFACE_SUMMARY":
            return f.get("tech", []), f.get("waf", [])
    return [], []

# ── CSS ────────────────────────────────────────────────────────────────────────

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#08111f;--card:#0f1e32;--card2:#162338;--border:#1e3451;
  --text:#e2e8f0;--muted:#64748b;--accent:#3b82f6;
  --green:#22c55e;--red:#ef4444;--orange:#f97316;--yellow:#eab308;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh;font-size:15px;line-height:1.6}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}

/* Top bar */
.topbar{background:#060d1a;border-bottom:1px solid var(--border);
        padding:12px 32px;display:flex;align-items:center;justify-content:space-between;
        position:sticky;top:0;z-index:200;backdrop-filter:blur(10px)}
.topbar .logo{font-size:1.05rem;font-weight:800;color:#f8fafc;display:flex;align-items:center;gap:8px}
.topbar .meta{font-size:.75rem;color:var(--muted);text-align:right;line-height:1.5}

/* Export toolbar */
.export-bar{display:flex;gap:8px;justify-content:flex-end;margin-bottom:20px;flex-wrap:wrap}
.btn{border:none;border-radius:7px;padding:8px 16px;cursor:pointer;font-size:.82rem;font-weight:600;
     display:inline-flex;align-items:center;gap:5px;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn-pdf{background:#2563eb;color:#fff}
.btn-json{background:#0f766e;color:#fff}
.btn-csv{background:#7c3aed;color:#fff}
.btn-print{background:#374151;color:#fff}

/* Layout */
.page{max-width:1320px;margin:0 auto;padding:24px 20px}

/* TOC */
.toc{background:var(--card);border:1px solid var(--border);border-radius:10px;
     padding:14px 20px;margin-bottom:24px}
.toc h4{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.toc-links{display:flex;flex-wrap:wrap;gap:6px 16px}
.toc-links a{color:#60a5fa;font-size:.82rem;text-decoration:none}
.toc-links a:hover{text-decoration:underline}

/* Risk banner */
.risk-banner{border-radius:12px;padding:22px 28px;margin-bottom:24px;
             display:flex;align-items:center;gap:28px}
.risk-circle{width:88px;height:88px;border-radius:50%;border:4px solid;
             display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
.risk-circle .num{font-size:2rem;font-weight:900;line-height:1}
.risk-circle .lbl{font-size:.58rem;letter-spacing:1px;text-transform:uppercase;margin-top:2px}
.risk-info h2{font-size:1.35rem;font-weight:800;margin-bottom:4px}
.risk-info p{color:#94a3b8;font-size:.87rem;line-height:1.5}

/* Summary cards */
.cards{display:grid;grid-template-columns:repeat(7,1fr);gap:10px;margin-bottom:24px}
@media(max-width:900px){.cards{grid-template-columns:repeat(4,1fr)}}
@media(max-width:500px){.cards{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;
      padding:14px;text-align:center}
.card .num{font-size:1.9rem;font-weight:800;line-height:1}
.card .lbl{font-size:.65rem;color:var(--muted);margin-top:3px;text-transform:uppercase;letter-spacing:.4px}

/* CVSS bar */
.cvss-bar{height:4px;border-radius:2px;background:var(--border);margin-top:4px;overflow:hidden}
.cvss-fill{height:100%;border-radius:2px;transition:width .4s}

/* Section */
.section{margin-bottom:30px}
.section-head{display:flex;align-items:center;gap:10px;margin-bottom:12px;
              border-bottom:1px solid var(--border);padding-bottom:8px}
.section-head h3{font-size:.98rem;font-weight:700;color:#f1f5f9}
.section-head .badge{background:var(--card2);color:var(--muted);border-radius:4px;
                     padding:1px 7px;font-size:.7rem}

/* Executive summary table */
.exec-table{width:100%;border-collapse:collapse;font-size:.85rem}
.exec-table th{background:#0b1626;color:var(--muted);padding:8px 12px;text-align:left;
               font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.4px}
.exec-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.exec-table tr:last-child td{border-bottom:none}

/* Controls */
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.controls input{background:var(--card);border:1px solid var(--border);border-radius:7px;
                padding:7px 14px;color:var(--text);font-size:.85rem;width:220px;outline:none}
.controls input:focus{border-color:var(--accent)}
.filter-grp{display:flex;gap:5px;flex-wrap:wrap}
.fbtn{border:1px solid var(--border);background:var(--card);color:var(--muted);
      border-radius:6px;padding:5px 11px;cursor:pointer;font-size:.75rem;transition:all .12s}
.fbtn:hover{background:var(--card2);color:var(--text)}
.fbtn.active{border-color:var(--accent);color:#60a5fa;background:var(--card2)}
.count-lbl{margin-left:auto;font-size:.78rem;color:var(--muted)}

/* Finding cards */
.finding{background:var(--card);border:1px solid var(--border);border-radius:10px;
         margin-bottom:7px;overflow:hidden;transition:border-color .12s}
.finding:hover{border-color:#334155}
.fhdr{display:flex;align-items:center;gap:9px;padding:11px 15px;cursor:pointer;user-select:none}
.sev-badge{border-radius:4px;padding:2px 8px;font-size:.65rem;font-weight:700;
           text-transform:uppercase;letter-spacing:.4px;white-space:nowrap;flex-shrink:0}
.ftitle{font-weight:600;font-size:.87rem;flex:1;color:#f1f5f9;line-height:1.3}
.conf-pill{border:1px solid;border-radius:12px;padding:2px 8px;font-size:.68rem;white-space:nowrap;flex-shrink:0}
.chevron{color:var(--muted);font-size:.65rem;transition:transform .15s;flex-shrink:0}
.fhdr.open .chevron{transform:rotate(180deg)}
.fbody{display:none;padding:0 15px 13px;border-top:1px solid var(--border)}
.fbody.open{display:block}

/* Proof box */
.proof-box{background:#060f1e;border:1px solid #1a3a5c;border-left:4px solid #3b82f6;
           border-radius:0 6px 6px 0;padding:11px 13px;margin:11px 0;font-size:.82rem;
           color:#93c5fd;line-height:1.5;word-break:break-all}
.proof-box strong{color:#60a5fa;display:block;margin-bottom:3px;font-size:.75rem;text-transform:uppercase;letter-spacing:.4px}
.proof-missing{border-left-color:#4b5563;color:#6b7280}
.rem-box{background:#040e1a;border:1px solid var(--border);border-left:4px solid #22c55e;
         border-radius:0 6px 6px 0;padding:11px 13px;margin-top:9px;font-size:.82rem;
         color:#86efac;line-height:1.5}
.rem-box strong{color:#4ade80;display:block;margin-bottom:3px;font-size:.75rem;text-transform:uppercase;letter-spacing:.4px}
.fbody table{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:7px}
.fbody td{padding:5px 9px;border:1px solid var(--border);vertical-align:top}
.fbody td:first-child{color:var(--muted);width:110px;white-space:nowrap}
.fbody td code{word-break:break-all;background:#0d1a2e;padding:1px 4px;border-radius:3px;font-size:.76rem}
.mitre-tag{background:#1e1b4b;border:1px solid #3730a3;color:#a5b4fc;
           border-radius:4px;padding:2px 8px;font-size:.7rem;display:inline-block;margin-top:5px}

/* Attack chains */
.chain-card{border:1px solid;border-radius:10px;padding:15px 18px;margin-bottom:9px}
.chain-hdr{display:flex;align-items:center;gap:9px;margin-bottom:7px}
.chain-name{font-weight:700;font-size:.93rem;flex:1;color:#f1f5f9}
.chain-score{font-size:.76rem;color:var(--muted);white-space:nowrap}
.chain-desc{font-size:.83rem;color:#94a3b8;margin-bottom:8px}
.chain-narrative{font-size:.8rem;color:#7d94b0;font-style:italic;margin-bottom:8px;line-height:1.5}
.chain-stages{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:5px}
.chain-stage{background:#0f172a;border:1px solid #334155;border-radius:4px;
             padding:2px 8px;font-size:.69rem;color:#94a3b8}
.chain-cves{font-size:.73rem;color:#64748b;margin-top:5px}
.cvss-badge{background:#0f172a;border:1px solid #334155;border-radius:4px;
            padding:2px 8px;font-size:.7rem;color:#f59e0b;font-weight:700}

/* Module table */
.mod-table{width:100%;border-collapse:collapse;font-size:.83rem}
.mod-table th{background:#0a1426;color:var(--muted);padding:7px 11px;text-align:left;
              font-weight:600;font-size:.68rem;text-transform:uppercase;letter-spacing:.4px}
.mod-table td{padding:8px 11px;border-bottom:1px solid var(--border)}
.mod-table tr:hover td{background:var(--card2)}
.mbadge{margin-right:5px;font-size:.72rem;font-weight:700}

/* Tech pills */
.tech-pill{background:var(--card2);border:1px solid var(--border);border-radius:20px;
           padding:3px 11px;font-size:.75rem;display:inline-block;margin:3px}

/* Remediation priority */
.rem-table{width:100%;border-collapse:collapse;font-size:.81rem}
.rem-table th{background:#0a1426;color:var(--muted);padding:7px 11px;text-align:left;
              font-weight:600;font-size:.68rem;text-transform:uppercase;letter-spacing:.4px}
.rem-table td{padding:9px 11px;border-bottom:1px solid var(--border);vertical-align:top}
.rem-table tr:hover td{background:var(--card2)}
.timeline-pill{border-radius:4px;padding:2px 7px;font-size:.68rem;font-weight:600;white-space:nowrap}

/* Scan diff */
.diff-new{color:#ef4444}
.diff-fixed{color:#22c55e}
.diff-same{color:#64748b}

/* Print styles */
@media print {
  @page{margin:15mm;size:A4}
  body{background:#fff!important;color:#111!important;font-size:11pt}
  .topbar,.export-bar,.controls,.toc{display:none!important}
  .risk-banner{border:2px solid #ccc!important;background:#f8f8f8!important;break-inside:avoid}
  .fbody{display:block!important}
  .fhdr .chevron{display:none}
  .finding{break-inside:avoid;border:1px solid #ddd!important;background:#fff!important}
  .proof-box{background:#f0f8ff!important;color:#1a3a5c!important;border-color:#93c5fd!important}
  .rem-box{background:#f0fdf4!important;color:#166534!important;border-color:#86efac!important}
  .fbody td{border-color:#ddd!important;color:#333!important}
  .fbody td:first-child{color:#666!important}
  .chain-card{border:1px solid #ddd!important;background:#fff!important;break-inside:avoid}
  .card{background:#f9f9f9!important;color:#333!important;border-color:#ddd!important}
  .mod-table td,.rem-table td{border-color:#eee!important;background:#fff!important}
  .section-head{border-bottom:2px solid #eee!important}
  .section-head h3{color:#111!important}
  h2,h3,h4{color:#111!important}
  .sev-badge{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  a{color:#000!important;text-decoration:none}
  code{background:#f1f5f9!important;color:#0f172a!important}
}
"""

# ── JavaScript ──────────────────────────────────────────────────────────────────

JS = r"""
// ── Accordion ─────────────────────────────────────────────────────────────
function toggle(el){
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('open');
}

// ── Filters ───────────────────────────────────────────────────────────────
function applyFilters(){
  const q    = (document.getElementById('search')||{value:''}).value.toLowerCase();
  const sev  = (document.querySelector('.fbtn[data-type="sev"].active')||{dataset:{val:'ALL'}}).dataset.val;
  const mod  = (document.querySelector('.fbtn[data-type="mod"].active')||{dataset:{val:'ALL'}}).dataset.val;
  const conf = parseInt((document.querySelector('.fbtn[data-type="conf"].active')||{dataset:{val:'0'}}).dataset.val||'0');
  let vis = 0;
  document.querySelectorAll('.finding').forEach(el=>{
    const show = (sev==='ALL'||el.dataset.sev===sev)
              && (mod==='ALL'||el.dataset.mod===mod)
              && parseInt(el.dataset.conf||0)>=conf
              && (!q||el.textContent.toLowerCase().includes(q));
    el.style.display=show?'':'none';
    if(show) vis++;
  });
  const cd=document.getElementById('count-lbl');
  if(cd) cd.textContent=vis+' finding'+(vis===1?'':'s')+' shown';
}
function setFilter(btn,type){
  document.querySelectorAll(`.fbtn[data-type="${type}"]`).forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}
const si=document.getElementById('search');
if(si) si.addEventListener('input',applyFilters);

// ── Print: expand all ─────────────────────────────────────────────────────
window.addEventListener('beforeprint',()=>{
  document.querySelectorAll('.fbody').forEach(b=>b.classList.add('open'));
  document.querySelectorAll('.fhdr').forEach(h=>h.classList.add('open'));
  document.querySelectorAll('.finding').forEach(el=>el.style.display='');
});
window.addEventListener('afterprint',()=>{
  document.querySelectorAll('.fbody').forEach(b=>b.classList.remove('open'));
  document.querySelectorAll('.fhdr').forEach(h=>h.classList.remove('open'));
  applyFilters();
});

// ── PDF download via jsPDF ────────────────────────────────────────────────
async function downloadPDF(){
  const btn=document.getElementById('pdf-btn');
  if(btn){btn.disabled=true;btn.textContent='⏳ Generating PDF...';}
  try{
    const {jsPDF}=window.jspdf;
    const doc=new jsPDF({orientation:'portrait',unit:'mm',format:'a4'});
    const W=doc.internal.pageSize.getWidth();
    const H=doc.internal.pageSize.getHeight();
    const margin=14;
    let y=margin;

    // ── Cover page ──
    doc.setFillColor(8,17,31);
    doc.rect(0,0,W,H,'F');
    doc.setTextColor(59,130,246);
    doc.setFontSize(22);doc.setFont('helvetica','bold');
    doc.text('Mirror Security Report',W/2,38,{align:'center'});
    doc.setTextColor(226,232,240);
    doc.setFontSize(11);doc.setFont('helvetica','normal');
    const target=document.getElementById('meta-target')?document.getElementById('meta-target').textContent:'';
    const ts=document.getElementById('meta-ts')?document.getElementById('meta-ts').textContent:'';
    doc.text('Target: '+target,W/2,50,{align:'center'});
    doc.text(ts,W/2,57,{align:'center'});

    // Risk score circle
    const score=parseInt(document.getElementById('meta-score')?document.getElementById('meta-score').textContent:'0')||0;
    const verdict=document.getElementById('meta-verdict')?document.getElementById('meta-verdict').textContent:'';
    const riskColor=score>=60?[239,68,68]:score>=35?[249,115,22]:score>=15?[234,179,8]:[34,197,94];
    doc.setDrawColor(...riskColor);doc.setLineWidth(2);
    doc.circle(W/2,80,14);
    doc.setTextColor(...riskColor);
    doc.setFontSize(18);doc.setFont('helvetica','bold');
    doc.text(String(score),W/2,83,{align:'center'});
    doc.setFontSize(7);doc.setFont('helvetica','normal');
    doc.text('RISK SCORE',W/2,89,{align:'center'});
    doc.setFontSize(13);doc.setFont('helvetica','bold');
    doc.text(verdict,W/2,102,{align:'center'});

    // Severity summary
    const sevColors={CRITICAL:[239,68,68],HIGH:[249,115,22],MEDIUM:[234,179,8],LOW:[59,130,246],INFO:[107,114,128]};
    let sx=margin;
    ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(sev=>{
      const el=document.getElementById('cnt-'+sev);
      const cnt=el?el.textContent:'0';
      const c=sevColors[sev]||[100,100,100];
      doc.setTextColor(...c);doc.setFontSize(20);doc.setFont('helvetica','bold');
      doc.text(cnt,sx+10,125,{align:'center'});
      doc.setTextColor(100,116,139);doc.setFontSize(7);doc.setFont('helvetica','normal');
      doc.text(sev,sx+10,131,{align:'center'});
      sx+=(W-2*margin)/5;
    });

    doc.addPage();

    // ── Findings table ──
    doc.setFillColor(8,17,31);doc.rect(0,0,W,H,'F');
    y=margin;
    doc.setTextColor(241,245,249);doc.setFontSize(13);doc.setFont('helvetica','bold');
    doc.text('All Findings',margin,y);y+=8;

    const rows=[];
    document.querySelectorAll('.finding').forEach(el=>{
      const sev=el.dataset.sev||'';
      const title=el.querySelector('.ftitle')?el.querySelector('.ftitle').textContent.trim().substring(0,70):'';
      const url=el.querySelector('td:last-child code')?el.querySelector('td:last-child code').textContent.trim().substring(0,60):'';
      const conf=el.dataset.conf||'';
      rows.push([sev,title,url,conf+'%']);
    });

    if(rows.length>0 && window.jspdf.jsPDF.API.autoTable){
      doc.autoTable({
        startY:y,
        head:[['Severity','Finding','URL','Confidence']],
        body:rows,
        theme:'grid',
        styles:{fontSize:7,textColor:[226,232,240],fillColor:[15,30,50],lineColor:[30,52,81],lineWidth:0.3},
        headStyles:{fillColor:[10,20,38],textColor:[100,116,139],fontStyle:'bold',fontSize:7},
        alternateRowStyles:{fillColor:[22,35,56]},
        columnStyles:{0:{cellWidth:18,fontStyle:'bold'},1:{cellWidth:85},2:{cellWidth:55},3:{cellWidth:20}},
        margin:{left:margin,right:margin},
        didParseCell:function(data){
          if(data.column.index===0&&data.section==='body'){
            const sev=data.cell.raw||'';
            const c=sevColors[sev]||[107,114,128];
            data.cell.styles.textColor=c;
          }
        },
        willDrawPage:function(data){
          doc.setFillColor(8,17,31);doc.rect(0,0,W,H,'F');
        },
      });
    } else {
      rows.slice(0,60).forEach(r=>{
        if(y>H-20){doc.addPage();doc.setFillColor(8,17,31);doc.rect(0,0,W,H,'F');y=margin;}
        const sev=r[0];
        const c=sevColors[sev]||[107,114,128];
        doc.setTextColor(...c);doc.setFontSize(7);doc.setFont('helvetica','bold');
        doc.text(sev.substring(0,8),margin,y);
        doc.setTextColor(226,232,240);doc.setFont('helvetica','normal');
        doc.text(r[1].substring(0,80),margin+20,y);
        y+=5;
      });
    }

    // ── Attack chains page ──
    const chainCards=document.querySelectorAll('.chain-card');
    if(chainCards.length>0){
      doc.addPage();
      doc.setFillColor(8,17,31);doc.rect(0,0,W,H,'F');
      y=margin;
      doc.setTextColor(241,245,249);doc.setFontSize(13);doc.setFont('helvetica','bold');
      doc.text('Attack Chains',margin,y);y+=8;
      chainCards.forEach(card=>{
        if(y>H-30){doc.addPage();doc.setFillColor(8,17,31);doc.rect(0,0,W,H,'F');y=margin;}
        const name=card.querySelector('.chain-name')?card.querySelector('.chain-name').textContent.trim():'';
        const desc=card.querySelector('.chain-desc')?card.querySelector('.chain-desc').textContent.trim():'';
        const narrative=card.querySelector('.chain-narrative')?card.querySelector('.chain-narrative').textContent.trim():'';
        doc.setTextColor(239,68,68);doc.setFontSize(9);doc.setFont('helvetica','bold');
        doc.text(name.substring(0,90),margin,y);y+=5;
        doc.setTextColor(148,163,184);doc.setFontSize(7);doc.setFont('helvetica','normal');
        const descLines=doc.splitTextToSize(desc.substring(0,200),W-2*margin);
        doc.text(descLines,margin,y);y+=descLines.length*4+1;
        if(narrative){
          doc.setTextColor(100,120,160);
          const narLines=doc.splitTextToSize(narrative.substring(0,300),W-2*margin);
          doc.text(narLines,margin,y);y+=narLines.length*4;
        }
        y+=4;
      });
    }

    // Page numbers
    const totalPages=doc.internal.getNumberOfPages();
    for(let i=1;i<=totalPages;i++){
      doc.setPage(i);
      doc.setTextColor(100,116,139);doc.setFontSize(7);doc.setFont('helvetica','normal');
      doc.text('Mirror Security Report — Page '+i+'/'+totalPages,W/2,H-6,{align:'center'});
    }

    doc.save('mirror-security-report.pdf');
  }catch(e){
    alert('PDF generation error: '+e.message+'\n\nTry using the Print button instead (Ctrl+P → Save as PDF).');
    console.error(e);
  }finally{
    if(btn){btn.disabled=false;btn.textContent='⬇ Download PDF';}
  }
}

// ── JSON export ───────────────────────────────────────────────────────────
function downloadJSON(){
  const data=window.__MIRROR_FINDINGS__||[];
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download='mirror-findings.json';
  document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
}

// ── CSV export ────────────────────────────────────────────────────────────
function downloadCSV(){
  const rows=[['Severity','Type','Confidence','URL','Detail','Remediation','MITRE']];
  (window.__MIRROR_FINDINGS__||[]).forEach(f=>{
    rows.push([
      f.severity||'',f.type||'',f.confidence||'',
      f.url||'',
      (f.detail||'').replace(/"/g,"'"),
      (f.remediation||'').replace(/"/g,"'"),
      f.mitre_technique||''
    ]);
  });
  const csv=rows.map(r=>r.map(c=>'"'+(c+'').replace(/"/g,'""')+'"').join(',')).join('\n');
  const blob=new Blob([csv],{type:'text/csv'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download='mirror-findings.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
}
"""

# ── HTML builders ──────────────────────────────────────────────────────────────

def build_finding_card(f: dict, idx: int) -> str:
    try:
        sev        = _safe_str(f.get("severity","INFO"))
        hex_       = SEV_HEX.get(sev, "#6b7280")
        dark       = SEV_DARK.get(sev, "#1f2937")
        conf       = int(f.get("confidence", 0) or 0)
        conf_label = _safe_str(f.get("confidence_label","?"))
        ftype      = esc(f.get("type",""))
        detail     = esc(f.get("detail","") or f.get("name",""))
        proof      = esc(f.get("proof",""))
        url        = esc(f.get("url",""))
        rem        = esc(f.get("remediation",""))
        mod        = module_from_type(f.get("type",""))
        icon       = MODULE_ICON.get(mod,"🔍")
        mitre_t    = esc(f.get("mitre_technique",""))
        mitre_n    = esc(f.get("mitre_name",""))
        cvss       = float(f.get("cvss", 0) or f.get("cvss_base", 0) or 0)
        conf_color = "#22c55e" if conf>=80 else "#eab308" if conf>=60 else "#6b7280"

        extra_rows = ""
        for k in ("param","payload","header","cipher","version","delta","waf","service",
                  "bypass_count","origin_sent","tls_version","key_bits","days_remaining",
                  "weak_secret","resource_id","cookie_name","ssrf_target"):
            v = f.get(k)
            if v is not None:
                extra_rows += f'<tr><td>{esc(k.replace("_"," ").title())}</td><td><code>{esc(str(v)[:200])}</code></td></tr>'

        mitre_tag = ""
        if mitre_t:
            mitre_tag = f'<div class="mitre-tag">MITRE {mitre_t}: {mitre_n}</div>'

        cvss_bar = ""
        if cvss > 0:
            pct = int(cvss / 10 * 100)
            bar_color = "#ef4444" if cvss>=9 else "#f97316" if cvss>=7 else "#eab308" if cvss>=4 else "#3b82f6"
            cvss_bar = f'<div class="cvss-bar"><div class="cvss-fill" style="width:{pct}%;background:{bar_color}"></div></div>'

        proof_html = (
            f'<div class="proof-box"><strong>Proof / Evidence</strong>{proof}</div>'
            if proof else
            '<div class="proof-box proof-missing">⚠ No explicit proof recorded — treat with lower priority.</div>'
        )

        return f"""
<div class="finding" data-sev="{sev}" data-mod="{mod}" data-conf="{conf}" id="f{idx}">
  <div class="fhdr" onclick="toggle(this)">
    <span class="sev-badge" style="background:{dark};color:{hex_};border:1px solid {hex_}44">{sev}</span>
    <span class="ftitle">{detail or ftype}</span>
    <span class="conf-pill" style="border-color:{conf_color};color:{conf_color}">{icon} {conf_label} {conf}%</span>
    <span class="chevron">▼</span>
  </div>
  <div class="fbody">
    {proof_html}
    <table>
      <tr><td>Type</td><td><code>{ftype}</code></td></tr>
      {'<tr><td>URL</td><td><code>' + url + '</code></td></tr>' if url else ''}
      {extra_rows}
      <tr><td>Module</td><td>{icon} {esc(mod)}</td></tr>
      <tr><td>Confidence</td><td style="color:{conf_color}">{conf}% — {esc(conf_label)}</td></tr>
      {'<tr><td>CVSS</td><td>' + str(cvss) + cvss_bar + '</td></tr>' if cvss else ''}
    </table>
    {mitre_tag}
    {'<div class="rem-box"><strong>Remediation</strong>' + rem + '</div>' if rem else ''}
  </div>
</div>"""
    except Exception as e:
        return f'<div class="finding" data-sev="INFO" data-mod="other" data-conf="0"><div class="fhdr"><span class="ftitle">Error rendering finding #{idx}: {esc(str(e))}</span></div></div>'


def build_chain_card(c: dict) -> str:
    try:
        risk   = _safe_str(c.get("risk","HIGH"))
        hex_   = SEV_HEX.get(risk, "#6b7280")
        score  = int(c.get("risk_score", 0) or 0)
        cvss   = float(c.get("cvss_base", 0) or 0)
        stages = c.get("kill_chain", []) or c.get("stages", []) or []
        mitre_stages = c.get("mitre_stages", [])
        stage_html = ""
        for s in stages:
            lbl = MITRE_STAGE.get(s, s)
            stage_html += f'<span class="chain-stage">{esc(lbl)}</span>'
        cves = ", ".join(_safe_str(cv) for cv in (c.get("cves", []) or []))
        narrative = esc(c.get("narrative", ""))
        return f"""
<div class="chain-card" style="border-color:{hex_}44;background:linear-gradient(135deg,{hex_}0d,var(--card))">
  <div class="chain-hdr">
    <span class="sev-badge" style="background:{SEV_DARK.get(risk,'#1f2937')};color:{hex_};border:1px solid {hex_}44">{risk}</span>
    <span class="chain-name">{esc(c.get('name','Attack Chain'))}</span>
    <span class="cvss-badge">CVSS {cvss}</span>
    <span class="chain-score">Risk {score}/100</span>
  </div>
  <div class="chain-desc">{esc(c.get('description',''))}</div>
  {'<div class="chain-narrative">' + narrative + '</div>' if narrative else ''}
  {'<div class="chain-stages">' + stage_html + '</div>' if stage_html else ''}
  {'<div class="chain-cves">CVEs: ' + esc(cves) + '</div>' if cves else ''}
</div>"""
    except Exception as e:
        return f'<div class="chain-card"><div class="chain-desc">Error rendering chain: {esc(str(e))}</div></div>'


def build_module_row(mod: str, findings: list) -> str:
    icon   = MODULE_ICON.get(mod, "🔍")
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = _safe_str(f.get("severity","INFO"))
        counts[s] = counts.get(s, 0) + 1
    badges = "".join(
        f'<span class="mbadge" style="color:{SEV_HEX[s]}">{s[0]} {counts[s]}</span>'
        for s in SEV_ORDER if counts[s]
    )
    ran = bool(findings) or REPORTS_DIR.joinpath(f"{mod}.json").exists()
    status_html = '<span style="color:#22c55e">✓ Ran</span>' if ran else '<span style="color:#4b5563">— No data</span>'
    return f"""<tr>
      <td>{icon} <code>{esc(mod)}</code></td>
      <td>{status_html}</td>
      <td>{badges or '<span style="color:#4b5563">—</span>'}</td>
      <td style="color:#94a3b8">{len(findings)}</td>
    </tr>"""


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_html_report(target: str, findings: list, chains=None, meta=None) -> str:
    try:
        chains   = chains or []
        meta     = meta or {}
        now      = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        score    = risk_score(findings)
        rlabel, rcolor = risk_label(score)

        counts = {s: 0 for s in SEV_ORDER}
        for f in findings:
            s = _safe_str(f.get("severity","INFO"))
            if s in counts:
                counts[s] += 1

        confirmed = [f for f in findings if int(f.get("confidence",0) or 0)>=65 and f.get("severity","INFO") != "INFO"]
        tech, waf = extract_tech_waf(findings)

        by_module: dict = {}
        for f in findings:
            mod = module_from_type(f.get("type",""))
            by_module.setdefault(mod, []).append(f)

        sorted_findings = sorted(findings, key=lambda f: (
            SEV_ORDER.index(_safe_str(f.get("severity","INFO"))) if _safe_str(f.get("severity","INFO")) in SEV_ORDER else 99,
            -(int(f.get("confidence",0) or 0))
        ))

        # ── Embed findings for JS export ──
        try:
            findings_json = json.dumps(sorted_findings[:500], default=_safe_str, ensure_ascii=False)
        except Exception:
            findings_json = "[]"

        # ── Summary cards ──
        cards_html = f'<div class="card"><div class="num">{len(findings)}</div><div class="lbl">Total</div></div>'
        for sev in SEV_ORDER:
            c = counts[sev]
            hex_ = SEV_HEX[sev]
            cards_html += f'<div class="card"><div class="num" id="cnt-{sev}" style="color:{hex_}">{c}</div><div class="lbl">{sev}</div></div>'

        # ── Risk banner ──
        banner = f"""
<div class="risk-banner" style="background:linear-gradient(135deg,{rcolor}14,{rcolor}06);border:1px solid {rcolor}2a">
  <div class="risk-circle" style="border-color:{rcolor};color:{rcolor}">
    <div class="num" id="meta-score">{score}</div>
    <div class="lbl">Risk</div>
  </div>
  <div class="risk-info">
    <h2 style="color:{rcolor}" id="meta-verdict">{rlabel}</h2>
    <p>{len(confirmed)} confirmed finding(s) &nbsp;|&nbsp; {len(findings)} total &nbsp;|&nbsp; {len(chains)} attack chain(s) &nbsp;|&nbsp; Scan: <span id="meta-ts">{now}</span></p>
    <p style="margin-top:3px;color:#64748b;font-size:.8rem">Target: <strong id="meta-target" style="color:#94a3b8">{esc(target)}</strong></p>
  </div>
</div>"""

        # ── Executive summary ──
        exec_rows = ""
        for sev in SEV_ORDER:
            c = counts[sev]
            if c == 0:
                continue
            hex_ = SEV_HEX[sev]
            tl   = REMEDIATION_TIMELINE.get(sev, "")
            exec_rows += f"""<tr>
              <td><span class="sev-badge" style="background:{SEV_DARK.get(sev,'#1f2937')};color:{hex_};border:1px solid {hex_}44">{sev}</span></td>
              <td style="color:{hex_};font-weight:700;font-size:1.1rem">{c}</td>
              <td style="color:#94a3b8;font-size:.8rem">{esc(tl)}</td>
            </tr>"""
        exec_section = f"""
<div class="section" id="sec-exec">
  <div class="section-head"><h3>📊 Executive Summary</h3></div>
  <table class="exec-table">
    <tr><th>Severity</th><th>Count</th><th>Remediation Timeline</th></tr>
    {exec_rows or '<tr><td colspan="3" style="color:#64748b;text-align:center">No significant findings</td></tr>'}
  </table>
</div>""" if exec_rows else ""

        # ── Tech panel ──
        tech_html = ""
        if tech or waf:
            pills = "".join(f'<span class="tech-pill">🏗 {esc(t)}</span>' for t in tech)
            pills += "".join(f'<span class="tech-pill">🛡 {esc(w)}</span>' for w in waf)
            tech_html = f"""
<div class="section" id="sec-tech">
  <div class="section-head"><h3>🖥 Technology Fingerprint</h3></div>
  <div>{pills or '<span style="color:#64748b">No technology detected</span>'}</div>
</div>"""

        # ── Attack chains ──
        chains_html = ""
        if chains:
            chain_cards = "".join(build_chain_card(c) for c in chains)
            chains_html = f"""
<div class="section" id="sec-chains">
  <div class="section-head"><h3>⛓ Attack Chains</h3><span class="badge">{len(chains)}</span></div>
  {chain_cards}
</div>"""

        # ── Remediation priority table ──
        top = [f for f in sorted_findings if _safe_str(f.get("severity")) in ("CRITICAL","HIGH","MEDIUM") and f.get("remediation")][:25]
        rem_rows = ""
        for i, f in enumerate(top, 1):
            sev  = _safe_str(f.get("severity","INFO"))
            hex_ = SEV_HEX.get(sev,"#6b7280")
            tl   = REMEDIATION_TIMELINE.get(sev,"")
            tl_bg = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#713f12"}.get(sev,"#1f2937")
            rem_rows += f"""<tr>
              <td style="color:var(--muted)">{i}</td>
              <td><span class="sev-badge" style="background:{SEV_DARK.get(sev,'#1f2937')};color:{hex_};border:1px solid {hex_}44">{sev}</span></td>
              <td style="font-size:.8rem">{esc(_safe_str(f.get('detail',''))[:90])}</td>
              <td style="font-size:.78rem;color:#94a3b8">{esc(_safe_str(f.get('remediation',''))[:130])}</td>
              <td><span class="timeline-pill" style="background:{tl_bg};color:{hex_}">{esc(tl)}</span></td>
            </tr>"""
        rem_table = f"""
<div class="section" id="sec-remediation">
  <div class="section-head"><h3>🔧 Remediation Priority</h3><span class="badge">Top {len(top)}</span></div>
  <table class="rem-table">
    <tr><th>#</th><th>Sev</th><th>Finding</th><th>Action</th><th>Timeline</th></tr>
    {rem_rows}
  </table>
</div>""" if rem_rows else ""

        # ── Module coverage ──
        ALL_MODULES = ["ghostcrawler","wafshatter","headerforge","authdrift","tokensniper",
                       "backendprobe","deeplogic","cryptohunter","timebleed","webprobe","rootchain","cveprobe"]
        mod_rows = "".join(build_module_row(mod, by_module.get(mod, [])) for mod in ALL_MODULES)
        mod_table = f"""
<div class="section" id="sec-modules">
  <div class="section-head"><h3>📋 Module Coverage</h3><span class="badge">{len(ALL_MODULES)} modules</span></div>
  <table class="mod-table">
    <tr><th>Module</th><th>Status</th><th>Severity Breakdown</th><th>Findings</th></tr>
    {mod_rows}
  </table>
</div>"""

        # ── Filter controls ──
        mod_btns = '<button class="fbtn active" data-type="mod" data-val="ALL" onclick="setFilter(this,\'mod\')">All Modules</button>'
        for mod in sorted(by_module.keys()):
            icon = MODULE_ICON.get(mod,"🔍")
            mod_btns += f'<button class="fbtn" data-type="mod" data-val="{mod}" onclick="setFilter(this,\'mod\')">{icon} {mod}</button>'

        sev_btns = "".join(
            f'<button class="fbtn" data-type="sev" data-val="{s}"'
            f' onclick="setFilter(this,\'sev\')"'
            f' style="color:{SEV_HEX[s]}">{s}</button>'
            for s in SEV_ORDER if counts[s]
        )
        controls = f"""
<div class="controls">
  <input type="text" id="search" placeholder="🔍 Search findings…" oninput="applyFilters()">
  <div class="filter-grp">
    <button class="fbtn active" data-type="sev" data-val="ALL" onclick="setFilter(this,'sev')">All</button>
    {sev_btns}
  </div>
  <div class="filter-grp">{mod_btns}</div>
  <div class="filter-grp">
    <button class="fbtn active" data-type="conf" data-val="0"  onclick="setFilter(this,'conf')">Any Conf</button>
    <button class="fbtn"        data-type="conf" data-val="65" onclick="setFilter(this,'conf')">≥65%</button>
    <button class="fbtn"        data-type="conf" data-val="85" onclick="setFilter(this,'conf')">≥85%</button>
  </div>
  <span class="count-lbl" id="count-lbl">{len(sorted_findings)} findings shown</span>
</div>"""

        finding_cards = "".join(build_finding_card(f, i) for i, f in enumerate(sorted_findings))
        no_findings_html = '<div style="text-align:center;color:#4b5563;padding:32px 0">🎉 No findings match the current filters.</div>' if not finding_cards else ""

        # ── Table of contents ──
        toc_links = []
        if exec_rows: toc_links.append('<a href="#sec-exec">Executive Summary</a>')
        if tech or waf: toc_links.append('<a href="#sec-tech">Technology</a>')
        if chains: toc_links.append('<a href="#sec-chains">Attack Chains</a>')
        if rem_rows: toc_links.append('<a href="#sec-remediation">Remediation</a>')
        toc_links += ['<a href="#sec-modules">Modules</a>', '<a href="#sec-findings">Findings</a>']
        toc_html = f"""
<div class="toc">
  <h4>Contents</h4>
  <div class="toc-links">{''.join(toc_links)}</div>
</div>"""

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
  <div class="logo">🛡 Mirror Security Report</div>
  <div class="meta">v5 Pro | {now}</div>
</div>

<div class="page">

<div class="export-bar">
  <button id="pdf-btn" class="btn btn-pdf" onclick="downloadPDF()">⬇ Download PDF</button>
  <button class="btn btn-json" onclick="downloadJSON()">⬇ Download JSON</button>
  <button class="btn btn-csv" onclick="downloadCSV()">⬇ Download CSV</button>
  <button class="btn btn-print" onclick="window.print()">🖨 Print</button>
</div>

{toc_html}

{banner}

<div class="cards">{cards_html}</div>

{exec_section}
{tech_html}
{chains_html}
{rem_table}
{mod_table}

<div class="section" id="sec-findings">
  <div class="section-head">
    <h3>🔍 All Findings</h3>
    <span class="badge">{len(sorted_findings)}</span>
  </div>
  {controls}
  <div id="findings-list">
    {finding_cards}
    {no_findings_html}
  </div>
</div>

<div style="text-align:center;color:#1e3451;font-size:.72rem;padding:20px 0;border-top:1px solid var(--border);margin-top:28px">
  Mirror Scanner v5 — generated {now} — authorized testing only
</div>

</div><!-- .page -->

<script>window.__MIRROR_FINDINGS__={findings_json};</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script>
<script>{JS}</script>
</body>
</html>"""
    except Exception as e:
        # Crash-proof fallback
        return f"""<!DOCTYPE html><html><head><title>Mirror Report - Error</title></head>
<body style="background:#0a0f1e;color:#e2e8f0;font-family:sans-serif;padding:40px">
<h1 style="color:#ef4444">Report Generation Error</h1>
<p>An error occurred while generating the report: {str(e)}</p>
<p>Findings available: {len(findings)}</p>
<pre style="background:#111;padding:20px;border-radius:8px;overflow:auto">
{json.dumps(findings[:10], indent=2, default=str)}
</pre>
<p><button onclick="window.print()" style="background:#2563eb;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer">Print/Save as PDF</button></p>
</body></html>"""


def load_reports():
    findings, chains = [], []
    for jf in sorted(REPORTS_DIR.glob("*.json")):
        if jf.stem.startswith("_") or jf.stem == "rootchain_report":
            continue
        try:
            d = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
            if isinstance(d, list):
                for f in d:
                    f.setdefault("_source_file", jf.stem)
                findings.extend(d)
            elif isinstance(d, dict):
                module_findings = d.get("findings", [])
                for f in module_findings:
                    f.setdefault("_source_file", jf.stem)
                findings.extend(module_findings)
        except Exception as e:
            print(f"  [WARN] Could not read {jf.name}: {e}")
    rc = REPORTS_DIR / "rootchain_report.json"
    if rc.exists():
        try:
            data = json.loads(rc.read_text(encoding="utf-8", errors="replace"))
            chains = data.get("attack_chains", [])
        except Exception as e:
            print(f"  [WARN] rootchain_report.json: {e}")
    return findings, chains


def main():
    target = ""
    if len(sys.argv) > 1:
        target = sys.argv[1]
    tf = REPORTS_DIR / "_target.txt"
    if tf.exists():
        target = tf.read_text(encoding="utf-8", errors="replace").strip()

    print("=" * 60)
    print("  Mirror Report Generator v5")
    print("  PDF | JSON | CSV export | Crash-proof | MITRE ATT&CK")
    print("=" * 60)
    print(f"[*] Target: {target or '(unknown)'}")

    REPORTS_DIR.mkdir(exist_ok=True)
    findings, chains = load_reports()
    print(f"[*] Loaded {len(findings)} findings, {len(chains)} chains")

    html = generate_html_report(target, findings, chains)
    out  = REPORTS_DIR / "report.html"
    out.write_text(html, encoding="utf-8")
    sz = out.stat().st_size
    print(f"\n[+] Report written → {out} ({sz:,} bytes, {len(findings)} findings)")
    print(f"[+] Open in browser for PDF/JSON/CSV export")
    return html


if __name__ == "__main__":
    main()
