#!/usr/bin/env python3
"""
Scan Diff v1 — Compare two Mirror scan results.

Given two lists of findings, produces:
  - NEW:       findings in scan B not in scan A (regressions / new attack surface)
  - FIXED:     findings in scan A not in scan B (confirmed remediated)
  - UNCHANGED: findings present in both scans

Fingerprinting uses (type, url_path, severity) so minor URL param changes
don't cause false "new" findings.
"""
import json, re, time
from pathlib import Path
from urllib.parse import urlparse

SEV_ORDER  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
SEV_HEX    = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#3b82f6","INFO":"#6b7280"}
SEV_DARK   = {"CRITICAL":"#7f1d1d","HIGH":"#7c2d12","MEDIUM":"#713f12","LOW":"#1e3a5f","INFO":"#1f2937"}
SEV_WEIGHT = {"CRITICAL":30,"HIGH":12,"MEDIUM":4,"LOW":1,"INFO":0}


def _path_only(url: str) -> str:
    """Normalise URL to path only for stable fingerprinting."""
    try:
        return urlparse(url).path.rstrip('/') or '/'
    except Exception:
        return url or ''


def _fingerprint(f: dict) -> str:
    """Stable key for a finding across scans."""
    t    = f.get("type","")
    path = _path_only(f.get("url",""))
    sev  = f.get("severity","INFO")
    return f"{t}|{path}|{sev}"


def diff_scans(scan_a: list, scan_b: list) -> dict:
    """
    Compare two finding lists and return a structured diff.

    Returns:
        {
          "new":        [...],   # in B, not in A  ← regressions
          "fixed":      [...],   # in A, not in B  ← remediated
          "unchanged":  [...],   # in both
          "risk_delta": int,     # B_score - A_score  (negative = improved)
          "score_a":    int,
          "score_b":    int,
          "summary":    {...},
        }
    """
    fp_a = {_fingerprint(f): f for f in scan_a}
    fp_b = {_fingerprint(f): f for f in scan_b}

    keys_a = set(fp_a.keys())
    keys_b = set(fp_b.keys())

    new_keys       = keys_b - keys_a
    fixed_keys     = keys_a - keys_b
    unchanged_keys = keys_a & keys_b

    new_findings       = [fp_b[k] for k in new_keys]
    fixed_findings     = [fp_a[k] for k in fixed_keys]
    unchanged_findings = [fp_b[k] for k in unchanged_keys]

    # Sort each group by severity
    def sev_sort(lst):
        return sorted(lst, key=lambda f: SEV_ORDER.index(f.get("severity","INFO"))
                      if f.get("severity","INFO") in SEV_ORDER else 99)

    score_a = min(100, sum(SEV_WEIGHT.get(f.get("severity","INFO"),0) for f in scan_a))
    score_b = min(100, sum(SEV_WEIGHT.get(f.get("severity","INFO"),0) for f in scan_b))

    def _count_by_sev(lst):
        c = {s:0 for s in SEV_ORDER}
        for f in lst: c[f.get("severity","INFO")] = c.get(f.get("severity","INFO"),0)+1
        return c

    verdict = "IMPROVED" if score_b < score_a else ("WORSENED" if score_b > score_a else "UNCHANGED")

    return {
        "new":             sev_sort(new_findings),
        "fixed":           sev_sort(fixed_findings),
        "unchanged":       sev_sort(unchanged_findings),
        "score_a":         score_a,
        "score_b":         score_b,
        "risk_delta":      score_b - score_a,
        "verdict":         verdict,
        "summary": {
            "new_count":       len(new_findings),
            "fixed_count":     len(fixed_findings),
            "unchanged_count": len(unchanged_findings),
            "new_by_sev":      _count_by_sev(new_findings),
            "fixed_by_sev":    _count_by_sev(fixed_findings),
        }
    }


# ── HTML comparison report ────────────────────────────────────────────────────

def esc(s):
    if not isinstance(s, str): s = str(s) if s is not None else ''
    return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')


def _finding_row(f, status_color, status_label, status_icon):
    sev  = f.get("severity","INFO")
    hex_ = SEV_HEX.get(sev,"#6b7280")
    dark = SEV_DARK.get(sev,"#1f2937")
    return f"""
<tr class="frow" data-status="{status_label.lower()}">
  <td><span style="color:{status_color};font-weight:700;font-size:.8rem">{status_icon} {status_label}</span></td>
  <td><span style="background:{dark};color:{hex_};border:1px solid {hex_};border-radius:3px;
      padding:1px 7px;font-size:.68rem;font-weight:700">{sev}</span></td>
  <td style="font-size:.83rem;color:#f1f5f9">{esc(f.get('detail','') or f.get('type',''))}</td>
  <td style="font-size:.75rem;color:#64748b"><code>{esc(f.get('url','')[:60])}</code></td>
  <td style="font-size:.78rem;color:#94a3b8">{esc(f.get('proof','')[:100] or '—')}</td>
</tr>"""


def generate_diff_html(target_a, target_b, diff, scan_a_label="Scan A", scan_b_label="Scan B"):
    now   = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    delta = diff["risk_delta"]
    verdict = diff["verdict"]
    verdict_color = {"IMPROVED":"#22c55e","WORSENED":"#ef4444","UNCHANGED":"#eab308"}.get(verdict,"#6b7280")
    delta_str = (f"−{abs(delta)}" if delta < 0 else f"+{delta}") if delta != 0 else "±0"

    sa, sb = diff["score_a"], diff["score_b"]

    # Build filter buttons
    tabs = """
<div class="tabs">
  <button class="tab active" onclick="filterStatus('all',this)">All</button>
  <button class="tab new"    onclick="filterStatus('new',this)">🆕 New</button>
  <button class="tab fixed"  onclick="filterStatus('fixed',this)">✅ Fixed</button>
  <button class="tab unch"   onclick="filterStatus('unchanged',this)">➡️ Unchanged</button>
</div>"""

    rows = ""
    for f in diff["new"]:       rows += _finding_row(f,"#ef4444","NEW","🆕")
    for f in diff["fixed"]:     rows += _finding_row(f,"#22c55e","FIXED","✅")
    for f in diff["unchanged"]: rows += _finding_row(f,"#64748b","UNCHANGED","➡️")

    sum_ = diff["summary"]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Mirror Scan Diff — {esc(target_b)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0a0f1e;--card:#111827;--card2:#1e293b;--border:#1e2d45;--text:#e2e8f0;--muted:#64748b}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
      background:var(--bg);color:var(--text);min-height:100vh;font-size:15px}}
.topbar{{background:#060d1a;border-bottom:1px solid var(--border);padding:14px 32px;
         display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}}
.topbar .logo{{font-size:1.1rem;font-weight:800;color:#f8fafc;display:flex;align-items:center;gap:8px}}
.topbar .meta{{font-size:.75rem;color:var(--muted);text-align:right;line-height:1.6}}
.page{{max-width:1280px;margin:0 auto;padding:28px 24px}}
.verdict-banner{{border-radius:12px;padding:22px 28px;margin-bottom:24px;
                 display:flex;align-items:center;gap:28px;flex-wrap:wrap;
                 border:1px solid {verdict_color}33;
                 background:linear-gradient(135deg,{verdict_color}18,{verdict_color}08)}}
.verdict-text h2{{font-size:1.5rem;font-weight:900;color:{verdict_color};margin-bottom:4px}}
.verdict-text p{{color:#94a3b8;font-size:.88rem;line-height:1.6}}
.score-pair{{display:flex;gap:20px;align-items:center;margin-left:auto;flex-wrap:wrap}}
.score-box{{text-align:center;background:#0f172a;border:1px solid var(--border);
            border-radius:10px;padding:14px 20px;min-width:90px}}
.score-box .n{{font-size:1.8rem;font-weight:800;line-height:1}}
.score-box .l{{font-size:.7rem;color:var(--muted);margin-top:3px;text-transform:uppercase;letter-spacing:.4px}}
.delta-box{{font-size:2rem;font-weight:900;color:{verdict_color}}}
.stat-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}}
.stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;
            padding:16px;text-align:center}}
.stat-card .n{{font-size:2rem;font-weight:800;line-height:1}}
.stat-card .l{{font-size:.72rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.4px}}
.scan-labels{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px}}
.scan-label{{background:var(--card);border:1px solid var(--border);border-radius:8px;
             padding:12px 16px;font-size:.85rem}}
.scan-label .tag{{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px}}
.tabs{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}}
.tab{{border:1px solid var(--border);background:var(--card);color:var(--muted);
      border-radius:6px;padding:6px 16px;cursor:pointer;font-size:.82rem;transition:all .12s}}
.tab.active{{background:var(--card2);color:#f1f5f9;border-color:#475569}}
.tab.new{{color:#f97316}}.tab.new.active{{border-color:#f97316;background:#1c0a00}}
.tab.fixed{{color:#22c55e}}.tab.fixed.active{{border-color:#22c55e;background:#001a0d}}
.tab.unch{{color:#64748b}}
.diff-count{{margin-left:auto;font-size:.8rem;color:var(--muted)}}
input.search{{background:var(--card);border:1px solid var(--border);border-radius:8px;
              padding:8px 14px;color:var(--text);font-size:.88rem;width:240px;outline:none;margin-right:8px}}
input.search:focus{{border-color:#3b82f6}}
.table-wrap{{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
table{{width:100%;border-collapse:collapse;font-size:.84rem}}
th{{background:#0f172a;color:var(--muted);padding:9px 14px;text-align:left;
    font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.4px}}
td{{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:#111827}}
.empty{{text-align:center;color:var(--muted);padding:40px 24px;font-size:.9rem}}
@media print{{
  body{{background:#fff;color:#000}}
  .topbar,.tabs,input.search{{display:none}}
  tr.frow{{display:table-row!important}}
  td,th{{border-color:#ddd!important;color:#333!important;background:#fff!important}}
  .verdict-banner,.stat-card,.scan-label{{background:#f9f9f9!important;border-color:#ccc!important}}
}}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">🛡️ Mirror — Scan Comparison</div>
  <div class="meta">Target: <strong>{esc(target_b or target_a)}</strong><br/>{now}</div>
</div>
<div class="page">

  <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
    <button onclick="window.print()" style="background:#2563eb;color:#fff;border:none;border-radius:8px;
      padding:9px 20px;cursor:pointer;font-size:.85rem;font-weight:600">🖨️ Save as PDF</button>
  </div>

  <!-- Verdict banner -->
  <div class="verdict-banner">
    <div class="verdict-text">
      <h2>{verdict}</h2>
      <p>{'Security posture improved — fewer confirmed vulnerabilities.' if verdict=='IMPROVED' else
          'New issues detected since last scan — review NEW findings immediately.' if verdict=='WORSENED' else
          'No change in security posture between scans.'}</p>
      <p style="margin-top:6px;color:#64748b">
        {sum_.get('fixed_count',0)} finding(s) remediated &nbsp;|&nbsp;
        {sum_.get('new_count',0)} new finding(s) &nbsp;|&nbsp;
        {sum_.get('unchanged_count',0)} unchanged
      </p>
    </div>
    <div class="score-pair">
      <div class="score-box"><div class="n" style="color:#94a3b8">{sa}</div><div class="l">Before ({esc(scan_a_label)})</div></div>
      <div class="delta-box">{delta_str}</div>
      <div class="score-box"><div class="n" style="color:{verdict_color}">{sb}</div><div class="l">After ({esc(scan_b_label)})</div></div>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card"><div class="n" style="color:#ef4444">{sum_.get('new_count',0)}</div><div class="l">🆕 New Findings</div></div>
    <div class="stat-card"><div class="n" style="color:#22c55e">{sum_.get('fixed_count',0)}</div><div class="l">✅ Remediated</div></div>
    <div class="stat-card"><div class="n" style="color:#64748b">{sum_.get('unchanged_count',0)}</div><div class="l">➡️ Unchanged</div></div>
  </div>

  <!-- Scan labels -->
  <div class="scan-labels">
    <div class="scan-label"><div class="tag">Before — {esc(scan_a_label)}</div><strong>{esc(target_a or '—')}</strong></div>
    <div class="scan-label"><div class="tag">After — {esc(scan_b_label)}</div><strong>{esc(target_b or '—')}</strong></div>
  </div>

  <!-- Filters -->
  <div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:14px">
    <input class="search" type="text" placeholder="🔍  Search…" oninput="applySearch()">
    {tabs}
    <span class="diff-count" id="diff-count">{len(diff['new'])+len(diff['fixed'])+len(diff['unchanged'])} findings</span>
  </div>

  <!-- Table -->
  <div class="table-wrap">
    <table id="diff-table">
      <tr><th>Status</th><th>Severity</th><th>Finding</th><th>URL</th><th>Proof</th></tr>
      {''.join(f'<tr class="frow" data-status="{esc(row.split("data-status=")[1].split(chr(34))[1] if chr(34) in row else "")}">' + row.split('<tr')[1] if '<tr' in row else row for row in rows.split('</tr>') if '<tr' in row) if rows else ''}
      {'<tr><td colspan="5" class="empty">No findings to compare.</td></tr>' if not rows else ''}
    </table>
  </div>

  <div style="text-align:center;color:#334155;font-size:.75rem;padding:24px 0;
    border-top:1px solid var(--border);margin-top:28px">
    Mirror Scanner Comparison — generated {now}
  </div>
</div>
<script>
let activeStatus = 'all';
function filterStatus(status, btn){{
  activeStatus = status;
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applySearch();
}}
function applySearch(){{
  const q = document.querySelector('.search').value.toLowerCase();
  let vis = 0;
  document.querySelectorAll('.frow').forEach(row => {{
    const ms = activeStatus === 'all' || row.dataset.status === activeStatus;
    const mt = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = (ms && mt) ? '' : 'none';
    if(ms && mt) vis++;
  }});
  document.getElementById('diff-count').textContent = vis + ' finding' + (vis===1?'':'s');
}}
</script>
</body>
</html>"""


def main():
    """CLI usage: python scan_diff.py reports_a/ reports_b/"""
    import sys
    def load_dir(d):
        findings = []
        for jf in sorted(Path(d).glob("*.json")):
            if jf.stem.startswith("_") or jf.stem=="rootchain_report": continue
            try:
                data = json.loads(jf.read_text())
                if isinstance(data, list): findings.extend(data)
            except Exception: pass
        return findings

    if len(sys.argv) < 3:
        print("Usage: scan_diff.py <reports_dir_A> <reports_dir_B>")
        return

    a_dir, b_dir = sys.argv[1], sys.argv[2]
    scan_a = load_dir(a_dir)
    scan_b = load_dir(b_dir)
    diff   = diff_scans(scan_a, scan_b)
    html   = generate_diff_html(a_dir, b_dir, diff, "Scan A", "Scan B")
    out    = Path("reports/diff_report.html")
    out.parent.mkdir(exist_ok=True)
    out.write_text(html, encoding='utf-8')
    print(f"[+] Diff: {diff['summary']['new_count']} new, {diff['summary']['fixed_count']} fixed, {diff['summary']['unchanged_count']} unchanged")
    print(f"[+] Risk: {diff['score_a']} → {diff['score_b']} ({diff['verdict']})")
    print(f"[+] Report → {out}")

if __name__ == '__main__': main()
