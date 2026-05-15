#!/usr/bin/env python3
"""ScanDiff v5 — Scan Comparison & Regression Tracker.

Compares current scan results against a previous baseline to identify:
- New findings (regressions introduced since last scan)
- Resolved findings (vulnerabilities fixed)
- Changed severity (escalations and de-escalations)
- Trend analysis: risk score over time
"""
import json, time, hashlib, sys
from pathlib import Path
from collections import defaultdict

REPORTS_DIR   = Path(__file__).parent.parent / "reports"
BASELINE_FILE = REPORTS_DIR / "_baseline.json"
SEV_ORDER     = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHT    = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def finding_key(f: dict) -> str:
    """Stable key for deduplication across scans."""
    parts = [
        f.get("type", ""),
        str(urlparse_host(f.get("url", ""))),
        f.get("param", ""),
        f.get("cve", ""),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def urlparse_host(url: str) -> str:
    """Return a stable identifier: netloc + full path (no query string).
    Previously truncated to 60 chars which caused two distinct paths to
    hash identically if they shared a long common prefix."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.netloc}{p.path}"
    except Exception:
        return url


def load_current() -> list:
    findings = []
    for jf in sorted(REPORTS_DIR.glob("*.json")):
        if jf.stem.startswith("_") or jf.stem == "rootchain_report":
            continue
        try:
            data = json.loads(jf.read_text())
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict):
                findings.extend(data.get("findings", []))
        except Exception:
            pass
    return findings


def risk_score(findings: list) -> int:
    return min(100, sum(SEV_WEIGHT.get(f.get("severity", "INFO"), 0) for f in findings))


def compare(current: list, baseline: list) -> dict:
    cur_by_key  = {finding_key(f): f for f in current}
    base_by_key = {finding_key(f): f for f in baseline}

    new_keys      = set(cur_by_key) - set(base_by_key)
    resolved_keys = set(base_by_key) - set(cur_by_key)
    common_keys   = set(cur_by_key) & set(base_by_key)

    new_findings      = [cur_by_key[k] for k in new_keys]
    resolved_findings = [base_by_key[k] for k in resolved_keys]
    changed_severity  = []

    for k in common_keys:
        cf = cur_by_key[k]
        bf = base_by_key[k]
        if cf.get("severity") != bf.get("severity"):
            changed_severity.append({
                "type": cf.get("type"),
                "url": cf.get("url"),
                "old_severity": bf.get("severity"),
                "new_severity": cf.get("severity"),
                "escalated": SEV_ORDER.index(cf.get("severity", "INFO")) < SEV_ORDER.index(bf.get("severity", "INFO")),
            })

    cur_risk  = risk_score(current)
    base_risk = risk_score(baseline)
    delta     = cur_risk - base_risk

    sev_new  = defaultdict(int)
    sev_res  = defaultdict(int)
    for f in new_findings:
        sev_new[f.get("severity","INFO")] += 1
    for f in resolved_findings:
        sev_res[f.get("severity","INFO")] += 1

    return {
        "generated_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "risk_score_current": cur_risk,
        "risk_score_baseline": base_risk,
        "risk_delta":         delta,
        "trend":              "WORSE" if delta > 5 else "BETTER" if delta < -5 else "STABLE",
        "new_findings_count": len(new_findings),
        "resolved_count":     len(resolved_findings),
        "changed_severity_count": len(changed_severity),
        "new_by_severity":    dict(sev_new),
        "resolved_by_severity": dict(sev_res),
        "new_findings":       new_findings[:50],
        "resolved_findings":  resolved_findings[:50],
        "changed_severity":   changed_severity[:20],
        "escalations":        [c for c in changed_severity if c["escalated"]][:10],
        "total_current":      len(current),
        "total_baseline":     len(baseline),
    }


def main():
    print("=" * 60)
    print("  ScanDiff v5 — Regression & Comparison Tracker")
    print("=" * 60)
    REPORTS_DIR.mkdir(exist_ok=True)
    current = load_current()
    print(f"[*] Current scan: {len(current)} findings (risk={risk_score(current)}/100)")

    if not BASELINE_FILE.exists():
        print("[*] No baseline found — saving current scan as new baseline")
        baseline_data = {
            "findings": current,
            "risk_score": risk_score(current),
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        BASELINE_FILE.write_text(json.dumps(baseline_data, indent=2, default=str))
        print(f"[+] Baseline saved → {BASELINE_FILE}")
        print("[*] Run again after remediation to compare progress")
        return

    baseline_data = json.loads(BASELINE_FILE.read_text())
    baseline = baseline_data.get("findings", [])
    print(f"[*] Baseline: {len(baseline)} findings (risk={baseline_data.get('risk_score', '?')}/100, saved {baseline_data.get('saved_at','?')})")

    diff = compare(current, baseline)
    print(f"\n[+] Trend: {diff['trend']} (Δ{diff['risk_delta']:+d} risk points)")
    print(f"[+] New: {diff['new_findings_count']} | Resolved: {diff['resolved_count']} | Changed: {diff['changed_severity_count']}")

    if diff["new_findings"]:
        print(f"\n[!] NEW findings since baseline:")
        for f in diff["new_findings"][:10]:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')} — {f.get('url','?')[:60]}")

    if diff["resolved_findings"]:
        print(f"\n[OK] RESOLVED since baseline:")
        for f in diff["resolved_findings"][:10]:
            print(f"    [{f.get('severity','?')}] {f.get('type','?')} — {f.get('url','?')[:60]}")

    if diff["escalations"]:
        print(f"\n[!] ESCALATED severity:")
        for c in diff["escalations"]:
            print(f"    {c['type']}: {c['old_severity']} → {c['new_severity']}")

    out_path = REPORTS_DIR / "scan_diff.json"
    out_path.write_text(json.dumps(diff, indent=2, default=str))
    print(f"\n[+] Diff report → {out_path}")

    # Update baseline option
    if len(sys.argv) > 1 and sys.argv[1] == "--update-baseline":
        baseline_data = {
            "findings": current,
            "risk_score": risk_score(current),
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        BASELINE_FILE.write_text(json.dumps(baseline_data, indent=2, default=str))
        print("[+] Baseline updated to current scan")


if __name__ == "__main__":
    main()
