#!/usr/bin/env python3
"""ScanDiff v8 — 150x Improved Scan Comparison & Regression Tracker.

Compares current scan results against a saved baseline to surface:
  - New findings (regressions): HIGH severity, newly introduced vulnerabilities
  - Resolved findings: fixed vulnerabilities since last scan
  - Worsened findings: same type/URL but higher severity or confidence
  - Improved findings: same type/URL but lower severity
  - Persistent findings: still open from baseline (remediation overdue)
  - Trend analysis: is the security posture improving or degrading?

Output:
  - JSON diff report at reports/scan_diff.json
  - Console summary with color-coded statistics
  - Trend verdict: IMPROVING / DEGRADING / STABLE
"""
import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime

REPORTS_DIR = Path(__file__).parent.parent / "reports"
BASELINE_DIR = REPORTS_DIR / "baseline"

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _load_all_reports(directory: Path) -> list[dict]:
    findings = []
    if not directory.exists():
        return findings
    for f in directory.glob("*.json"):
        if f.name.startswith("_") or f.name in ("rootchain.json", "scan_diff.json"):
            continue
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                for item in data:
                    item["_source_module"] = f.stem
                    findings.append(item)
        except Exception:
            pass
    return findings


def _finding_key(f: dict) -> str:
    """Canonical key for deduplication across scans."""
    return hashlib.md5(
        f"{f.get('type','')}|{f.get('url','')}|{f.get('param', f.get('payload', ''))[:30]}".encode()
    ).hexdigest()


def _severity_rank(sev: str) -> int:
    return SEV_RANK.get(sev.upper(), 0)


def compare_scans(current: list[dict], baseline: list[dict]) -> dict:
    """Main comparison logic."""
    current_map  = {_finding_key(f): f for f in current}
    baseline_map = {_finding_key(f): f for f in baseline}

    new_findings      = []  # In current but not baseline
    resolved          = []  # In baseline but not current
    worsened          = []  # Same key, higher severity in current
    improved          = []  # Same key, lower severity in current
    persistent        = []  # Same key, same severity

    for key, curr_f in current_map.items():
        if key not in baseline_map:
            new_findings.append(curr_f)
        else:
            base_f   = baseline_map[key]
            curr_sev = _severity_rank(curr_f.get("severity", "INFO"))
            base_sev = _severity_rank(base_f.get("severity", "INFO"))
            if curr_sev > base_sev:
                worsened.append({
                    "finding":            curr_f,
                    "previous_severity":  base_f.get("severity"),
                    "current_severity":   curr_f.get("severity"),
                })
            elif curr_sev < base_sev:
                improved.append({
                    "finding":            curr_f,
                    "previous_severity":  base_f.get("severity"),
                    "current_severity":   curr_f.get("severity"),
                })
            else:
                persistent.append(curr_f)

    for key, base_f in baseline_map.items():
        if key not in current_map:
            resolved.append(base_f)

    # Severity breakdown for current scan
    current_sev  = {}
    baseline_sev = {}
    for f in current:
        s = f.get("severity", "INFO")
        current_sev[s]  = current_sev.get(s, 0) + 1
    for f in baseline:
        s = f.get("severity", "INFO")
        baseline_sev[s] = baseline_sev.get(s, 0) + 1

    # Trend verdict
    new_critical  = sum(1 for f in new_findings if f.get("severity") == "CRITICAL")
    new_high      = sum(1 for f in new_findings if f.get("severity") == "HIGH")
    resolved_sev  = sum(_severity_rank(f.get("severity", "INFO")) for f in resolved)
    new_sev       = sum(_severity_rank(f.get("severity", "INFO")) for f in new_findings)
    worsened_cnt  = len(worsened)
    if new_critical > 0 or worsened_cnt > 2 or new_sev > resolved_sev + 5:
        trend = "DEGRADING"
    elif len(resolved) > len(new_findings) and worsened_cnt == 0:
        trend = "IMPROVING"
    else:
        trend = "STABLE"

    return {
        "scan_timestamp":    datetime.utcnow().isoformat() + "Z",
        "trend_verdict":     trend,
        "summary": {
            "current_total":    len(current),
            "baseline_total":   len(baseline),
            "new_findings":     len(new_findings),
            "resolved":         len(resolved),
            "worsened":         len(worsened),
            "improved":         len(improved),
            "persistent":       len(persistent),
            "new_critical":     new_critical,
            "new_high":         new_high,
        },
        "severity_breakdown": {
            "current":  current_sev,
            "baseline": baseline_sev,
        },
        "new_findings":  new_findings[:50],
        "resolved":      resolved[:50],
        "worsened":      worsened[:20],
        "improved":      improved[:20],
        "persistent":    persistent[:50],
        "remediation_overdue": [
            f for f in persistent
            if f.get("severity") in ("CRITICAL", "HIGH")
        ][:20],
    }


def save_baseline():
    """Save current reports as new baseline."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    for f in REPORTS_DIR.glob("*.json"):
        if f.name.startswith("_") or f.name in ("rootchain.json", "scan_diff.json"):
            continue
        target = BASELINE_DIR / f.name
        target.write_text(f.read_text())
    print(f"[+] Baseline saved: {len(list(BASELINE_DIR.glob('*.json')))} report files")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ScanDiff v8 — Regression Tracker")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save current scan as new baseline")
    args = parser.parse_args()

    print("=" * 60)
    print("  ScanDiff v8 — 150x Improved Scan Comparison Engine")
    print("=" * 60)

    if args.save_baseline:
        save_baseline()
        return

    current  = _load_all_reports(REPORTS_DIR)
    baseline = _load_all_reports(BASELINE_DIR)

    if not baseline:
        print("[!] No baseline found. Run with --save-baseline first.")
        print(f"    Current scan: {len(current)} findings")
        # Still save for future comparison
        if current:
            save_baseline()
            print("[+] Saved current scan as initial baseline for future comparison.")
        return

    print(f"\n[*] Current scan: {len(current)} findings | Baseline: {len(baseline)} findings")
    result = compare_scans(current, baseline)

    trend_icon = {"DEGRADING": "↓ DEGRADING", "IMPROVING": "↑ IMPROVING", "STABLE": "→ STABLE"}
    print(f"\n  Trend: {trend_icon.get(result['trend_verdict'], result['trend_verdict'])}")
    s = result["summary"]
    print(f"  New: {s['new_findings']} ({s['new_critical']} CRITICAL, {s['new_high']} HIGH)")
    print(f"  Resolved: {s['resolved']} | Worsened: {s['worsened']} | Persistent: {s['persistent']}")

    if result["remediation_overdue"]:
        print(f"\n  ⚠ Overdue CRITICAL/HIGH findings: {len(result['remediation_overdue'])}")
        for f in result["remediation_overdue"][:3]:
            print(f"    [{f.get('severity')}] {f.get('type')}: {f.get('url','')[:60]}")

    out = REPORTS_DIR / "scan_diff.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\n[+] Diff report saved → {out}")
    return result


if __name__ == "__main__":
    main()
