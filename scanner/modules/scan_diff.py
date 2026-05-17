#!/usr/bin/env python3
"""ScanDiff v9 — Improved Scan Comparison & Regression Tracker.

Compares current scan results against a saved baseline to surface:
  - New findings (regressions): HIGH severity, newly introduced vulnerabilities
  - Resolved findings: fixed vulnerabilities since last scan
  - Worsened findings: same type/URL but higher severity or confidence
  - Improved findings: same type/URL but lower severity
  - Persistent findings: still open from baseline (remediation overdue)
  - Trend analysis: severity-weighted scoring (IMPROVING / DEGRADING / STABLE)

Output:
  - JSON diff report at reports/scan_diff.json
  - Markdown summary at reports/scan_diff.md
  - Console summary with statistics
"""
import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR  = Path(__file__).parent.parent / "reports"
BASELINE_DIR = REPORTS_DIR / "baseline"

SEV_RANK   = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_WEIGHT = {"CRITICAL": 16, "HIGH": 8, "MEDIUM": 3, "LOW": 1, "INFO": 0}


def _load_all_reports(directory: Path) -> list[dict]:
    """Load and flatten all scanner JSON reports from a directory."""
    findings: list[dict] = []
    if not directory.exists():
        return findings
    for fp in sorted(directory.glob("*.json")):
        if fp.name.startswith("_") or fp.name in ("rootchain.json", "scan_diff.json"):
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        item.setdefault("_source_module", fp.stem)
                        findings.append(item)
        except Exception:
            pass
    return findings


def _finding_key(f: dict) -> str:
    """Canonical key for deduplication across scans."""
    raw = (
        f"{f.get('type', '')}|"
        f"{f.get('url', '')}|"
        f"{str(f.get('param', f.get('payload', f.get('key', ''))))[:30]}"
    )
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()


def _severity_rank(sev: str) -> int:
    return SEV_RANK.get(str(sev).upper(), 0)


def _severity_weight(sev: str) -> int:
    return SEV_WEIGHT.get(str(sev).upper(), 0)


def _type_breakdown(findings: list[dict]) -> dict[str, int]:
    """Count findings by type prefix (first segment before underscore)."""
    breakdown: dict[str, int] = {}
    for f in findings:
        ftype = str(f.get("type", "UNKNOWN"))
        prefix = ftype.split("_")[0]
        breakdown[prefix] = breakdown.get(prefix, 0) + 1
    return dict(sorted(breakdown.items(), key=lambda x: x[1], reverse=True))


def _module_breakdown(findings: list[dict]) -> dict[str, int]:
    """Count findings per source module."""
    breakdown: dict[str, int] = {}
    for f in findings:
        mod = str(f.get("_source_module", "unknown"))
        breakdown[mod] = breakdown.get(mod, 0) + 1
    return dict(sorted(breakdown.items(), key=lambda x: x[1], reverse=True))


def compare_scans(current: list[dict], baseline: list[dict]) -> dict:
    """Main comparison logic with severity-weighted trend scoring."""
    current_map  = {_finding_key(f): f for f in current}
    baseline_map = {_finding_key(f): f for f in baseline}

    new_findings: list[dict] = []
    resolved:     list[dict] = []
    worsened:     list[dict] = []
    improved:     list[dict] = []
    persistent:   list[dict] = []

    for key, curr_f in current_map.items():
        if key not in baseline_map:
            new_findings.append(curr_f)
        else:
            base_f   = baseline_map[key]
            curr_sev = _severity_rank(curr_f.get("severity", "INFO"))
            base_sev = _severity_rank(base_f.get("severity", "INFO"))
            if curr_sev > base_sev:
                worsened.append({
                    "finding":           curr_f,
                    "previous_severity": base_f.get("severity", "INFO"),
                    "current_severity":  curr_f.get("severity", "INFO"),
                    "sev_delta":         curr_sev - base_sev,
                })
            elif curr_sev < base_sev:
                improved.append({
                    "finding":           curr_f,
                    "previous_severity": base_f.get("severity", "INFO"),
                    "current_severity":  curr_f.get("severity", "INFO"),
                    "sev_delta":         base_sev - curr_sev,
                })
            else:
                persistent.append(curr_f)

    for key, base_f in baseline_map.items():
        if key not in current_map:
            resolved.append(base_f)

    # Severity breakdowns
    current_sev:  dict[str, int] = {}
    baseline_sev: dict[str, int] = {}
    for f in current:
        s = str(f.get("severity", "INFO"))
        current_sev[s]  = current_sev.get(s, 0) + 1
    for f in baseline:
        s = str(f.get("severity", "INFO"))
        baseline_sev[s] = baseline_sev.get(s, 0) + 1

    # Severity-weighted trend scoring
    # Positive score = degrading, negative = improving
    new_weight       = sum(_severity_weight(f.get("severity", "INFO")) for f in new_findings)
    resolved_weight  = sum(_severity_weight(f.get("severity", "INFO")) for f in resolved)
    worsened_weight  = sum(
        _severity_weight(w["current_severity"]) - _severity_weight(w["previous_severity"])
        for w in worsened
    )
    improved_weight  = sum(
        _severity_weight(i["previous_severity"]) - _severity_weight(i["current_severity"])
        for i in improved
    )
    trend_score = (new_weight + worsened_weight) - (resolved_weight + improved_weight)

    new_critical = sum(1 for f in new_findings if str(f.get("severity", "")).upper() == "CRITICAL")
    new_high     = sum(1 for f in new_findings if str(f.get("severity", "")).upper() == "HIGH")

    if new_critical >= 1 or trend_score > 12:
        trend = "DEGRADING"
    elif trend_score < -8 and len(resolved) > 0:
        trend = "IMPROVING"
    else:
        trend = "STABLE"

    # Type-level new finding breakdown
    new_by_type = _type_breakdown(new_findings)

    # Recommendations
    recommendations: list[str] = []
    if new_critical:
        recommendations.append(
            f"URGENT: {new_critical} new CRITICAL finding(s) introduced — "
            "review immediately before next deployment."
        )
    overdue = [f for f in persistent if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")]
    if overdue:
        recommendations.append(
            f"{len(overdue)} CRITICAL/HIGH finding(s) remain unresolved from baseline — "
            "remediation is overdue."
        )
    if worsened:
        recommendations.append(
            f"{len(worsened)} finding(s) worsened in severity — investigate root cause."
        )
    if trend == "IMPROVING" and resolved:
        recommendations.append(
            f"Positive trend: {len(resolved)} finding(s) resolved. Continue current remediation cadence."
        )
    if not recommendations:
        recommendations.append("No urgent actions identified. Maintain current security posture.")

    return {
        "scan_timestamp":     datetime.now(timezone.utc).isoformat(),
        "trend_verdict":      trend,
        "trend_score":        trend_score,
        "summary": {
            "current_total":   len(current),
            "baseline_total":  len(baseline),
            "new_findings":    len(new_findings),
            "resolved":        len(resolved),
            "worsened":        len(worsened),
            "improved":        len(improved),
            "persistent":      len(persistent),
            "new_critical":    new_critical,
            "new_high":        new_high,
        },
        "severity_breakdown": {
            "current":  current_sev,
            "baseline": baseline_sev,
        },
        "type_breakdown": {
            "current_new":     new_by_type,
            "current_all":     _type_breakdown(current),
        },
        "module_breakdown": {
            "current":  _module_breakdown(current),
            "baseline": _module_breakdown(baseline),
        },
        "recommendations":     recommendations,
        "new_findings":        new_findings[:50],
        "resolved":            resolved[:50],
        "worsened":            worsened[:20],
        "improved":            improved[:20],
        "persistent":          persistent[:50],
        "remediation_overdue": overdue[:20],
    }


def save_baseline():
    """Save current reports as new baseline."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    saved = 0
    for fp in REPORTS_DIR.glob("*.json"):
        if fp.name.startswith("_") or fp.name in ("rootchain.json", "scan_diff.json"):
            continue
        try:
            (BASELINE_DIR / fp.name).write_text(fp.read_text(encoding="utf-8", errors="replace"))
            saved += 1
        except Exception:
            pass
    print(f"[+] Baseline saved: {saved} report file(s) → {BASELINE_DIR}")


def _write_markdown(result: dict, out_path: Path):
    """Write a Markdown summary of the diff report."""
    s    = result["summary"]
    ts   = result["scan_timestamp"]
    trend = result["trend_verdict"]
    trend_label = {"DEGRADING": "[DOWN] DEGRADING", "IMPROVING": "[UP] IMPROVING",
                   "STABLE": "[--] STABLE"}.get(trend, trend)
    lines = [
        f"# ScanDiff v9 — Regression Report",
        f"\nGenerated: {ts}",
        f"\n## Trend: {trend_label}  (score: {result.get('trend_score', 0):+d})\n",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Current total | {s['current_total']} |",
        f"| Baseline total | {s['baseline_total']} |",
        f"| New findings | {s['new_findings']} ({s['new_critical']} CRITICAL, {s['new_high']} HIGH) |",
        f"| Resolved | {s['resolved']} |",
        f"| Worsened | {s['worsened']} |",
        f"| Improved | {s['improved']} |",
        f"| Persistent | {s['persistent']} |",
    ]
    if result.get("recommendations"):
        lines.append("\n## Recommendations\n")
        for rec in result["recommendations"]:
            lines.append(f"- {rec}")
    if result.get("remediation_overdue"):
        lines.append(f"\n## Overdue CRITICAL/HIGH Findings ({len(result['remediation_overdue'])})\n")
        for f in result["remediation_overdue"][:10]:
            lines.append(
                f"- **[{f.get('severity','?')}]** `{f.get('type','?')}` — "
                f"`{str(f.get('url',''))[:80]}`"
            )
    if result.get("new_findings"):
        lines.append(f"\n## New Findings ({s['new_findings']})\n")
        for f in result["new_findings"][:10]:
            lines.append(
                f"- **[{f.get('severity','?')}]** `{f.get('type','?')}` — "
                f"`{str(f.get('url',''))[:80]}`"
            )
    try:
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ScanDiff v9 — Regression Tracker")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save current scan as new baseline")
    args = parser.parse_args()

    print("=" * 60)
    print("  ScanDiff v9 — Scan Comparison & Regression Tracker")
    print("=" * 60)

    if args.save_baseline:
        save_baseline()
        return

    current  = _load_all_reports(REPORTS_DIR)
    baseline = _load_all_reports(BASELINE_DIR)

    if not baseline:
        print("[!] No baseline found. Run with --save-baseline first.")
        print(f"    Current scan: {len(current)} findings")
        if current:
            save_baseline()
            print("[+] Current scan saved as initial baseline for next comparison.")
        return

    print(f"\n[*] Current: {len(current)} findings | Baseline: {len(baseline)} findings")
    result = compare_scans(current, baseline)

    trend_label = {"DEGRADING": "[DOWN] DEGRADING", "IMPROVING": "[UP] IMPROVING",
                   "STABLE": "[--] STABLE"}.get(result["trend_verdict"], result["trend_verdict"])
    print(f"\n  Trend    : {trend_label}  (weighted score: {result.get('trend_score', 0):+d})")
    s = result["summary"]
    print(f"  New      : {s['new_findings']}  ({s['new_critical']} CRITICAL, {s['new_high']} HIGH)")
    print(f"  Resolved : {s['resolved']}  |  Worsened: {s['worsened']}  |  Persistent: {s['persistent']}")

    if result.get("type_breakdown", {}).get("current_new"):
        top_new = list(result["type_breakdown"]["current_new"].items())[:4]
        print(f"  New types: {', '.join(f'{k}:{v}' for k, v in top_new)}")

    if result["remediation_overdue"]:
        print(f"\n  [!] Overdue CRITICAL/HIGH: {len(result['remediation_overdue'])}")
        for f in result["remediation_overdue"][:3]:
            print(f"      [{f.get('severity','?')}] {f.get('type','?')}: "
                  f"{str(f.get('url',''))[:60]}")

    if result.get("recommendations"):
        print("\n  Recommendations:")
        for rec in result["recommendations"][:3]:
            print(f"    - {rec}")

    out_json = REPORTS_DIR / "scan_diff.json"
    out_md   = REPORTS_DIR / "scan_diff.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    _write_markdown(result, out_md)
    print(f"\n[+] Diff report → {out_json}")
    print(f"[+] Markdown    → {out_md}")
    return result


if __name__ == "__main__":
    main()
