#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import time
from pathlib import Path

BANNER = r"""
╔══════════════════════════════════════════════════════════════════╗
║          SECURITY ARSENAL — Professional Assessment Suite        ║
║                  Authorized Testing Only v3.0                    ║
║   GhostCrawler | WAFShatter | HeaderForge | TimeBleed            ║
║   AuthDrift | TokenSniper | DeepLogic | CryptoHunter             ║
║   BackendProbe | WebProbe | RootChain                            ║
╚══════════════════════════════════════════════════════════════════╝
"""

STAGES = [
    ("modules/ghostcrawler.py",  "Stage 1:  Endpoint Discovery & Token Hunt"),
    ("modules/wafshatter.py",    "Stage 2:  WAF/CDN Bypass & Origin Hunt"),
    ("modules/headerforge.py",   "Stage 3:  Security Header & CSP Audit"),
    ("modules/timebleed.py",     "Stage 4:  Blind Injection Timing Oracle"),
    ("modules/authdrift.py",     "Stage 5:  Broken Access Control & Leaks"),
    ("modules/tokensniper.py",   "Stage 6:  JWT & API Token Analysis"),
    ("modules/deeplogic.py",     "Stage 7:  Business Logic Flaws"),
    ("modules/cryptohunter.py",  "Stage 8:  Cryptographic Weaknesses"),
    ("modules/backendprobe.py",  "Stage 9:  Deep Backend Scanning"),
    ("modules/webprobe.py",      "Stage 10: Modern Web Vulnerabilities"),
    ("modules/rootchain.py",     "Stage 11: Attack Chain Correlation"),
]

def check_dependencies():
    try:
        import aiohttp
    except ImportError:
        print("[!] Missing: aiohttp")
        print("[!] Run: pip install aiohttp")
        sys.exit(1)

def print_summary():
    reports = Path("reports")
    if not reports.exists():
        return
    print("\n" + "="*64)
    print("  REPORTS GENERATED:")
    print("="*64)
    total_findings = 0
    for report_file in sorted(reports.glob("*.json")):
        if report_file.name.startswith("_"):
            continue
        try:
            with open(report_file) as f:
                data = json.load(f)
            count = len(data) if isinstance(data, list) else 0
            total_findings += count
            print(f"  {report_file.name:35s}: {count:3d} findings")
        except Exception:
            print(f"  {report_file.name:35s}: (unreadable)")
    print(f"\n  Total findings across all modules: {total_findings}")
    print("="*64)

def main():
    print(BANNER)
    check_dependencies()
    Path("reports").mkdir(exist_ok=True)
    Path("modules").mkdir(exist_ok=True)

    print("[!] LEGAL NOTICE: Only run against assets you have written authorization for.\n")
    target = input("[?] Master target URL: ").strip()
    if not target:
        print("[X] No target provided.")
        return
    if not target.startswith("http"):
        target = "https://" + target

    confirm = input(f"[?] Confirm written authorization for {target} (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[X] Aborting — authorization required.")
        return

    with open("reports/_target.txt", "w") as f:
        f.write(target)

    print(f"\n[+] Target : {target}")
    print(f"[+] Reports: ./reports/")
    print(f"[+] Modules: {len(STAGES)}\n")

    start_time = time.time()
    ran = 0
    skipped = 0

    for script, label in STAGES:
        print("\n" + "="*64)
        print(f"  ▶  {label}")
        print("="*64)

        if not Path(script).exists():
            print(f"  [X] Missing: {script}")
            skipped += 1
            continue

        choice = input(f"  [?] Run {Path(script).name}? (y/n/all/quit): ").strip().lower()

        if choice == "quit":
            print("[*] Quitting pipeline.")
            break
        elif choice == "all":
            print(f"  [*] Running all remaining stages automatically...")
            for remaining_script, remaining_label in STAGES[STAGES.index((script, label)):]:
                print(f"\n  ▶  {remaining_label}")
                if not Path(remaining_script).exists():
                    print(f"  [X] Missing: {remaining_script}")
                    continue
                try:
                    result = subprocess.run(
                        [sys.executable, remaining_script],
                        check=False,
                        capture_output=False
                    )
                    ran += 1
                except KeyboardInterrupt:
                    print("\n[!] Interrupted.")
                    break
                time.sleep(0.5)
            break
        elif choice == "n":
            print("  [*] Skipped.")
            skipped += 1
            continue
        elif choice != "y":
            print("  [*] Skipped.")
            skipped += 1
            continue

        try:
            subprocess.run([sys.executable, script], check=False)
            ran += 1
        except KeyboardInterrupt:
            print("\n[!] Stage interrupted.")
            cont = input("  [?] Continue to next stage? (y/n): ").strip().lower()
            if cont != "y":
                break

        time.sleep(0.5)

    elapsed = time.time() - start_time
    print_summary()
    print(f"\n[+] Completed: {ran} stages ran, {skipped} skipped")
    print(f"[+] Total time: {elapsed:.1f}s")
    print(f"[+] Run rootchain for full correlation: python modules/rootchain.py")

if __name__ == "__main__":
    main()

