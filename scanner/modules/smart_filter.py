#!/usr/bin/env python3
"""smart_filter.py v8 — Shared utilities for all Mirror scanner modules.

Provides:
  - delay(): configurable async sleep with jitter
  - confidence_label(): human-readable label from numeric confidence
  - meets_confidence_floor(): minimum confidence gate (65)
  - random_ua(): randomized realistic User-Agent string
  - WAF_BYPASS_HEADERS: common bypass headers dict
  - REQUEST_DELAY: global base delay seconds
  - shannon_entropy(): entropy calculation for secret detection
  - severity_sanity_check(): cap/normalize severity/confidence
  - enrich_finding(): add exploit dimensions to finding dict
  - dedup_key(): canonical deduplication key
  - build_baseline_404(): fingerprint soft 404 status codes
  - MITRE_MAP: MITRE ATT&CK technique → name lookup
  - CONFIDENCE_FLOOR: minimum confidence to report (65)
"""
import asyncio
import math
import random
import time
import hashlib
from pathlib import Path

CONFIDENCE_FLOOR = 65
REQUEST_DELAY    = 0.05  # seconds base delay between requests

MITRE_MAP: dict[str, str] = {
    "T1059":     "Command and Scripting Interpreter",
    "T1059.007": "JavaScript",
    "T1078":     "Valid Accounts",
    "T1082":     "System Information Discovery",
    "T1083":     "File and Directory Discovery",
    "T1087":     "Account Discovery",
    "T1110":     "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing",
    "T1185":     "Browser Session Hijacking",
    "T1190":     "Exploit Public-Facing Application",
    "T1195":     "Supply Chain Compromise",
    "T1497":     "Virtualization/Sandbox Evasion",
    "T1499":     "Endpoint Denial of Service",
    "T1518":     "Software Discovery",
    "T1528":     "Steal Application Access Token",
    "T1539":     "Steal Web Session Cookie",
    "T1552":     "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.005": "Cloud Instance Metadata API",
    "T1557":     "Adversary-in-the-Middle",
    "T1562.001": "Disable or Modify Tools",
    "T1565":     "Data Manipulation",
    "T1566":     "Phishing",
    "T1584":     "Compromise Infrastructure",
    "T1600":     "Weaken Encryption",
}

# Realistic User-Agent pool (desktop + mobile + bots)
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# Common WAF bypass headers added to all requests
WAF_BYPASS_HEADERS: dict[str, str] = {
    "X-Forwarded-For":       "127.0.0.1",
    "X-Real-IP":             "127.0.0.1",
    "X-Originating-IP":      "127.0.0.1",
    "X-Remote-Addr":         "127.0.0.1",
    "Accept":                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":       "en-US,en;q=0.9",
    "Accept-Encoding":       "gzip, deflate, br",
    "Cache-Control":         "no-cache",
    "Pragma":                "no-cache",
    "Connection":            "keep-alive",
}


def random_ua() -> str:
    """Return a random realistic User-Agent string."""
    return random.choice(_USER_AGENTS)


async def delay(seconds: float | None = None) -> None:
    """Async sleep with optional jitter to avoid detection."""
    base = seconds if seconds is not None else REQUEST_DELAY
    jitter = random.uniform(0, base * 0.3)
    await asyncio.sleep(max(0.01, base + jitter))


def confidence_label(conf: int) -> str:
    """Human-readable label from numeric confidence 0-100."""
    if conf >= 95:
        return "Confirmed"
    if conf >= 85:
        return "High"
    if conf >= 70:
        return "Medium"
    if conf >= 50:
        return "Low"
    return "Tentative"


def meets_confidence_floor(conf: int) -> bool:
    """True if finding should be reported (above minimum threshold)."""
    return conf >= CONFIDENCE_FLOOR


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def dedup_key(finding: dict) -> str:
    """Generate canonical deduplication key for a finding."""
    parts = [
        finding.get("type", ""),
        finding.get("url", ""),
        finding.get("payload", finding.get("param", ""))[:30],
        finding.get("secret_type", ""),
        finding.get("bypass_technique", ""),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def severity_sanity_check(finding: dict) -> dict:
    """Normalize severity and confidence. Cap INFO findings at 80 confidence."""
    sev = finding.get("severity", "INFO").upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        finding["severity"] = "INFO"
    conf = int(finding.get("confidence", 70))
    if sev == "INFO" and conf > 80:
        finding["confidence"] = 80
    if conf > 100:
        finding["confidence"] = 100
    if conf < 0:
        finding["confidence"] = 0
    finding["severity"] = sev
    return finding


def enrich_finding(finding: dict) -> dict:
    """Add exploit dimension fields if missing."""
    sev = finding.get("severity", "INFO")
    score_map = {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1}
    if "exploitability" not in finding:
        finding["exploitability"] = score_map.get(sev, 1)
    if "impact" not in finding:
        finding["impact"] = (
            f"{sev.title()} severity — see detail for impact analysis."
        )
    if "reproducibility" not in finding:
        finding["reproducibility"] = "See proof field."
    if "auth_required" not in finding:
        finding["auth_required"] = False
    if "mitigation_layers" not in finding:
        finding["mitigation_layers"] = ["Remediation required"]
    # Add MITRE name if only technique is present
    if "mitre_technique" in finding and "mitre_name" not in finding:
        finding["mitre_name"] = MITRE_MAP.get(finding["mitre_technique"], "Unknown")
    if "confidence_label" not in finding:
        finding["confidence_label"] = confidence_label(finding.get("confidence", 70))
    return finding


async def build_baseline_404(sess, target: str) -> set:
    """
    Probe a few random paths to discover what status codes the server
    returns for non-existent resources (soft-404 detection).
    Returns a set of status codes that are the server's 404 equivalent.
    """
    import aiohttp
    probe_paths = [
        "/this_path_definitely_does_not_exist_mirror_scan",
        "/xyzzy_nonexistent_page_scan",
        "/api/nonexistent_mirror_probe_endpoint",
    ]
    statuses: list[int] = []
    for path in probe_paths:
        url = target.rstrip("/") + path
        try:
            async with sess.get(
                url,
                headers={**WAF_BYPASS_HEADERS, "User-Agent": random_ua()},
                ssl=False,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=12, connect=8),
            ) as r:
                statuses.append(r.status)
        except Exception:
            pass
        await asyncio.sleep(0.1)
    # The most common status among probes is the soft-404 equivalent
    if not statuses:
        return {404}
    from collections import Counter
    common = Counter(statuses).most_common(1)[0][0]
    return {404, common}
