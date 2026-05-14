#!/usr/bin/env python3
"""smart_filter.py — Shared utilities for all Mirror scanner modules."""
import asyncio, random, time, math, hashlib
from pathlib import Path

REQUEST_DELAY = 0.18

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

WAF_BYPASS_HEADERS = {
    "X-Forwarded-For":   "127.0.0.1",
    "X-Real-IP":         "127.0.0.1",
    "X-Originating-IP":  "127.0.0.1",
    "X-Remote-IP":       "127.0.0.1",
    "X-Remote-Addr":     "127.0.0.1",
    "X-Client-IP":       "127.0.0.1",
    "CF-Connecting-IP":  "127.0.0.1",
    "True-Client-IP":    "127.0.0.1",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "Forwarded":         "for=127.0.0.1;proto=https",
}

CONFIDENCE_FLOOR = 65  # raised from 60

def random_ua():
    return random.choice(USER_AGENTS)

async def delay(base=REQUEST_DELAY, jitter=0.08):
    await asyncio.sleep(base + random.uniform(0, jitter))

def confidence_score(checks: dict) -> int:
    total, earned = 0, 0
    for _, (passed, weight) in checks.items():
        total += weight
        if passed:
            earned += weight
    return int((earned / total) * 100) if total else 0

def confidence_label(score: int) -> str:
    if score >= 90: return "Confirmed"
    if score >= 75: return "High"
    if score >= 60: return "Medium"
    if score >= 40: return "Low"
    return "Speculative"

def meets_confidence_floor(score: int) -> bool:
    return score >= CONFIDENCE_FLOOR

def severity_from_confidence(base_sev: str, conf: int) -> str:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx   = order.index(base_sev) if base_sev in order else 2
    if conf < 50 and idx > 1:
        idx -= 1
    return order[idx]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

def dedup_key(finding: dict) -> str:
    parts = [
        finding.get("type", ""),
        finding.get("url", ""),
        finding.get("param", ""),
        finding.get("cve", ""),
    ]
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()

async def build_baseline_404(sess, target: str) -> set:
    import aiohttp
    known_bad = set()
    test_paths = [
        "/this-path-does-not-exist-mirror-test",
        "/404test_mirror_xz99",
        "/nonexistent/deep/path/mirror",
    ]
    for path in test_paths:
        try:
            async with sess.get(
                target + path,
                headers={"User-Agent": random_ua()},
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
            ) as r:
                body = await r.text(errors="ignore")
                known_bad.add(r.status)
                if len(body) < 500:
                    known_bad.add(f"body:{len(body)}")
        except Exception:
            pass
        await delay()
    return known_bad

def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    if cvss >= 0.1: return "LOW"
    return "INFO"

MITRE_MAP = {
    "SQLI":              ("T1190", "Exploit Public-Facing Application"),
    "SQLI_BLIND":        ("T1190", "Exploit Public-Facing Application"),
    "CMD_INJECTION":     ("T1059", "Command and Scripting Interpreter"),
    "SSRF":              ("T1090", "Proxy"),
    "XXE":               ("T1190", "Exploit Public-Facing Application"),
    "JWT":               ("T1550.001", "Use Alternate Authentication Material: Application Access Token"),
    "IDOR":              ("T1078", "Valid Accounts"),
    "OPEN_REDIRECT":     ("T1566", "Phishing"),
    "SSTI":              ("T1190", "Exploit Public-Facing Application"),
    "PATH_TRAVERSAL":    ("T1083",  "File and Directory Discovery"),
    "SECRET_EXPOSURE":   ("T1552.001", "Credentials In Files"),
    "WEAK_TLS":          ("T1557", "Adversary-in-the-Middle"),
    "CORS_MISCONFIGURED":("T1557", "Adversary-in-the-Middle"),
    "AUTH_BYPASS":       ("T1078", "Valid Accounts"),
}


  def severity_sanity_check(finding: dict) -> dict:
      """
      Global false-positive guard: enforce severity caps based on evidence quality.
      - CRITICAL requires confidence ≥ 95
      - HIGH requires confidence ≥ 80
      - Never allow 403/401/302 status alone to produce HIGH/CRITICAL
      - Server-disclosure findings capped at INFO
      """
      sev = finding.get("severity", "INFO")
      conf = finding.get("confidence", 0)
      ftype = finding.get("type", "")

      # Disclosure-only findings — cap at INFO
      DISCLOSURE_TYPES = {
          "SERVER_VERSION_DISCLOSURE", "SERVER_DISCLOSURE", "DNS_RESOLVED_IP",
          "ENDPOINT_DISCOVERED", "RATE_LIMIT_ACTIVE",
      }
      if ftype in DISCLOSURE_TYPES and sev in ("HIGH", "CRITICAL", "MEDIUM"):
          finding["severity"] = "INFO"
          return finding

      # CRITICAL requires very high confidence
      if sev == "CRITICAL" and conf < 95:
          finding["severity"] = "HIGH"

      # HIGH requires solid confidence
      if sev == "HIGH" and conf < 75:
          finding["severity"] = "MEDIUM"

      return finding
  