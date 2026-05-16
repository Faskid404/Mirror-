#!/usr/bin/env python3
"""smart_filter.py v9 — Massively enhanced shared utilities for all Mirror scanner modules.

Provides:
  - delay(): configurable async sleep with jitter
  - confidence_label(): human-readable label from numeric confidence
  - confidence_score(): weighted factor scoring for cveprobe compatibility
  - severity_from_confidence(): derive severity from confidence score
  - meets_confidence_floor(): minimum confidence gate (65)
  - random_ua(): randomised realistic User-Agent string
  - WAF_BYPASS_HEADERS: 30+ bypass headers dict (always-on baseline)
  - make_bypass_headers(ip, extra): per-request rotating IP bypass headers
  - PATH_BYPASS_VARIANTS(path): generate 30+ normalised path variants
  - METHOD_BYPASS_HEADERS: HTTP method override headers
  - REQUEST_DELAY: global base delay seconds
  - shannon_entropy(): entropy calculation for secret detection
  - severity_sanity_check(): cap/normalise severity/confidence
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
from urllib.parse import quote

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

# ── Realistic User-Agent pool — desktop + mobile + bots + scanners ─────────────
_USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    # Search crawlers (bypass some WAF bot-detection rules)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/126.0.6478.126 Safari/537.36",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    # Trusted monitoring agents (bypass some WAF/CDN policies)
    "Datadog Agent/7.52.0",
    "New Relic Browser monitoring",
    "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",
]

# ── Internal IP pool for rotating IP spoofing headers ─────────────────────────
_BYPASS_IPS = [
    "127.0.0.1",
    "127.0.0.2",
    "10.0.0.1",
    "10.0.0.100",
    "10.10.10.1",
    "10.20.30.1",
    "172.16.0.1",
    "172.16.1.100",
    "172.31.0.1",
    "192.168.0.1",
    "192.168.1.1",
    "192.168.100.1",
    "::1",
    "0.0.0.0",
    "localhost",
    "0x7f000001",   # 127.0.0.1 hex
    "2130706433",   # 127.0.0.1 decimal
    "0177.0.0.01",  # 127.0.0.1 octal
]

# ── Baseline WAF bypass headers added to EVERY request ────────────────────────
WAF_BYPASS_HEADERS: dict[str, str] = {
    # IP spoofing — tell the server/WAF we come from localhost/trusted internal
    "X-Forwarded-For":           "127.0.0.1",
    "X-Real-IP":                 "127.0.0.1",
    "X-Originating-IP":          "127.0.0.1",
    "X-Remote-Addr":             "127.0.0.1",
    "X-Remote-IP":               "127.0.0.1",
    "X-Client-IP":               "127.0.0.1",
    "X-Cluster-Client-IP":       "127.0.0.1",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "True-Client-IP":            "127.0.0.1",
    "CF-Connecting-IP":          "127.0.0.1",
    "Fastly-Client-IP":          "127.0.0.1",
    "X-ProxyUser-Ip":            "127.0.0.1",
    "Client-IP":                 "127.0.0.1",
    "Forwarded":                 "for=127.0.0.1;proto=https",
    # Host/protocol tricks
    "X-Forwarded-Host":          "localhost",
    "X-Host":                    "localhost",
    "X-Forwarded-Proto":         "https",
    "X-Forwarded-Scheme":        "https",
    "X-Original-URL":            "/",
    "X-Rewrite-URL":             "/",
    # Browser-realistic headers
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Cache-Control":             "no-cache",
    "Pragma":                    "no-cache",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site":            "none",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-User":            "?1",
    "Sec-Fetch-Dest":            "document",
}

# ── HTTP method override headers (bypass 403 on restricted methods) ────────────
METHOD_BYPASS_HEADERS: dict[str, dict[str, str]] = {
    "GET_override":      {"X-HTTP-Method-Override": "GET", "X-Method-Override": "GET", "_method": "GET"},
    "POST_override":     {"X-HTTP-Method-Override": "POST", "X-Method-Override": "POST"},
    "DELETE_override":   {"X-HTTP-Method-Override": "DELETE", "X-Method-Override": "DELETE"},
    "PUT_override":      {"X-HTTP-Method-Override": "PUT"},
    "PATCH_override":    {"X-HTTP-Method-Override": "PATCH"},
}

# ── Per-request rotating IP bypass header generator ───────────────────────────
def make_bypass_headers(ip: str | None = None, extra: dict | None = None) -> dict:
    """
    Build a fresh WAF-bypass header dict for a single request.
    Rotates through internal IPs to avoid pattern matching.
    Optional ``ip`` pins a specific spoofed IP; otherwise one is chosen randomly.
    Optional ``extra`` dict is merged on top.
    """
    chosen_ip = ip or random.choice(_BYPASS_IPS)
    h = {
        "X-Forwarded-For":           f"{chosen_ip}, {random.choice(_BYPASS_IPS)}",
        "X-Real-IP":                 chosen_ip,
        "X-Originating-IP":          chosen_ip,
        "X-Remote-Addr":             chosen_ip,
        "X-Remote-IP":               chosen_ip,
        "X-Client-IP":               chosen_ip,
        "X-Cluster-Client-IP":       chosen_ip,
        "X-Custom-IP-Authorization": chosen_ip,
        "True-Client-IP":            chosen_ip,
        "CF-Connecting-IP":          chosen_ip,
        "Fastly-Client-IP":          chosen_ip,
        "X-ProxyUser-Ip":            chosen_ip,
        "Client-IP":                 chosen_ip,
        "Forwarded":                 f"for={chosen_ip};proto=https;by={random.choice(_BYPASS_IPS)}",
        "X-Forwarded-Host":          "localhost",
        "X-Host":                    "localhost",
        "X-Forwarded-Proto":         "https",
        "X-Forwarded-Scheme":        "https",
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":           "en-US,en;q=0.9",
        "Accept-Encoding":           "gzip, deflate, br",
        "Cache-Control":             "no-cache",
        "Pragma":                    "no-cache",
        "Connection":                "keep-alive",
        "User-Agent":                random_ua(),
    }
    if extra:
        h.update(extra)
    return h


def PATH_BYPASS_VARIANTS(path: str) -> list[tuple[str, str]]:
    """
    Generate 30+ normalised path variants for a given path to bypass WAF/ACL rules.
    Each tuple is (variant_path, technique_label).
    """
    p = path.rstrip("/")
    base = p.lstrip("/")
    variants: list[tuple[str, str]] = [
        (p,                                    "original"),
        (p + "/",                              "trailing-slash"),
        (p.upper(),                            "uppercase"),
        (p.capitalize(),                       "capitalize"),
        ("/" + base[0].upper() + base[1:],     "first-char-upper"),
        (f"/{base[0].lower()}{base[1:].upper()}", "mixed-case"),
        ("/" + quote(base, safe=""),           "url-encoded"),
        ("/" + quote(base, safe="").replace("%", "%25"), "double-url-encoded"),
        (f"/{base}%20",                        "trailing-space"),
        (f"/{base}%09",                        "trailing-tab"),
        (f"/{base}%00",                        "null-byte"),
        (f"/{base}%0a",                        "newline-byte"),
        (f"/{base}.json",                      "json-extension"),
        (f"/{base}.html",                      "html-extension"),
        (f"/{base}.php",                       "php-extension"),
        (f"/{base}.asp",                       "asp-extension"),
        (f"/{base};.js",                       "semicolon-js"),
        (f"/{base};.css",                      "semicolon-css"),
        (f"/./{base}",                         "dot-prefix"),
        (f"/{base}/.",                         "dot-suffix"),
        (f"//{base}",                          "double-slash"),
        (f"/{base}//",                         "double-slash-suffix"),
        (f"///{base}",                         "triple-slash"),
        (f"/{base}?",                          "empty-query"),
        (f"/{base}?x=1",                       "dummy-query"),
        (f"/{base}?x=1&y=2",                   "multi-query"),
        (f"/{base}#",                          "hash-fragment"),
        (f"/..;/{base}",                       "dot-dot-semicolon"),
        (f"/{base}/..;/",                      "path-traversal-semicolon"),
        (f"/%2F{base}",                        "encoded-leading-slash"),
        (f"/{base}%2F",                        "encoded-trailing-slash"),
        (f"/{base}%5C",                        "backslash-suffix"),
        ("/" + "".join(f"%{ord(c):02x}" if c.isalpha() else c for c in base), "hex-chars"),
        (f"/api/v1/../{base}" if not base.startswith("api") else f"/{base}/../{base}", "traversal-bypass"),
    ]
    # Unicode full-width character variants (bypass WAF pattern matching)
    fw = {"a": "ａ", "d": "ｄ", "m": "ｍ", "i": "ｉ", "n": "ｎ",
          "s": "ｓ", "e": "ｅ", "r": "ｒ", "u": "ｕ", "p": "ｐ"}
    fw_path = "/" + "".join(fw.get(c, c) for c in base)
    if fw_path != f"/{base}":
        variants.append((fw_path, "unicode-fullwidth"))
    return variants


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


def confidence_score(factors: dict) -> int:
    """
    Weighted confidence score from a factor dict:
      {factor_name: (bool_value, int_weight)}
    Returns 0-100.
    Compatible with cveprobe.py usage pattern.
    """
    if not factors:
        return 0
    total = 0
    max_total = 0
    for _name, val in factors.items():
        if isinstance(val, (tuple, list)) and len(val) == 2:
            flag, weight = val
            max_total += weight
            if flag:
                total += weight
        elif isinstance(val, bool):
            max_total += 1
            if val:
                total += 1
    if max_total == 0:
        return 0
    return min(100, int(total * 100 / max_total))


def severity_from_confidence(severity: str, conf: int) -> str:
    """
    Optionally upgrade severity if confidence is very high,
    or downgrade if confidence is low. Ensures severity is sensible.
    """
    sev = severity.upper() if severity else "INFO"
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev = "INFO"
    if conf < 50 and sev in ("CRITICAL", "HIGH"):
        return "MEDIUM"
    if conf >= 90 and sev == "LOW":
        return "MEDIUM"
    return sev


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
        str(finding.get("payload", finding.get("param", "")))[:30],
        finding.get("secret_type", ""),
        finding.get("bypass_technique", ""),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def severity_sanity_check(finding: dict) -> dict:
    """Normalise severity and confidence. Cap INFO findings at 80 confidence."""
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
    if "mitre_technique" in finding and "mitre_name" not in finding:
        finding["mitre_name"] = MITRE_MAP.get(finding["mitre_technique"], "Unknown")
    if "confidence_label" not in finding:
        finding["confidence_label"] = confidence_label(finding.get("confidence", 70))
    return finding


async def build_baseline_404(sess, target: str) -> set:
    """
    Probe several random paths to discover what status codes the server
    returns for non-existent resources (soft-404 detection).
    Returns a set of status codes that are the server's 404 equivalent.
    Also handles servers that always return 200 (true soft-404 servers).
    """
    import aiohttp
    nonce = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    probe_paths = [
        f"/this_path_definitely_does_not_exist_{nonce}",
        f"/xyzzy_nonexistent_page_{nonce}",
        f"/api/nonexistent_mirror_probe_{nonce}",
        f"/{nonce}/deep/nonexistent",
    ]
    statuses: list[int] = []
    bodies:   list[str] = []
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
                try:
                    bodies.append(await r.text(errors="ignore"))
                except Exception:
                    bodies.append("")
        except Exception:
            pass
        await asyncio.sleep(0.1)

    if not statuses:
        return {404}

    from collections import Counter
    common = Counter(statuses).most_common(1)[0][0]
    result = {404, common}

    # If the server returns 200 for everything (true soft-404),
    # record the body fingerprint so callers can compare body similarity.
    if common == 200 and bodies:
        avg_len = sum(len(b) for b in bodies) / len(bodies)
        # Store soft-404 body length hint as a sentinel value (negative)
        # Callers check: if status == 200 and abs(len(body) - avg_len) < threshold → skip
        result.add(-int(avg_len))  # negative sentinel for avg soft-404 body length

    return result
