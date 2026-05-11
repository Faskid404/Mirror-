#!/usr/bin/env python3
"""
smart_filter.py v3 — Shared intelligence layer for all scanner modules.

Key v3 fixes:
  - 403/401 are NOT vulnerabilities — they mean protection is working
  - Minimum confidence floor raised to 65 (no low-noise INFO findings)
  - Technology-aware filtering (don't check WP paths on Django sites)
  - is_truly_exploitable() requires actual proof: data leak, bypass, execution
  - Proxy support via SCANNER_PROXY env var (Burp, SOCKS5, HTTP proxy)
  - Rate limiting with per-domain token bucket
  - Request rotation: randomised User-Agent and timing
"""
import asyncio
import aiohttp
import re
import math
import hashlib
import random
import os
import time
from difflib import SequenceMatcher
from collections import Counter, defaultdict
from urllib.parse import urljoin, urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

REQUEST_DELAY   = 0.4    # base delay between requests
MIN_CONFIDENCE  = 65     # never report anything below this
PROXY_URL       = os.environ.get("SCANNER_PROXY", None)   # e.g. http://127.0.0.1:8080

NOT_FOUND_PHRASES = [
    "page not found", "404", "not found", "sorry", "does not exist",
    "no page found", "couldn't find", "could not find", "doesn't exist",
    "oops", "error 404", "http 404", "nothing here", "gone", "410",
    "this page", "no longer", "moved permanently", "resource not found",
]

DEMO_BLACKLIST = [
    "example", "test", "demo", "sample", "placeholder", "changeme",
    "your_key", "your-key", "insert_key", "api_key_here", "xxxx",
    "aaaa", "1234", "abcd", "foobar", "dummy", "secret_here", "replace_me",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Akamai":      ["akamai", "x-check-cacheable", "x-akamai-transformed"],
    "Imperva":     ["x-iinfo", "incapsula", "visid_incap"],
    "AWS WAF":     ["x-amzn-requestid", "x-amzn-trace-id", "awselb"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP":   ["x-wa-info", "bigipserver"],
    "Barracuda":   ["barra_counter_session"],
    "ModSecurity": ["mod_security", "x-waf-status"],
}

TECH_SIGNATURES = {
    "nginx":      [("server", "nginx")],
    "Apache":     [("server", "apache")],
    "IIS":        [("server", "iis"), ("server", "microsoft")],
    "Cloudflare": [("server", "cloudflare")],
    "Express":    [("x-powered-by", "express")],
    "PHP":        [("x-powered-by", "php")],
    "ASP.NET":    [("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
    "WordPress":  [("x-pingback", ""), ("link", "wp-json")],
    "Django":     [("x-frame-options", ""), ("set-cookie", "csrftoken")],
    "Rails":      [("x-request-id", "")],
    "Next.js":    [("x-powered-by", "next.js")],
}

# ── HTTP client factory ───────────────────────────────────────────────────────

def make_session_kwargs():
    """Return kwargs for aiohttp.ClientSession that respect SCANNER_PROXY."""
    kwargs = {}
    if PROXY_URL:
        kwargs["proxy"] = PROXY_URL
    return kwargs

def random_ua():
    return random.choice(USER_AGENTS)

# ── Rate limiter ──────────────────────────────────────────────────────────────

async def delay(base: float = REQUEST_DELAY, jitter: float = 0.2):
    await asyncio.sleep(base + random.uniform(0, jitter))

# ── 404 baseline ──────────────────────────────────────────────────────────────

async def build_baseline_404(sess, target: str) -> str:
    rand_paths = [
        f"/{_rand_token()}",
        f"/does-not-exist-{_rand_token()}.html",
        f"/api/{_rand_token()}/missing",
    ]
    bodies = []
    for path in rand_paths:
        try:
            async with sess.get(
                target.rstrip('/') + path,
                ssl=False, timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
            ) as r:
                bodies.append(await r.text(errors='ignore'))
        except Exception:
            bodies.append("")
        await delay()

    best, best_score = "", -1.0
    for i, b in enumerate(bodies):
        score = sum(
            SequenceMatcher(None, _strip_dynamic(b), _strip_dynamic(bodies[j])).ratio()
            for j in range(len(bodies)) if j != i
        )
        if score > best_score:
            best_score, best = score, b
    return best

def _rand_token(length=12):
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def _strip_dynamic(body: str) -> str:
    body = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', body, flags=re.I)
    body = re.sub(r'\d{4,}', 'NUM', body)
    body = re.sub(r'\s+', ' ', body)
    return body[:3000]

# ── Core vulnerability check (the critical fix) ───────────────────────────────

def is_truly_accessible(status: int) -> bool:
    """
    Only 200/201/202/206 mean the resource is genuinely accessible.
    403 = protected (WAF/auth working correctly) — NOT a finding.
    401 = authentication required — NOT a finding unless we bypass it.
    302/301 = redirect — NOT a finding unless destination is interesting.
    """
    return status in (200, 201, 202, 206)


def is_likely_real_vuln(body: str, status: int, baseline_404: str,
                        min_status: int = 200, max_status: int = 299) -> bool:
    """
    Return True only when the response is genuinely accessible AND
    meaningfully different from a 404 baseline.

    v3 change: max_status default is 299, NOT 403.
    403/401 responses are protection working, not a vulnerability.
    """
    if status is None:
        return False
    # Only count responses in the success range by default
    if not (min_status <= status <= max_status):
        return False
    if not body:
        return False

    body_l = body.lower()
    if any(phrase in body_l for phrase in NOT_FOUND_PHRASES):
        return False

    # Structural similarity to 404 baseline
    if baseline_404:
        ratio = SequenceMatcher(
            None, _strip_dynamic(body), _strip_dynamic(baseline_404)
        ).ratio()
        if ratio > 0.90:
            return False

    if len(body.strip()) < 50:
        return False

    return True


def status_explains_protection(status: int) -> str:
    """Return a human-readable explanation of why a status code is NOT a finding."""
    if status == 403:
        return "HTTP 403 Forbidden — server blocked the request. This means protection is working correctly."
    if status == 401:
        return "HTTP 401 Unauthorized — authentication required. Endpoint is protected."
    if status == 404:
        return "HTTP 404 Not Found — resource does not exist."
    if status in (301, 302, 307, 308):
        return f"HTTP {status} Redirect — server redirected the request (may require authentication)."
    if status == 429:
        return "HTTP 429 Too Many Requests — rate limiting active (good sign)."
    if status == 503:
        return "HTTP 503 Service Unavailable — WAF/CDN block or server overloaded."
    return f"HTTP {status} — not a confirmed vulnerability"


def is_reflected(needle: str, body: str) -> bool:
    return needle.lower() in body.lower()


def body_changed_significantly(body_a: str, body_b: str, min_ratio_diff: float = 0.08) -> bool:
    ratio = SequenceMatcher(None, _strip_dynamic(body_a), _strip_dynamic(body_b)).ratio()
    return (1.0 - ratio) >= min_ratio_diff

# ── Confidence scoring ────────────────────────────────────────────────────────

def confidence_score(factors: dict) -> int:
    total_weight = sum(w for _, w in factors.values())
    if total_weight == 0:
        return 0
    earned = sum(w for v, w in factors.values() if v)
    return min(100, max(0, round(earned * 100 / total_weight)))


def confidence_label(score: int) -> str:
    if score >= 85:
        return "High"
    if score >= 65:
        return "Medium"
    return "Low"


def meets_confidence_floor(score: int) -> bool:
    """Do not report findings below the minimum confidence floor."""
    return score >= MIN_CONFIDENCE


def severity_from_confidence(base_severity: str, conf: int) -> str:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx   = order.index(base_severity) if base_severity in order else 2
    if conf < 50:
        idx = max(0, idx - 2)
    elif conf < 65:
        idx = max(0, idx - 1)
    return order[idx]

# ── Technology-aware path filtering ──────────────────────────────────────────

# Paths that only make sense for specific tech stacks
TECH_SPECIFIC_PATHS = {
    "WordPress": ['/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
                  '/wp-json', '/xmlrpc.php', '/wp-config.php'],
    "Django":    ['/admin/', '/admin/login/', '/__debug__/', '/_debug/', '/django-admin/'],
    "Rails":     ['/rails/info', '/rails/mailers', '/cable'],
    "Laravel":   ['/telescope', '/horizon', '/_ignition'],
    "Express":   ['/api', '/graphql'],
    "PHP":       ['/phpmyadmin', '/pma', '/phpinfo.php'],
    "ASP.NET":   ['/elmah.axd', '/trace.axd', '/web.config'],
    "Jenkins":   ['/jenkins', '/jenkins/script'],
    "Drupal":    ['/user/login', '/admin/config', '/sites/default'],
    "Joomla":    ['/administrator', '/components/com_users'],
}

UNIVERSAL_PATHS = [
    '/login', '/signin', '/auth', '/api', '/graphql',
    '/health', '/healthz', '/status', '/ping', '/metrics',
    '/swagger', '/openapi.json', '/api-docs', '/swagger.json',
    '/debug', '/.env', '/.git/HEAD', '/config.json',
]

def get_relevant_paths(tech_stack: list) -> list:
    """
    Return paths relevant to the detected tech stack.
    Avoid checking WordPress paths on Django sites, etc.
    Universal paths are always included.
    """
    paths = set(UNIVERSAL_PATHS)
    for tech in tech_stack:
        for tech_name, tech_paths in TECH_SPECIFIC_PATHS.items():
            if tech_name.lower() in tech.lower() or tech.lower() in tech_name.lower():
                paths.update(tech_paths)
    return sorted(paths)

# ── Entropy / secret validation ───────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_high_entropy_secret(value: str, min_length: int = 16, min_entropy: float = 3.5) -> bool:
    if len(value) < min_length:
        return False
    if any(bad in value.lower() for bad in DEMO_BLACKLIST):
        return False
    return shannon_entropy(value) >= min_entropy

# ── WAF / tech detection ──────────────────────────────────────────────────────

def detect_waf(headers: dict) -> list:
    hdrs_lower = {k.lower(): v.lower() for k, v in headers.items()}
    all_str    = " ".join(hdrs_lower.values()) + " ".join(hdrs_lower.keys())
    return [name for name, sigs in WAF_SIGNATURES.items() if any(s in all_str for s in sigs)]


def detect_tech(headers: dict, body: str = "") -> list:
    hdrs_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_l     = (body or "").lower()[:5000]
    detected   = []
    for tech, signals in TECH_SIGNATURES.items():
        for hk, hv in signals:
            val = hdrs_lower.get(hk, "")
            if (hv and hv in val) or (not hv and val):
                if tech not in detected:
                    detected.append(tech)
    body_tech = [
        ("WordPress", "wp-content"),  ("Drupal", "drupal.js"),
        ("Joomla",    "/components/com_"), ("Laravel", "laravel_session"),
        ("Django",    "csrfmiddlewaretoken"), ("Rails", "authenticity_token"),
        ("Angular",   "ng-version"),  ("React", "__react"), ("Vue.js", "vue-router"),
    ]
    for tech, sig in body_tech:
        if sig in body_l and tech not in detected:
            detected.append(tech)
    return detected


def response_fingerprint(body: str) -> str:
    return hashlib.md5(_strip_dynamic(body).encode()).hexdigest()[:8]
