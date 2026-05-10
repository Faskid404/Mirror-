#!/usr/bin/env python3
"""
smart_filter.py v2 — Shared intelligence layer for all scanner modules.

Improvements:
  - WAF/CDN fingerprinting (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri)
  - Enhanced 404 baseline with 3-probe averaging
  - Structural similarity scoring (avoids false positives from dynamic content)
  - Shannon entropy for secret/token validation
  - Response diffing (detect meaningful changes vs noise)
  - Rate limiter with jitter (avoids triggering rate-limit WAF rules)
  - Technology fingerprint from headers + body
  - Common false-positive suppressor for known benign patterns
"""
import asyncio
import aiohttp
import re
import math
import hashlib
import random
import time
from difflib import SequenceMatcher
from collections import Counter
from urllib.parse import urljoin, urlparse

# ── Constants ─────────────────────────────────────────────────────────────────

REQUEST_DELAY = 0.35   # seconds between requests (add jitter below)

NOT_FOUND_PHRASES = [
    "page not found", "404", "not found", "sorry", "does not exist",
    "no page found", "couldn't find", "could not find", "doesn't exist",
    "oops", "error 404", "http 404", "nothing here", "gone", "410",
    "this page", "no longer", "moved permanently",
]

DEMO_BLACKLIST = [
    "example", "test", "demo", "sample", "placeholder", "changeme",
    "your_key", "your-key", "insert_key", "api_key_here", "xxxx",
    "aaaa", "1234", "abcd", "foobar", "dummy", "secret_here", "replace_me",
]

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Akamai":      ["akamai", "x-check-cacheable", "x-akamai-transformed"],
    "Imperva":     ["x-iinfo", "incapsula", "visid_incap"],
    "AWS WAF":     ["x-amzn-requestid", "x-amzn-trace-id", "awselb"],
    "Sucuri":      ["x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP":   ["x-wa-info", "bigipserver", "f5-"],
    "Barracuda":   ["barra_counter_session", "barracudabypass"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

TECH_SIGNATURES = {
    "nginx":        [("server", "nginx")],
    "Apache":       [("server", "apache")],
    "IIS":          [("server", "iis"), ("server", "microsoft")],
    "Cloudflare":   [("server", "cloudflare")],
    "Express":      [("x-powered-by", "express")],
    "PHP":          [("x-powered-by", "php")],
    "ASP.NET":      [("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
    "WordPress":    [("x-pingback", ""), ("link", "wp-json")],
    "Django":       [("x-frame-options", ""), ("csrftoken", "")],
    "Rails":        [("x-powered-by", "phusion passenger"), ("x-request-id", "")],
    "Next.js":      [("x-powered-by", "next.js")],
    "Fastly":       [("x-served-by", "cache"), ("x-cache", "")],
    "Varnish":      [("x-varnish", ""), ("via", "varnish")],
}


# ── Rate limiter ──────────────────────────────────────────────────────────────

async def delay(base: float = REQUEST_DELAY, jitter: float = 0.15):
    """Sleep for base + random jitter to avoid fingerprinting."""
    await asyncio.sleep(base + random.uniform(0, jitter))


# ── 404 baseline ──────────────────────────────────────────────────────────────

async def build_baseline_404(sess, target: str) -> str:
    """
    Fetch three random paths and return the body with the highest average
    structural similarity to the others (most representative 'not found' page).
    Returns empty string if none of the requests succeed.
    """
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
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
            ) as r:
                bodies.append(await r.text(errors='ignore'))
        except Exception:
            bodies.append("")
        await delay()

    # Pick the body with the highest total similarity to the other two
    best, best_score = "", -1.0
    for i, b in enumerate(bodies):
        score = sum(
            SequenceMatcher(None, _strip_dynamic(b), _strip_dynamic(bodies[j])).ratio()
            for j in range(len(bodies)) if j != i
        )
        if score > best_score:
            best_score, best = score, b
    return best


def _rand_token(length: int = 12) -> str:
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _strip_dynamic(body: str) -> str:
    """Remove numbers, UUIDs, timestamps so similarity ignores dynamic tokens."""
    body = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', body, flags=re.I)
    body = re.sub(r'\d{4,}', 'NUM', body)
    body = re.sub(r'\s+', ' ', body)
    return body[:3000]


# ── False-positive detection ──────────────────────────────────────────────────

def is_likely_real_vuln(body: str, status: int, baseline_404: str,
                        min_status: int = 200, max_status: int = 403) -> bool:
    """Return True only if the response looks meaningfully different from a 404."""
    if status is None:
        return False
    if not (min_status <= status <= max_status):
        return False
    if not body:
        return False

    body_l = body.lower()
    if any(phrase in body_l for phrase in NOT_FOUND_PHRASES):
        return False

    # Structural similarity to baseline
    if baseline_404:
        ratio = SequenceMatcher(
            None, _strip_dynamic(body), _strip_dynamic(baseline_404)
        ).ratio()
        if ratio > 0.92:
            return False  # too similar to 404

    # Suspiciously tiny body
    if len(body.strip()) < 30:
        return False

    return True


def is_reflected(needle: str, body: str) -> bool:
    """Case-insensitive check that needle appears verbatim in body."""
    return needle.lower() in body.lower()


def body_changed_significantly(body_a: str, body_b: str,
                               min_ratio_diff: float = 0.08) -> bool:
    """Return True when two responses differ enough to suggest meaningful behaviour change."""
    ratio = SequenceMatcher(None, _strip_dynamic(body_a), _strip_dynamic(body_b)).ratio()
    return (1.0 - ratio) >= min_ratio_diff


# ── Confidence scoring ────────────────────────────────────────────────────────

def confidence_score(factors: dict) -> int:
    """
    Compute weighted confidence 0-100.

    factors = {
        'label': (bool_condition, weight),
        ...
    }
    Total weight should normally equal 100. Score is clipped to [0, 100].
    """
    total_weight = sum(w for _, w in factors.values())
    if total_weight == 0:
        return 0
    earned = sum(w for v, w in factors.values() if v)
    return min(100, max(0, round(earned * 100 / total_weight)))


def confidence_label(score: int) -> str:
    if score >= 85:
        return "High"
    if score >= 60:
        return "Medium"
    return "Low"


def severity_from_confidence(base_severity: str, conf: int) -> str:
    """Down-grade severity when confidence is low."""
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx   = order.index(base_severity) if base_severity in order else 2
    if conf < 50:
        idx = max(0, idx - 2)
    elif conf < 70:
        idx = max(0, idx - 1)
    return order[idx]


# ── Entropy / secret validation ───────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Return Shannon entropy of string s (bits per character)."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_high_entropy_secret(value: str, min_length: int = 16,
                            min_entropy: float = 3.5) -> bool:
    """True if value looks like a real secret (long + high entropy)."""
    if len(value) < min_length:
        return False
    if any(bad in value.lower() for bad in DEMO_BLACKLIST):
        return False
    return shannon_entropy(value) >= min_entropy


# ── WAF detection ─────────────────────────────────────────────────────────────

def detect_waf(headers: dict) -> list:
    """Return list of WAF names detected from response headers."""
    hdrs_lower = {k.lower(): v.lower() for k, v in headers.items()}
    all_header_vals = " ".join(hdrs_lower.values()) + " ".join(hdrs_lower.keys())
    detected = []
    for waf_name, signals in WAF_SIGNATURES.items():
        if any(s in all_header_vals for s in signals):
            detected.append(waf_name)
    return detected


# ── Technology fingerprinting ─────────────────────────────────────────────────

def detect_tech(headers: dict, body: str = "") -> list:
    """Return list of technology names detected from headers and body."""
    hdrs_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_l = (body or "").lower()[:5000]
    detected = []
    for tech, signals in TECH_SIGNATURES.items():
        for header_key, header_val in signals:
            hv = hdrs_lower.get(header_key, "")
            if (header_val and header_val in hv) or (not header_val and hv):
                if tech not in detected:
                    detected.append(tech)
    # Body-based tech detection
    body_tech = [
        ("WordPress",    "wp-content"),
        ("Drupal",       "drupal.js"),
        ("Joomla",       "/components/com_"),
        ("Laravel",      "laravel_session"),
        ("Django",       "csrfmiddlewaretoken"),
        ("Rails",        "authenticity_token"),
        ("Angular",      "ng-version"),
        ("React",        "__react"),
        ("Vue.js",       "vue-router"),
    ]
    for tech, sig in body_tech:
        if sig in body_l and tech not in detected:
            detected.append(tech)
    return detected


# ── Response fingerprinting ───────────────────────────────────────────────────

def response_fingerprint(body: str) -> str:
    """Return a short stable hash of the structural content (dynamic parts removed)."""
    return hashlib.md5(_strip_dynamic(body).encode()).hexdigest()[:8]
