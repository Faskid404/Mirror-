#!/usr/bin/env python3
"""
Shared smart filtering utilities used by all scanner modules.
- Smart 404 detection via baseline comparison
- Confidence scoring (0-100)
- Request rate limiting
- Token entropy validation
- False-positive suppression
"""
import asyncio
import aiohttp
import re
import math
from collections import Counter
from urllib.parse import urljoin

NOT_FOUND_PHRASES = [
    "page not found", "404", "not found", "sorry", "does not exist",
    "no page found", "couldn't find", "could not find", "doesn't exist",
    "oops", "error 404", "http 404",
]

DEMO_BLACKLIST = [
    "example", "test", "demo", "sample", "placeholder", "changeme",
    "your_key", "your-key", "insert_key", "api_key_here", "xxxx",
    "aaaa", "1234", "abcd", "foobar", "dummy",
]

REQUEST_DELAY = 0.3


async def build_baseline_404(sess, target: str, n: int = 5) -> str:
    """
    Fetch several random non-existent URLs and concatenate their bodies
    to create a 404 baseline fingerprint.
    """
    import random, string
    combined = ""
    for _ in range(n):
        rand = ''.join(random.choices(string.ascii_lowercase, k=18))
        url = target.rstrip('/') + f"/{rand}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with sess.get(url, ssl=False, timeout=timeout, allow_redirects=True) as r:
                body = await r.text(errors='ignore')
                combined += body[:2000]
        except Exception:
            pass
        await asyncio.sleep(REQUEST_DELAY)
    return combined


def is_likely_real_vuln(response_text: str, status: int, baseline_404: str) -> bool:
    """
    Returns True only if the response looks genuinely different from a 404 page
    and has enough content to be meaningful.
    """
    if status != 200:
        return False
    if not response_text or len(response_text) < 300:
        return False

    resp_lower = response_text.lower()
    for phrase in NOT_FOUND_PHRASES:
        if phrase in resp_lower:
            return False

    if baseline_404:
        set_404 = set(baseline_404)
        set_resp = set(response_text)
        if len(set_resp) == 0:
            return False
        similarity = len(set_404 & set_resp) / len(set_resp)
        if similarity > 0.60:
            return False

    return True


def is_reflected(payload: str, response_text: str) -> bool:
    """Check if a payload was actually reflected in the response."""
    return bool(response_text) and payload in response_text


def confidence_score(factors: dict) -> int:
    """
    Compute 0-100 confidence from weighted boolean factors.
    factors: {factor_name: (bool, weight)}
    """
    total_weight = sum(w for _, w in factors.values())
    if total_weight == 0:
        return 0
    earned = sum(w for (v, w) in factors.values() if v)
    return min(100, int((earned / total_weight) * 100))


def confidence_label(score: int) -> str:
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    elif score >= 25:
        return "Low"
    return "Informational"


def severity_from_confidence(base_severity: str, conf: int) -> str:
    """Downgrade severity if confidence is low."""
    if conf >= 75:
        return base_severity
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    idx = order.index(base_severity) if base_severity in order else 4
    if conf >= 50:
        return order[min(idx + 1, 4)]
    return order[min(idx + 2, 4)]


def high_entropy(s: str, threshold: float = 3.8, min_length: int = 16) -> bool:
    """Return True if string has high entropy and meets min length."""
    if len(s) < min_length:
        return False
    c = Counter(s)
    n = len(s)
    ent = -sum((v / n) * math.log2(v / n) for v in c.values())
    return ent >= threshold


def is_demo_value(s: str) -> bool:
    """Return True if the value looks like a demo/placeholder."""
    sl = s.lower()
    for d in DEMO_BLACKLIST:
        if d in sl:
            return True
    if re.match(r'^(.)\1{7,}$', s):
        return True
    return False
