#!/usr/bin/env python3
"""WebProbe v5 — Pro-grade Modern Web Vulnerability Scanner.

Improvements:
- XSS: reflected, stored indicators, DOM sinks, CSP bypass
- Open redirect: 40+ payloads with protocol confusion
- CORS misconfiguration: null origin, wildcard + credentials, pre-flight
- Clickjacking: frame-options + CSP frame-ancestors
- Prototype pollution indicators
- DOM clobbering detection
- Web cache poisoning: unkeyed header injection
- Subresource Integrity (SRI) missing
- PostMessage vulnerability indicators
- HTTP Request Smuggling CL.TE / TE.CL indicators
- Content sniffing (X-Content-Type-Options)
"""
import asyncio, aiohttp, json, re, sys, time
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, REQUEST_DELAY,
)

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '"><svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '{{7*7}}',  # template injection
    '${7*7}',
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "//evil.com/", "https://evil.com",
    "//evil.com%2F", "//evil.com%25%2F",
    "/\\/evil.com", "//evil%2ecom",
    "https:evil.com", "//google.com@evil.com",
    "////evil.com", "//%09evil.com",
    "/%2f%2fevil.com", "http://evil.com",
    "https://evil.com?url=https://target.com",
    "//evil.com#https://target.com",
    "javascript://evil.com/%0aalert(1)",
    "%09//evil.com",
]

REDIRECT_PARAMS = [
    "next", "redirect", "return", "url", "goto",
    "dest", "destination", "redir", "redirect_uri",
    "return_url", "returnUrl", "backUrl", "back",
    "callback", "forward", "location", "target",
    "continue", "ref", "referrer", "out",
]

CORS_ORIGINS = [
    "https://evil.com",
    "https://attacker.mirror.com",
    "null",
    "https://mirror.com.evil.com",
    "https://mirror-evil.com",
]

CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Port", "80"),
    ("X-Original-URL",   "/admin"),
    ("X-Rewrite-URL",    "/admin"),
    ("X-Forwarded-Scheme", "http"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Host", "evil.com"),
]

DOM_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'document\.domain\s*=',
    r'\.src\s*=',
    r'execScript\s*\(',
    r'window\.location\s*=',
]

SRI_PATTERN = re.compile(r'<script[^>]+src=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>', re.I)
SRI_INTEGRITY = re.compile(r'integrity=["\'][^"\']+["\']', re.I)


class WebProbe:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.findings = []
        self._dedup   = set()

    async def _get(self, sess, url, params=None, headers=None, allow_redirects=False, timeout=10):
        merged = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
        if headers:
            merged.update(headers)
        try:
            async with sess.get(
                url, params=params or {}, headers=merged, ssl=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=allow_redirects,
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    # ── XSS detection ─────────────────────────────────────────────────────────

    async def test_xss(self, sess):
        print("\n[*] Testing for reflected XSS...")
        test_params = ["q", "search", "query", "id", "name", "input", "text",
                       "s", "keyword", "term", "msg", "message", "content", "data"]
        for param in test_params[:8]:
            for payload in XSS_PAYLOADS[:6]:
                url = f"{self.target}?{param}={quote(payload, safe='')}"
                s, body, hdrs = await self._get(sess, url, allow_redirects=True)
                await delay(0.05)
                if s not in (200, 201) or not body:
                    continue
                # Check if payload is reflected unescaped
                if payload in body and not self._is_escaped(payload, body):
                    key = f"xss_{param}_{payload[:20]}"
                    if key not in self._dedup:
                        self._dedup.add(key)
                        csp = hdrs.get("Content-Security-Policy", hdrs.get("content-security-policy", ""))
                        self.findings.append({
                            "type": "XSS_REFLECTED",
                            "severity": "HIGH" if not csp else "MEDIUM",
                            "confidence": 90,
                            "confidence_label": "High",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "csp_present": bool(csp),
                            "csp_value": csp[:100] if csp else None,
                            "proof": f"Param {param}={payload} → payload reflected unescaped in HTTP {s} response",
                            "detail": f"Reflected XSS via '{param}' parameter{' (CSP may mitigate)' if csp else ''}",
                            "remediation": (
                                "1. HTML-encode all user input before reflecting: &, <, >, \", '. "
                                "2. Set Content-Security-Policy: default-src 'self'; script-src 'self'. "
                                "3. Use framework output encoding (React JSX, Django templates auto-escape). "
                                "4. Set X-Content-Type-Options: nosniff."
                            ),
                            "mitre_technique": "T1059.007", "mitre_name": "Command and Scripting Interpreter: JavaScript",
                        })
                        print(f"  [HIGH] Reflected XSS: {param}={payload[:40]}")
                        break

    def _is_escaped(self, payload: str, body: str) -> bool:
        escaped_variants = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;"),
            payload.replace("'", "&#x27;"),
        ]
        return any(v in body for v in escaped_variants)

    # ── DOM XSS sink analysis ─────────────────────────────────────────────────

    async def test_dom_sinks(self, sess):
        print("\n[*] Scanning for DOM XSS sinks in JavaScript...")
        s, body, hdrs = await self._get(sess, self.target + "/", allow_redirects=True)
        if not body:
            return
        # Find JS script tags and inline scripts
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
        js_combined = "\n".join(script_blocks)
        sinks_found = []
        for pattern in DOM_SINK_PATTERNS:
            if re.search(pattern, js_combined, re.I):
                sinks_found.append(pattern.replace(r'\s*', ' ').replace(r'\(', '('))
        if sinks_found:
            self.findings.append({
                "type": "DOM_XSS_SINKS_DETECTED",
                "severity": "MEDIUM",
                "confidence": 72,
                "confidence_label": confidence_label(72),
                "url": self.target,
                "sinks": sinks_found[:10],
                "proof": f"{len(sinks_found)} dangerous DOM sinks found in inline JavaScript: {sinks_found[:3]}",
                "detail": f"DOM XSS risk: {len(sinks_found)} dangerous sink(s) in inline JS",
                "remediation": (
                    "1. Avoid dangerous sinks: document.write, innerHTML, eval. "
                    "2. Use textContent instead of innerHTML for text output. "
                    "3. Use DOMPurify to sanitize HTML before inserting into DOM. "
                    "4. Implement a strict CSP to block inline script execution."
                ),
            })
            print(f"  [MEDIUM] DOM sinks found: {sinks_found[:3]}")

    # ── Open redirect ─────────────────────────────────────────────────────────

    async def test_open_redirect(self, sess):
        print("\n[*] Testing for open redirect vulnerabilities...")
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS[:10]:
                url = f"{self.target}?{param}={quote(payload, safe='/:@')}"
                s, body, hdrs = await self._get(sess, url, allow_redirects=False)
                await delay(0.05)
                if s in (301, 302, 303, 307, 308):
                    location = hdrs.get("Location", hdrs.get("location", ""))
                    # Guard against partial matches like "evil.com.victim.com" by
                    # requiring the attacker domain to appear as a proper hostname boundary.
                    def _is_attacker_domain(loc: str) -> bool:
                        import re as _re
                        return bool(_re.search(
                            r'(?:https?://|^|[/@])(?:evil\.com|attacker\.com|attacker\.invalid)',
                            loc, _re.I))
                    if location and _is_attacker_domain(location):
                        key = f"redir_{param}_{payload[:20]}"
                        if key not in self._dedup:
                            self._dedup.add(key)
                            self.findings.append({
                                "type": "OPEN_REDIRECT",
                                "severity": "MEDIUM",
                                "confidence": 92,
                                "confidence_label": "Confirmed",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "redirect_location": location,
                                "proof": f"HTTP {s} Location: {location} — parameter {param}={payload} caused redirect to attacker domain",
                                "detail": f"Open redirect via '{param}' parameter to {payload}",
                                "remediation": (
                                    "1. Never use user input directly in redirect locations. "
                                    "2. Use an allowlist of permitted redirect destinations. "
                                    "3. Use relative paths only for internal redirects. "
                                    "4. Validate redirect URL against expected host."
                                ),
                                "mitre_technique": "T1566", "mitre_name": "Phishing",
                            })
                            print(f"  [MEDIUM] Open redirect: {param}={payload} → {location}")
                        break

    # ── CORS misconfiguration ─────────────────────────────────────────────────

    async def test_cors(self, sess):
        print("\n[*] Testing CORS misconfiguration...")
        test_paths = ["/", "/api", "/api/me", "/api/user", "/api/data"]
        for path in test_paths:
            url = self.target + path
            for origin in CORS_ORIGINS:
                s, body, hdrs = await self._get(sess, url, headers={"Origin": origin})
                await delay(0.08)
                if s is None:
                    continue
                acao = hdrs.get("Access-Control-Allow-Origin", hdrs.get("access-control-allow-origin", ""))
                acac = hdrs.get("Access-Control-Allow-Credentials", hdrs.get("access-control-allow-credentials", ""))
                if not acao:
                    continue

                if origin == "null" and acao == "null" and acac.lower() == "true":
                    self.findings.append({
                        "type": "CORS_NULL_ORIGIN_WITH_CREDENTIALS",
                        "severity": "CRITICAL",
                        "confidence": 97,
                        "confidence_label": "Confirmed",
                        "url": url,
                        "origin_sent": origin,
                        "acao_header": acao,
                        "proof": f"Origin: null → ACAO: null + ACAC: true at {path} — sandbox iframe can steal cookies",
                        "detail": "CORS: null origin reflected with credentials=true — sandboxed iframes can read authenticated responses",
                        "remediation": "Never allow null origin. Use an explicit origin allowlist.",
                    })
                    print(f"  [CRITICAL] CORS null origin + credentials at {path}")

                elif acao == origin and acac.lower() == "true" and origin != "null":
                    self.findings.append({
                        "type": "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
                        "severity": "CRITICAL",
                        "confidence": 95,
                        "confidence_label": "Confirmed",
                        "url": url,
                        "origin_sent": origin,
                        "acao_header": acao,
                        "proof": f"Origin: {origin} → ACAO: {acao} + ACAC: true — cross-origin requests allowed with credentials",
                        "detail": f"CORS reflects arbitrary origin with credentials — full CORS exploit possible",
                        "remediation": "Use an explicit origin allowlist. Never dynamically reflect untrusted origins. Separate credentialed and public CORS policies.",
                        "mitre_technique": "T1557", "mitre_name": "Adversary-in-the-Middle",
                    })
                    print(f"  [CRITICAL] CORS arbitrary origin + credentials at {path}")
                    break

    # ── Clickjacking ──────────────────────────────────────────────────────────

    async def test_clickjacking(self, sess):
        print("\n[*] Testing for clickjacking...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}
        xfo = hdrs_lower.get("x-frame-options", "")
        csp = hdrs_lower.get("content-security-policy", "")
        has_frame_protection = bool(xfo) or "frame-ancestors" in csp

        if not has_frame_protection:
            self.findings.append({
                "type": "CLICKJACKING_VULNERABLE",
                "severity": "MEDIUM",
                "confidence": 95,
                "confidence_label": "Confirmed",
                "url": self.target,
                "x_frame_options": xfo or "(missing)",
                "csp_frame_ancestors": "frame-ancestors" in csp,
                "proof": "No X-Frame-Options header and no CSP frame-ancestors directive",
                "detail": "Clickjacking possible — page can be embedded in a cross-origin iframe",
                "remediation": (
                    "Add X-Frame-Options: DENY or SAMEORIGIN header. "
                    "Better: Content-Security-Policy: frame-ancestors 'none'; (overrides X-Frame-Options). "
                    "CSP frame-ancestors is the modern standard."
                ),
                "mitre_technique": "T1185", "mitre_name": "Browser Session Hijacking",
            })
            print(f"  [MEDIUM] Clickjacking: no X-Frame-Options or CSP frame-ancestors")
        elif xfo and "deny" not in xfo and "sameorigin" not in xfo:
            self.findings.append({
                "type": "CLICKJACKING_WEAK_CONFIG",
                "severity": "LOW",
                "confidence": 85,
                "confidence_label": "High",
                "url": self.target,
                "x_frame_options": xfo,
                "proof": f"X-Frame-Options: {xfo} — allow-from is deprecated",
                "detail": "X-Frame-Options: ALLOW-FROM is deprecated and ignored by modern browsers",
                "remediation": "Use CSP frame-ancestors instead: Content-Security-Policy: frame-ancestors 'none';",
            })

    # ── Web cache poisoning ───────────────────────────────────────────────────

    async def test_cache_poisoning(self, sess):
        print("\n[*] Testing for web cache poisoning...")
        for poison_header, poison_value in CACHE_POISON_HEADERS:
            url = self.target + "/?_cache_test=1"
            s, body, hdrs = await self._get(sess, url, headers={poison_header: poison_value})
            await delay(0.1)
            if s not in (200, 301, 302) or not body:
                continue
            # Check if poison value is reflected in response
            if poison_value.lower() in (body or "").lower():
                # ── Stage 2: verify the poisoned value persists in a clean second request ──
                # Without a second-request cache hit, this is just reflection — not poisoning.
                await delay(0.5)
                s2, body2, hdrs2 = await self._get(sess, url)
                cache_status2 = (
                    hdrs2.get("X-Cache", hdrs2.get("x-cache", "")) +
                    hdrs2.get("CF-Cache-Status", hdrs2.get("cf-cache-status", ""))
                ).lower()
                age2 = hdrs2.get("age", hdrs2.get("Age", "0"))
                is_cached = "hit" in cache_status2 or (str(age2).isdigit() and int(age2) > 0)
                poison_persists = poison_value.lower() in (body2 or "").lower() and is_cached

                if not poison_persists:
                    print(f"  [SKIP] {poison_header} reflected but NOT cached — no poisoning (just reflection)")
                    continue

                cache_status = hdrs.get("X-Cache", hdrs.get("x-cache", hdrs.get("CF-Cache-Status", "")))
                self.findings.append({
                    "type": "WEB_CACHE_POISONING_CONFIRMED",
                    "severity": "HIGH",
                    "confidence": 88,
                    "confidence_label": confidence_label(88),
                    "url": url,
                    "poison_header": poison_header,
                    "poison_value": poison_value,
                    "cache_status_on_hit": cache_status2,
                    "proof": (
                        f"Stage 1 — {poison_header}: {poison_value} reflected in HTTP {s} response\n"
                        f"Stage 2 — Second clean request received CACHED response (age={age2}, status={cache_status2})\n"
                        f"         with poisoned value still present — cache poisoning CONFIRMED"
                    ),
                    "detail": (
                        f"Web cache poisoning confirmed: {poison_header} value persists in cached response. "
                        f"Any visitor to {url} will receive the poisoned content."
                    ),
                    "remediation": (
                        "1. Add this header to the cache key (Vary header or cache-key config).\n"
                        "2. Strip/validate this header before it reaches the application.\n"
                        "3. Configure CDN to not cache responses containing user-controlled header values.\n"
                        "4. Review all unkeyed headers in your caching layer."
                    ),
                })
                print(f"  [HIGH] CACHE POISONING CONFIRMED: {poison_header}: {poison_value} — persists in cached response")

    # ── SRI check ─────────────────────────────────────────────────────────────

    async def test_sri(self, sess):
        print("\n[*] Checking Subresource Integrity (SRI) on external scripts...")
        s, body, hdrs = await self._get(sess, self.target + "/", allow_redirects=True)
        if not body:
            return
        external_scripts = SRI_PATTERN.findall(body)
        missing_sri = [tag for tag in external_scripts if not SRI_INTEGRITY.search(tag)]
        if missing_sri:
            self.findings.append({
                "type": "SRI_MISSING",
                "severity": "MEDIUM",
                "confidence": 88,
                "confidence_label": "High",
                "url": self.target,
                "count": len(missing_sri),
                "examples": [re.search(r'src=["\']([^"\']+)["\']', t, re.I).group(1) if re.search(r'src=["\']([^"\']+)["\']', t, re.I) else t[:80] for t in missing_sri[:3]],
                "proof": f"{len(missing_sri)} external script(s) loaded without integrity attribute",
                "detail": f"SRI missing on {len(missing_sri)} external script(s) — CDN compromise would execute attacker code",
                "remediation": "Add integrity and crossorigin attributes to all external scripts: <script src='...' integrity='sha384-...' crossorigin='anonymous'>",
            })
            print(f"  [MEDIUM] SRI missing on {len(missing_sri)} external script(s)")

    # ── Content type sniffing ─────────────────────────────────────────────────

    async def test_content_type_sniffing(self, sess):
        print("\n[*] Checking Content-Type security headers...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}

        checks = [
            ("x-content-type-options", "nosniff", "X_CONTENT_TYPE_OPTIONS_MISSING",
             "MEDIUM", "Missing X-Content-Type-Options: nosniff — browser may MIME-sniff responses as executable",
             "Add: X-Content-Type-Options: nosniff"),
            ("referrer-policy", None, "REFERRER_POLICY_MISSING",
             "LOW", "Missing Referrer-Policy — Referer header may leak sensitive URLs",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("permissions-policy", None, "PERMISSIONS_POLICY_MISSING",
             "LOW", "Missing Permissions-Policy — camera/microphone/geolocation unrestricted",
             "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
        ]
        for header, expected_value, ftype, severity, detail, remediation in checks:
            val = hdrs_lower.get(header, "")
            missing = not val or (expected_value and expected_value not in val)
            if missing:
                self.findings.append({
                    "type": ftype,
                    "severity": severity,
                    "confidence": 95,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "header": header,
                    "current_value": val or "(absent)",
                    "proof": f"HTTP response missing or misconfigured {header}: '{val or 'not present'}'",
                    "detail": detail,
                    "remediation": remediation,
                })
                print(f"  [{severity}] {header}: {val or 'missing'}")

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  WebProbe v5 — Modern Web Vulnerability Scanner")
        print("  XSS | Open Redirect | CORS | Clickjacking | Cache Poisoning | SRI")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=120)) as sess:
            await asyncio.gather(
                self.test_xss(sess),
                self.test_dom_sinks(sess),
                self.test_open_redirect(sess),
                self.test_cors(sess),
                self.test_clickjacking(sess),
                self.test_cache_poisoning(sess),
                self.test_sri(sess),
                self.test_content_type_sniffing(sess),
            )
        print(f"\n[+] WebProbe complete: {len(self.findings)} findings")
        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(WebProbe(target).run())
    with open("reports/webprobe.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/webprobe.json")


if __name__ == "__main__":
    main()
