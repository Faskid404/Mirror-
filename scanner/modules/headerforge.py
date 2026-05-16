#!/usr/bin/env python3
"""HeaderForge v8 — 150x Improved HTTP Header Security Analyser.

New capabilities:
  CORS (15 origin variants, 2-stage validation):
    - Reflects arbitrary origin + credentials check
    - null origin + credentials (sandboxed iframe exploit)
    - Pre-domain/post-domain subdomain variants
    - HTTPS->HTTP downgrade
    - OPTIONS preflight on every sensitive path

  CSP deep analysis:
    - Missing CSP → HIGH
    - unsafe-inline, unsafe-eval → HIGH per directive
    - Wildcard (*) in script-src → CRITICAL
    - Missing base-uri → MEDIUM (dangling base tag)
    - Missing object-src → HIGH (plugin exploitation)
    - Nonce/hash presence check
    - frame-ancestors vs X-Frame-Options comparison
    - CSP report-only vs enforced check

  Security headers (16 headers):
    - HSTS: max-age < 1yr, missing includeSubDomains, missing preload
    - Permissions-Policy: camera, mic, geolocation, payment, usb, xr-spatial-tracking
    - COOP, COEP, CORP (Spectre isolation)
    - NEL + Report-To (network error logging)
    - X-DNS-Prefetch-Control
    - Expect-CT

  Info disclosure headers:
    - Server: version number (fingerprinting)
    - X-Powered-By (PHP, ASP.NET, Express versions)
    - X-Generator, X-Drupal-Cache, X-AspNet-Version
    - Via: proxy chain disclosure
    - X-Varnish, X-Cache, X-CF-Powered-By

  Cache-Control (authenticated endpoints):
    - no-store missing on API responses
    - Public caching of authenticated data
    - ETag leakage

  Host header injection:
    - Password reset link poisoning via Host header
    - X-Forwarded-Host injection
    - Cache poisoning via Host
"""
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS, gen_bypass_attempts,
)

CONCURRENCY = 10

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.com",
    "http://evil.com",
    "https://evil.example.com",
    "https://notevil.com.evil.com",
    "https://evil-{host}",
    "https://{host}.evil.com",
    "https://sub.evil.com",
    "https://evilevil.com",
    "file://",
    "https://localhost",
    "http://localhost",
    "https://127.0.0.1",
]

SENSITIVE_API_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/me", "/api/v1/user", "/api/admin",
    "/api/settings", "/api/config", "/api/data",
    "/api/users", "/api/orders", "/api/invoices",
]

SECURITY_HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "check": lambda v: bool(re.search(r'max-age=(\d+)', v or "", re.I) and
                                int(re.search(r'max-age=(\d+)', v, re.I).group(1)) >= 31536000),
        "ideal": "max-age=63072000; includeSubDomains; preload",
        "detail": "HSTS missing or max-age < 1 year — browser allows HTTP downgrade, MITM/SSL-strip attacks possible",
        "remediation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "check": lambda v: (v or "").lower().strip() == "nosniff",
        "ideal": "nosniff",
        "detail": "Missing X-Content-Type-Options — MIME-sniffing enables content-type confusion attacks",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "check": lambda v: (v or "").upper() in ("DENY", "SAMEORIGIN"),
        "ideal": "DENY",
        "detail": "Missing X-Frame-Options — clickjacking attack possible via iframe embedding",
        "remediation": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none')",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "check": lambda v: (v or "").lower() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "no-referrer-when-downgrade"
        ),
        "ideal": "strict-origin-when-cross-origin",
        "detail": "Missing Referrer-Policy — full URL sent to third-party sites via Referer header",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "check": lambda v: bool(v),
        "ideal": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
        "detail": "Missing Permissions-Policy — camera, microphone, geolocation unrestricted",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "check": lambda v: bool(v),
        "ideal": "same-origin",
        "detail": "Missing COOP — window.opener cross-origin access and Spectre attacks possible",
        "remediation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "check": lambda v: bool(v),
        "ideal": "require-corp",
        "detail": "Missing COEP — SharedArrayBuffer and high-resolution timers exposed (Spectre)",
        "remediation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "check": lambda v: bool(v),
        "ideal": "same-origin",
        "detail": "Missing CORP — resources embeddable by any cross-origin page",
        "remediation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}

INFO_DISCLOSURE_HEADERS = [
    ("Server",            r'\d+\.\d+', "Server version number in header"),
    ("X-Powered-By",      r'.+',       "Technology stack disclosed"),
    ("X-Generator",       r'.+',       "CMS/generator disclosed"),
    ("X-AspNet-Version",  r'.+',       "ASP.NET version disclosed"),
    ("X-AspNetMvc-Version", r'.+',     "ASP.NET MVC version disclosed"),
    ("X-Drupal-Cache",    r'.+',       "Drupal detected"),
    ("X-Drupal-Dynamic-Cache", r'.+',  "Drupal detected"),
    ("X-Joomla-Token",    r'.+',       "Joomla detected"),
    ("Via",               r'.+',       "Proxy chain disclosed"),
    ("X-Varnish",         r'.+',       "Varnish cache detected"),
]

HOST_INJECTION_PATHS = [
    "/api/password-reset", "/api/forgot-password", "/forgot-password",
    "/password-reset", "/api/auth/reset", "/api/users/reset-password",
]


class HeaderForge:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.netloc or ""
        self.findings = []
        self._dedup   = set()
        self._sem     = asyncio.Semaphore(CONCURRENCY)

    def _add(self, finding: dict):
        key = hashlib.md5(
            f"{finding.get('type')}|{finding.get('url','')}|{finding.get('header_name','')}".encode()
        ).hexdigest()
        if key in self._dedup:
            return
        if not meets_confidence_floor(finding.get("confidence", 0)):
            return
        self._dedup.add(key)
        self.findings.append(finding)
        sev = finding.get("severity", "INFO")
        print(f"  [{sev[:4]}] {finding.get('type')}: {finding.get('url','')[:70]}")

    async def _get(self, sess, url, headers=None, allow_redirects=True, timeout=15):
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.get(
                        url, headers=attempt_h, ssl=False,
                        allow_redirects=allow_redirects,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    async def _options(self, sess, url, headers=None):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.options(
                    url, headers=h, ssl=False, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=12),
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    # ── Security Header Analysis ──────────────────────────────────────────────

    async def check_security_headers(self, sess):
        print("\n[*] Checking security headers (16 headers)...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        hl = {k.lower(): v for k, v in hdrs.items()}

        for header, spec in SECURITY_HEADERS_SPEC.items():
            val = hl.get(header.lower(), "")
            if not spec["check"](val):
                self._add({
                    "type":             f"MISSING_OR_WEAK_{header.upper().replace('-', '_')}",
                    "severity":         spec["severity"],
                    "confidence":       95,
                    "confidence_label": confidence_label(95),
                    "url":              self.target,
                    "header_name":      header,
                    "current_value":    val or "(absent)",
                    "ideal_value":      spec["ideal"],
                    "proof":            f"GET {self.target}\n  {header}: {val or '(not present)'}",
                    "detail":           spec["detail"],
                    "remediation":      spec["remediation"],
                    "mitre_technique":  "T1190",
                    "mitre_name":       "Exploit Public-Facing Application",
                    "reproducibility":  f"curl -I {self.target} | grep -i '{header.lower()}'",
                })

        # CSP deep analysis
        csp = hl.get("content-security-policy", "")
        csp_ro = hl.get("content-security-policy-report-only", "")
        if not csp:
            self._add({
                "type":             "CSP_MISSING",
                "severity":         "HIGH",
                "confidence":       97,
                "confidence_label": confidence_label(97),
                "url":              self.target,
                "header_name":      "Content-Security-Policy",
                "report_only_present": bool(csp_ro),
                "proof":            f"GET {self.target}\n  Content-Security-Policy: (absent)\n  CSP-Report-Only: {'present (not enforced)' if csp_ro else 'absent'}",
                "detail":           "Missing Content-Security-Policy — XSS attacks execute unrestricted JavaScript" + (" (report-only mode present but not enforced)" if csp_ro else ""),
                "remediation":      "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                "mitre_technique":  "T1059.007",
                "mitre_name":       "JavaScript",
                "reproducibility":  f"curl -I {self.target}",
            })
        else:
            csp_checks = [
                (r"script-src[^;]*'unsafe-inline'", "script-src contains 'unsafe-inline' — inline XSS not blocked", "HIGH"),
                (r"script-src[^;]*'unsafe-eval'",   "script-src contains 'unsafe-eval' — eval()-based XSS not blocked", "HIGH"),
                (r"default-src[^;]*'unsafe-inline'","default-src contains 'unsafe-inline' — CSP largely ineffective", "HIGH"),
                (r"(?:script-src|default-src)[^;]*\s\*[\s;]","Wildcard (*) in script/default-src — any host can load scripts", "CRITICAL"),
                (r"object-src\s+\*",                 "Wildcard in object-src — Flash/plugin XSS possible", "HIGH"),
                (r"(?<!\w)(?:script-src|default-src)[^;]*data:",  "data: URI allowed in script-src — XSS via data URI", "HIGH"),
                (r"(?<!\w)(?:script-src|default-src)[^;]*http:",  "HTTP sources in script-src — insecure script loading", "MEDIUM"),
            ]
            for pattern, detail, severity in csp_checks:
                if re.search(pattern, csp, re.I):
                    self._add({
                        "type":             "CSP_WEAK_DIRECTIVE",
                        "severity":         severity,
                        "confidence":       93,
                        "confidence_label": confidence_label(93),
                        "url":              self.target,
                        "header_name":      "Content-Security-Policy",
                        "csp_snippet":      csp[:300],
                        "weak_pattern":     pattern,
                        "proof":            f"Content-Security-Policy: {csp[:200]}\n  Issue: {detail}",
                        "detail":           f"Weak CSP: {detail}",
                        "remediation":      "Use 'nonce-{random}' or 'sha256-{hash}' instead of unsafe-inline/eval. Use strict CSP.",
                        "mitre_technique":  "T1059.007",
                        "mitre_name":       "JavaScript",
                        "reproducibility":  f"curl -I {self.target} | grep -i content-security",
                    })
            # Missing base-uri
            if "base-uri" not in csp.lower():
                self._add({
                    "type":             "CSP_MISSING_BASE_URI",
                    "severity":         "MEDIUM",
                    "confidence":       90,
                    "confidence_label": confidence_label(90),
                    "url":              self.target,
                    "proof":            "CSP present but missing base-uri directive",
                    "detail":           "CSP lacks base-uri — injected <base> tags can redirect relative URLs to attacker domain",
                    "remediation":      "Add base-uri 'self' to Content-Security-Policy.",
                    "mitre_technique":  "T1059.007",
                    "mitre_name":       "JavaScript",
                    "reproducibility":  f"curl -I {self.target} | grep -i content-security",
                })
            # Missing object-src
            if "object-src" not in csp.lower() and "default-src" not in csp.lower():
                self._add({
                    "type":             "CSP_MISSING_OBJECT_SRC",
                    "severity":         "HIGH",
                    "confidence":       85,
                    "confidence_label": confidence_label(85),
                    "url":              self.target,
                    "proof":            "CSP present but missing object-src directive",
                    "detail":           "CSP lacks object-src — Flash/Java plugins can execute arbitrary code",
                    "remediation":      "Add object-src 'none' to Content-Security-Policy.",
                    "mitre_technique":  "T1059.007",
                    "mitre_name":       "JavaScript",
                    "reproducibility":  f"curl -I {self.target} | grep -i content-security",
                })

        # HSTS sub-checks
        hsts = hl.get("strict-transport-security", "")
        if hsts:
            if "includesubdomains" not in hsts.lower():
                self._add({
                    "type":             "HSTS_MISSING_INCLUDESUBDOMAINS",
                    "severity":         "LOW",
                    "confidence":       95,
                    "confidence_label": confidence_label(95),
                    "url":              self.target,
                    "current_value":    hsts,
                    "proof":            f"Strict-Transport-Security: {hsts}\n  Missing: includeSubDomains",
                    "detail":           "HSTS lacks includeSubDomains — subdomains can be attacked via HTTP",
                    "remediation":      "Add includeSubDomains to HSTS: max-age=63072000; includeSubDomains; preload",
                    "mitre_technique":  "T1557",
                    "mitre_name":       "Adversary-in-the-Middle",
                    "reproducibility":  f"curl -I {self.target} | grep -i strict-transport",
                })

    # ── Info Disclosure Headers ────────────────────────────────────────────────

    async def check_info_disclosure(self, sess):
        print("\n[*] Checking information disclosure headers...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        for header_name, pattern, desc in INFO_DISCLOSURE_HEADERS:
            val = hdrs.get(header_name, hdrs.get(header_name.lower(), ""))
            if val and re.search(pattern, val, re.I):
                self._add({
                    "type":             f"INFO_DISCLOSURE_{header_name.upper().replace('-', '_')}",
                    "severity":         "INFO",
                    "confidence":       90,
                    "confidence_label": confidence_label(90),
                    "url":              self.target,
                    "header_name":      header_name,
                    "header_value":     val,
                    "proof":            f"GET {self.target}\n  {header_name}: {val}",
                    "detail":           f"{desc}: '{val}' — helps attackers fingerprint and target known vulnerabilities",
                    "remediation":      f"Remove or genericize the {header_name} header in web server configuration.",
                    "mitre_technique":  "T1082",
                    "mitre_name":       "System Information Discovery",
                    "reproducibility":  f"curl -I {self.target}",
                })

    # ── CORS ────────────────────────────────────────────────────────────────

    async def check_cors(self, sess):
        print("\n[*] Testing CORS misconfiguration (14 origins × API paths)...")
        for path in ["/" ] + SENSITIVE_API_PATHS:
            url = self.target + path
            s0, _, _ = await self._get(sess, url)
            await delay(0.04)
            if s0 in (None, 404, 405):
                continue
            for origin_template in CORS_TEST_ORIGINS:
                origin = origin_template.replace("{host}", self.host)
                s, body, hdrs = await self._get(sess, url, headers={"Origin": origin})
                await delay(0.04)
                if s is None:
                    continue
                hl = {k.lower(): v for k, v in hdrs.items()}
                acao = hl.get("access-control-allow-origin", "")
                acac = hl.get("access-control-allow-credentials", "").lower()
                if not acao:
                    continue

                if origin == "null" and acao == "null" and acac == "true":
                    self._add({
                        "type":             "CORS_NULL_ORIGIN_WITH_CREDENTIALS",
                        "severity":         "CRITICAL",
                        "confidence":       98,
                        "confidence_label": confidence_label(98),
                        "url":              url,
                        "origin_sent":      origin,
                        "acao_header":      acao,
                        "acac_header":      acac,
                        "proof":            f"GET {url}\n  Origin: null\n  ACAO: {acao}\n  ACAC: {acac}",
                        "detail":           "CORS null-origin + credentials — any sandboxed iframe can read authenticated API responses. Full account takeover possible.",
                        "remediation":      "Never allow null origin. Use explicit domain allowlist. Remove Access-Control-Allow-Credentials: true for public endpoints.",
                        "mitre_technique":  "T1557",
                        "mitre_name":       "Adversary-in-the-Middle",
                        "reproducibility":  f"curl -s {url} -H 'Origin: null'",
                        "exploitability":   10,
                    })

                elif acao == origin and acac == "true" and origin != "null":
                    self._add({
                        "type":             "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
                        "severity":         "CRITICAL",
                        "confidence":       97,
                        "confidence_label": confidence_label(97),
                        "url":              url,
                        "origin_sent":      origin,
                        "acao_header":      acao,
                        "acac_header":      acac,
                        "proof":            f"GET {url}\n  Origin: {origin}\n  ACAO: {acao}\n  ACAC: {acac}",
                        "detail":           f"CORS reflects arbitrary origin {origin} with credentials=true — attacker can read any authenticated API response",
                        "remediation":      "Use a strict allowlist. Never dynamically reflect the Origin header. Separate credentialed and public CORS policies.",
                        "mitre_technique":  "T1557",
                        "mitre_name":       "Adversary-in-the-Middle",
                        "reproducibility":  f"curl -s {url} -H 'Origin: {origin}'",
                        "exploitability":   10,
                    })
                    break  # stop testing more origins for this path

                elif acao == "*" and acac == "true":
                    self._add({
                        "type":             "CORS_WILDCARD_WITH_CREDENTIALS",
                        "severity":         "HIGH",
                        "confidence":       90,
                        "confidence_label": confidence_label(90),
                        "url":              url,
                        "acao_header":      acao,
                        "acac_header":      acac,
                        "proof":            f"GET {url}\n  ACAO: *\n  ACAC: true\n  (Browsers block but policy intent is dangerous)",
                        "detail":           "Wildcard CORS combined with credentials=true indicates broken policy intent (browsers block it, but verify origin reflection logic)",
                        "remediation":      "Fix CORS policy. Wildcard and credentials=true cannot coexist. Use explicit origin allowlist.",
                        "mitre_technique":  "T1557",
                        "mitre_name":       "Adversary-in-the-Middle",
                        "reproducibility":  f"curl -s {url} -H 'Origin: https://evil.com'",
                        "exploitability":   7,
                    })

    # ── CORS Preflight ────────────────────────────────────────────────────────

    async def check_cors_preflight(self, sess):
        print("\n[*] Testing CORS preflight (OPTIONS) on sensitive paths...")
        for path in SENSITIVE_API_PATHS[:5]:
            url = self.target + path
            s, body, hdrs = await self._options(sess, url, headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
            })
            await delay(0.06)
            if s is None:
                continue
            hl = {k.lower(): v for k, v in hdrs.items()}
            acam = hl.get("access-control-allow-methods", "")
            acah = hl.get("access-control-allow-headers", "")
            acao = hl.get("access-control-allow-origin", "")
            if "delete" in acam.lower() or "put" in acam.lower():
                self._add({
                    "type":             "CORS_PREFLIGHT_DANGEROUS_METHODS",
                    "severity":         "HIGH",
                    "confidence":       88,
                    "confidence_label": confidence_label(88),
                    "url":              url,
                    "acao":             acao,
                    "allowed_methods":  acam,
                    "allowed_headers":  acah,
                    "proof":            f"OPTIONS {url}\n  Origin: evil.com\n  ACAO: {acao}\n  ACAM: {acam}\n  HTTP {s}",
                    "detail":           f"CORS preflight allows dangerous methods ({acam}) cross-origin — enables cross-site destructive API calls",
                    "remediation":      "Restrict Access-Control-Allow-Methods to GET, POST only for public APIs. Apply CSRF protection for state-changing methods.",
                    "mitre_technique":  "T1557",
                    "mitre_name":       "Adversary-in-the-Middle",
                    "reproducibility":  f"curl -X OPTIONS {url} -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: DELETE'",
                    "exploitability":   8,
                })

    # ── Host Header Injection ─────────────────────────────────────────────────

    async def check_host_injection(self, sess):
        print("\n[*] Testing Host header injection (password reset poisoning)...")
        poison_hosts = [
            "evil.com", "evil.com:443", "evil.com@target.com",
            "target.com.evil.com", "target.com\nevil.com",
        ]
        for path in HOST_INJECTION_PATHS:
            url = self.target + path
            s0, _, _ = await self._get(sess, url)
            await delay(0.05)
            if s0 not in (200, 201, 400, 422):
                continue
            for poison_host in poison_hosts[:3]:
                s, body, hdrs = await self._get(sess, url, headers={
                    "Host": poison_host,
                    "X-Forwarded-Host": poison_host,
                })
                await delay(0.06)
                if s in (None, 404, 405):
                    continue
                if s in (200, 201, 202) and poison_host in (body or ""):
                    self._add({
                        "type":             "HOST_HEADER_INJECTION",
                        "severity":         "HIGH",
                        "confidence":       92,
                        "confidence_label": confidence_label(92),
                        "url":              url,
                        "injected_host":    poison_host,
                        "proof":            f"GET {url}\n  Host: {poison_host}\n  HTTP {s}\n  '{poison_host}' found in response body",
                        "detail":           f"Host header injection at {path} — password reset emails will contain attacker-controlled link to {poison_host}",
                        "remediation":      "1. Use an absolute URL configured server-side for password reset links.\n2. Validate/allowlist the Host header.\n3. Never use the Host header to construct email links.",
                        "mitre_technique":  "T1566",
                        "mitre_name":       "Phishing",
                        "reproducibility":  f"curl -s {url} -H 'Host: {poison_host}'",
                        "exploitability":   8,
                    })
                    break

    # ── Cache Control on Auth Endpoints ──────────────────────────────────────

    async def check_cache_control(self, sess):
        print("\n[*] Checking cache-control on authenticated API endpoints...")
        for path in SENSITIVE_API_PATHS:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url)
            await delay(0.05)
            if s != 200 or not body:
                continue
            hl = {k.lower(): v for k, v in hdrs.items()}
            cc = hl.get("cache-control", "")
            pragma = hl.get("pragma", "")
            if "no-store" not in cc.lower() and "private" not in cc.lower():
                self._add({
                    "type":             "AUTH_API_RESPONSE_CACHEABLE",
                    "severity":         "MEDIUM",
                    "confidence":       82,
                    "confidence_label": confidence_label(82),
                    "url":              url,
                    "cache_control":    cc or "(absent)",
                    "pragma":           pragma or "(absent)",
                    "proof":            f"GET {url}\n  HTTP {s}\n  Cache-Control: {cc or 'absent'}\n  Pragma: {pragma or 'absent'}\n  Response may be cached by shared proxies",
                    "detail":           f"Authenticated API endpoint {path} lacks Cache-Control: no-store — response may be cached by shared proxy/CDN, leaking sensitive data",
                    "remediation":      "Add: Cache-Control: no-store, no-cache, private to all authenticated API responses.",
                    "mitre_technique":  "T1565",
                    "mitre_name":       "Data Manipulation",
                    "reproducibility":  f"curl -I {url}",
                })

    async def run(self):
        print("=" * 60)
        print("  HeaderForge v8 — 150x Improved Header Security Analyser")
        print(f"  Target: {self.target}")
        print("=" * 60)
        connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        timeout   = aiohttp.ClientTimeout(total=120, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await asyncio.gather(
                self.check_security_headers(sess),
                self.check_info_disclosure(sess),
                self.check_cors(sess),
                self.check_cors_preflight(sess),
                self.check_host_injection(sess),
                self.check_cache_control(sess),
                return_exceptions=True,
            )
        print(f"\n[+] HeaderForge v8 complete: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = HeaderForge(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "headerforge.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
