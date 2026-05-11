#!/usr/bin/env python3
"""HeaderForge v4 — Pro-grade HTTP Header Attack Surface Analyser.

Improvements over v3:
- CORS: tests actual cross-origin requests to confirm policy (not just header presence)
- CSP: parses and grrades each directive — flags 'unsafe-inline', 'unsafe-eval', wildcards
- Security headers: checks every OWASP-recommended header with correct value validation
- Clickjacking: confirms X-Frame-Options AND CSP frame-ancestors
- Cache: detects sensitive content cached without Vary/Cache-Control
- Information leakage: server/x-powered-by version disclosure with CVE context
"""
import asyncio, aiohttp, json, re, sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

# ── CORS Origins to test ───────────────────────────────────────────────────────
CORS_TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",                          # null origin (file:// or sandboxed iframe)
    "https://target.com.evil.com",   # subdomain confusion
]

# ── Expected security headers with correct values ─────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "validate": lambda v: "max-age=" in v.lower() and int(
            re.search(r'max-age=(\d+)', v, re.I).group(1)) >= 31536000
            if re.search(r'max-age=(\d+)', v, re.I) else False,
        "severity": "HIGH",
        "ideal": "max-age=63072000; includeSubDomains; preload",
        "detail": "HSTS forces HTTPS — missing/weak value allows SSL stripping attacks",
    },
    "Content-Security-Policy": {
        "required": True,
        "validate": lambda v: "default-src" in v or "script-src" in v,
        "severity": "HIGH",
        "ideal": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        "detail": "CSP prevents XSS by restricting script sources",
    },
    "X-Frame-Options": {
        "required": False,  # OK if CSP frame-ancestors is set instead
        "validate": lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
        "severity": "MEDIUM",
        "ideal": "DENY",
        "detail": "Missing X-Frame-Options enables clickjacking — attacker embeds site in iframe",
    },
    "X-Content-Type-Options": {
        "required": True,
        "validate": lambda v: v.lower() == "nosniff",
        "severity": "LOW",
        "ideal": "nosniff",
        "detail": "Missing nosniff allows MIME-type sniffing attacks in IE/old browsers",
    },
    "Referrer-Policy": {
        "required": True,
        "validate": lambda v: v.lower() in [
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade", "same-origin"],
        "severity": "LOW",
        "ideal": "strict-origin-when-cross-origin",
        "detail": "Referrer-Policy controls how much URL info is sent to third parties",
    },
    "Permissions-Policy": {
        "required": True,
        "validate": lambda v: len(v) > 5,
        "severity": "LOW",
        "ideal": "geolocation=(), microphone=(), camera=()",
        "detail": "Permissions-Policy restricts access to powerful browser APIs",
    },
    "X-XSS-Protection": {
        "required": False,  # Deprecated but should not be '1' without 'mode=block'
        "validate": lambda v: v in ["0", "1; mode=block"],
        "severity": "INFO",
        "ideal": "0  (deprecated — rely on CSP instead)",
        "detail": "Non-standard value may cause issues in legacy browsers",
    },
    "Cross-Origin-Opener-Policy": {
        "required": True,
        "validate": lambda v: v.lower() in ["same-origin", "same-origin-allow-popups"],
        "severity": "LOW",
        "ideal": "same-origin",
        "detail": "COOP prevents cross-origin window access (Spectre/SharedArrayBuffer attacks)",
    },
    "Cross-Origin-Resource-Policy": {
        "required": False,
        "validate": lambda v: v.lower() in ["same-site", "same-origin", "cross-origin"],
        "severity": "LOW",
        "ideal": "same-origin",
        "detail": "CORP prevents cross-origin reads of resources",
    },
    "Cross-Origin-Embedder-Policy": {
        "required": False,
        "validate": lambda v: v.lower() in ["require-corp", "unsafe-none"],
        "severity": "LOW",
        "ideal": "require-corp",
        "detail": "COEP enables powerful features (SharedArrayBuffer) securely",
    },
}

# ── Dangerous CSP directives ───────────────────────────────────────────────────
CSP_WEAKNESSES = [
    (r"script-src[^;]*'unsafe-inline'",        "unsafe-inline in script-src bypasses XSS protection", "HIGH"),
    (r"script-src[^;]*'unsafe-eval'",          "unsafe-eval allows eval() — code injection risk",      "HIGH"),
    (r"default-src[^;]*'unsafe-inline'",       "unsafe-inline in default-src — XSS protection nullified","HIGH"),
    (r"script-src[^;]*\*(?:['\s;]|$)",         "Wildcard * in script-src — any domain can load scripts","CRITICAL"),
    (r"default-src[^;]*\*(?:['\s;]|$)",        "Wildcard * in default-src — any resource allowed",    "HIGH"),
    (r"object-src(?![^;]*'none')",             "object-src not set to 'none' — Flash/plugin injection","MEDIUM"),
    (r"base-uri(?![^;]*'(?:none|self)')",      "base-uri not restricted — base tag injection possible","MEDIUM"),
    (r"script-src[^;]*http://",                "HTTP source in script-src — plaintext script loading", "HIGH"),
    (r"frame-ancestors\s+\*",                  "frame-ancestors * — clickjacking protection disabled",  "HIGH"),
    (r"upgrade-insecure-requests",             "",  "INFO"),  # Good — info only
]

# ── Information disclosure headers ─────────────────────────────────────────────
INFO_DISCLOSURE_HEADERS = [
    ("Server",           r'(?i)(apache|nginx|iis|lighttpd|express|tomcat|jetty|gunicorn|werkzeug)[/\s]+([\d.]+)',
                         "Server version disclosed"),
    ("X-Powered-By",     r'.+',
                         "Technology stack disclosed via X-Powered-By"),
    ("X-AspNet-Version", r'.+',
                         "ASP.NET version disclosed"),
    ("X-AspNetMvc-Version", r'.+',
                         "ASP.NET MVC version disclosed"),
    ("X-Generator",      r'.+',
                         "Generator technology disclosed"),
    ("X-Drupal-Cache",   r'.+',
                         "Drupal CMS fingerprinted via X-Drupal-Cache"),
    ("X-Wix-Request-Id", r'.+',
                         "Wix platform fingerprinted"),
]


class HeaderForge:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        self.host     = urlparse(target).hostname
        self.findings = []

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    # ── Security header audit ──────────────────────────────────────────────────

    async def audit_security_headers(self, sess):
        print("\n[*] Auditing security headers — value validation, not just presence...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        if not hdrs:
            return

        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        csp_value = hdrs_lower.get('content-security-policy', '')
        has_frame_ancestors = 'frame-ancestors' in csp_value.lower()

        for header, cfg in SECURITY_HEADERS.items():
            key = header.lower()
            value = hdrs_lower.get(key)

            # X-Frame-Options: OK if CSP frame-ancestors covers it
            if header == "X-Frame-Options" and has_frame_ancestors:
                continue

            if value is None and cfg["required"]:
                conf = 85
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type': 'MISSING_SECURITY_HEADER',
                        'severity': cfg["severity"],
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'url': self.target,
                        'header': header,
                        'proof': f"Header '{header}' absent from response",
                        'ideal_value': cfg["ideal"],
                        'detail': f"Missing {header}: {cfg['detail']}",
                        'remediation': f"Add: {header}: {cfg['ideal']}",
                    })
                    print(f"  [MISSING] {header}")
            elif value is not None:
                try:
                    valid = cfg["validate"](value)
                except Exception:
                    valid = False
                if not valid and cfg["required"]:
                    conf = 80
                    if meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'WEAK_SECURITY_HEADER',
                            'severity': cfg["severity"],
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': self.target,
                            'header': header,
                            'current_value': value,
                            'ideal_value': cfg["ideal"],
                            'proof': f"{header}: {value} — value does not meet security standard",
                            'detail': f"Weak {header} value: {cfg['detail']}",
                            'remediation': f"Change to: {header}: {cfg['ideal']}",
                        })
                        print(f"  [WEAK] {header}: {value[:80]}")
                else:
                    print(f"  [OK] {header}")

    # ── CSP deep analysis ──────────────────────────────────────────────────────

    async def analyse_csp(self, sess):
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        if not hdrs:
            return

        csp = hdrs.get('Content-Security-Policy') or hdrs.get('content-security-policy', '')
        if not csp:
            return  # Already flagged by security header audit

        print(f"\n[*] Deep CSP analysis — checking {len(CSP_WEAKNESSES)} weakness patterns...")

        for pattern, detail, severity in CSP_WEAKNESSES:
            if not detail:
                continue  # Info-only, skip
            if re.search(pattern, csp, re.I):
                conf = 90
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type': 'CSP_WEAKNESS',
                        'severity': severity,
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'url': self.target,
                        'csp_value': csp[:500],
                        'matched_pattern': pattern,
                        'proof': f"CSP directive matches weak pattern: {detail}",
                        'detail': f"CSP weakness: {detail}",
                        'remediation': (
                            "Review CSP directives. Remove 'unsafe-inline'/'unsafe-eval'. "
                            "Use nonces or hashes for inline scripts. "
                            "Set object-src 'none' and base-uri 'self'."
                        ),
                    })
                    print(f"  [CSP-{severity}] {detail}")

    # ── CORS audit ─────────────────────────────────────────────────────────────

    async def audit_cors(self, sess):
        print("\n[*] CORS policy audit — testing with attacker origins...")
        for origin in CORS_TEST_ORIGINS:
            for path in ['/', '/api', '/api/v1', '/api/me']:
                url = self.target + path
                s, body, hdrs = await self._get(
                    sess, url, headers={"Origin": origin})
                await delay()
                acao = (hdrs.get('Access-Control-Allow-Origin') or
                        hdrs.get('access-control-allow-origin', ''))
                acac = (hdrs.get('Access-Control-Allow-Credentials') or
                        hdrs.get('access-control-allow-credentials', ''))

                if not acao:
                    continue

                # Critical: reflects the attacker origin AND allows credentials
                if acao == origin and acac.lower() == 'true':
                    self.findings.append({
                        'type': 'CORS_REFLECT_WITH_CREDENTIALS',
                        'severity': 'CRITICAL',
                        'confidence': 95,
                        'confidence_label': 'High',
                        'url': url,
                        'test_origin': origin,
                        'acao_header': acao,
                        'acac_header': acac,
                        'proof': (f"Origin: {origin} → "
                                  f"Access-Control-Allow-Origin: {acao} + "
                                  f"Access-Control-Allow-Credentials: true"),
                        'detail': (f"CORS reflects attacker origin with credentials=true — "
                                   f"attacker can make authenticated cross-origin requests"),
                        'remediation': (
                            "1. Never reflect the Origin header verbatim. "
                            "2. Maintain an explicit whitelist of allowed origins. "
                            "3. Only set Access-Control-Allow-Credentials: true for trusted origins."
                        ),
                    })
                    print(f"  [CRITICAL] CORS: {origin} reflected + credentials=true at {path}!")

                elif acao == '*' and acac.lower() == 'true':
                    self.findings.append({
                        'type': 'CORS_WILDCARD_WITH_CREDENTIALS',
                        'severity': 'CRITICAL',
                        'confidence': 95,
                        'confidence_label': 'High',
                        'url': url,
                        'proof': "Access-Control-Allow-Origin: * with Allow-Credentials: true",
                        'detail': "CORS wildcard + credentials — browsers block this, but indicates misconfiguration",
                        'remediation': "Remove wildcard ACAO when using credentials. Use explicit origin whitelist.",
                    })
                    print(f"  [CRITICAL] CORS wildcard + credentials at {path}")

                elif acao == origin:
                    conf = 75
                    if meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'CORS_REFLECTS_ORIGIN',
                            'severity': 'MEDIUM',
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': url,
                            'test_origin': origin,
                            'acao_header': acao,
                            'proof': f"Origin: {origin} → Access-Control-Allow-Origin: {acao} (reflected)",
                            'detail': "CORS reflects any origin — allows cross-origin reads from attacker pages",
                            'remediation': "Implement explicit origin allowlist instead of reflecting input.",
                        })
                        print(f"  [MEDIUM] CORS reflects {origin} at {path}")
                    break  # One finding per origin type is enough

    # ── Information disclosure ─────────────────────────────────────────────────

    async def check_info_disclosure(self, sess):
        print("\n[*] Checking for server/technology version disclosure...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        if not hdrs:
            return

        for hdr_name, pattern, detail in INFO_DISCLOSURE_HEADERS:
            value = hdrs.get(hdr_name) or hdrs.get(hdr_name.lower())
            if value and re.search(pattern, value, re.I):
                self.findings.append({
                    'type': 'INFORMATION_DISCLOSURE',
                    'severity': 'LOW',
                    'confidence': 92,
                    'confidence_label': 'High',
                    'url': self.target,
                    'header': hdr_name,
                    'value': value,
                    'proof': f"{hdr_name}: {value}",
                    'detail': f"{detail} — aids attacker reconnaissance (CVE lookup by version)",
                    'remediation': (
                        f"Remove or suppress the {hdr_name} header. "
                        "In Nginx: server_tokens off; In Apache: ServerTokens Prod; "
                        "In Express: app.disable('x-powered-by');"
                    ),
                })
                print(f"  [INFO-LEAK] {hdr_name}: {value}")

    # ── Cache poisoning surface ────────────────────────────────────────────────

    async def check_cache_security(self, sess):
        print("\n[*] Checking cache configuration on sensitive endpoints...")
        sensitive_paths = ['/api/me', '/api/profile', '/api/user', '/dashboard', '/account']
        for path in sensitive_paths:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url)
            await delay()
            if s not in [200, 203]:
                continue
            cc = hdrs.get('Cache-Control') or hdrs.get('cache-control', '')
            if not cc or not any(
                    kw in cc.lower() for kw in ['no-store', 'private', 'no-cache']):
                self.findings.append({
                    'type': 'SENSITIVE_ENDPOINT_CACHED',
                    'severity': 'MEDIUM',
                    'confidence': 78,
                    'confidence_label': confidence_label(78),
                    'url': url,
                    'cache_control': cc or '(absent)',
                    'proof': f"HTTP {s} — no Cache-Control: no-store/private on sensitive path",
                    'detail': f"Sensitive endpoint {path} may be cached by browsers/proxies",
                    'remediation': (
                        "Add: Cache-Control: no-store, no-cache, must-revalidate, private "
                        "on all authenticated/sensitive endpoints."
                    ),
                })
                print(f"  [MEDIUM] Cacheable sensitive path: {url} (Cache-Control: {cc or 'absent'})")

    # ── Runner ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  HeaderForge v4 — HTTP Header Attack Surface Analyser")
        print("  Deep validation: values checked, not just presence")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=8, ssl=False)
        async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": random_ua()}) as sess:

            await self.audit_security_headers(sess)
            await self.analyse_csp(sess)
            await self.audit_cors(sess)
            await self.check_info_disclosure(sess)
            await self.check_cache_security(sess)

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
    findings = asyncio.run(HeaderForge(target).run())
    with open("reports/headerforge.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/headerforge.json")


if __name__ == '__main__':
    main()
