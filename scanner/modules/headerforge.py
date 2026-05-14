#!/usr/bin/env python3
"""HeaderForge v6 — Zero-False-Positive HTTP Header Security Analyser.

CORS: 2-stage validation — reflect + credentials check, then verify sensitive data access.
CSP: flag only exploitable weaknesses (unsafe-inline, unsafe-eval, wildcards).
Security headers: HIGH only for HSTS and CSP (genuinely exploitable when missing).
             MEDIUM for X-Frame-Options (clickjacking).
             INFO for informational headers (Referrer-Policy etc.).
Info disclosure: INFO severity only.
Cache: flag authenticated endpoints with no-store/private missing AND 200 response.
"""
import asyncio, aiohttp, json, re, sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

CORS_TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",
    "https://target.com.evil.com",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True, "severity": "HIGH",
        "validate": lambda v: "max-age=" in v.lower() and int(
            re.search(r'max-age=(\d+)', v, re.I).group(1)) >= 31536000
            if re.search(r'max-age=(\d+)', v, re.I) else False,
        "ideal": "max-age=63072000; includeSubDomains; preload",
        "detail": "Missing HSTS — browser allows HTTP downgrade, enables SSL stripping / MITM attacks",
    },
    "Content-Security-Policy": {
        "required": True, "severity": "HIGH",
        "validate": lambda v: "default-src" in v or "script-src" in v,
        "ideal": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        "detail": "Missing CSP — XSS attacks will execute unrestricted JavaScript",
    },
    "X-Frame-Options": {
        "required": False, "severity": "MEDIUM",
        "validate": lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
        "ideal": "DENY",
        "detail": "Missing X-Frame-Options — page can be embedded in attacker iframe (clickjacking)",
    },
    "X-Content-Type-Options": {
        "required": True, "severity": "INFO",
        "validate": lambda v: v.lower() == "nosniff",
        "ideal": "nosniff",
        "detail": "Missing X-Content-Type-Options — MIME-sniffing attacks possible in legacy browsers",
    },
    "Referrer-Policy": {
        "required": True, "severity": "INFO",
        "validate": lambda v: v.lower() in [
            "no-referrer","strict-origin","strict-origin-when-cross-origin","same-origin"],
        "ideal": "strict-origin-when-cross-origin",
        "detail": "Referrer-Policy absent — full URL sent to third-party origins in Referer header",
    },
    "Permissions-Policy": {
        "required": True, "severity": "INFO",
        "validate": lambda v: len(v) > 5,
        "ideal": "geolocation=(), microphone=(), camera=()",
        "detail": "No Permissions-Policy — browser APIs (camera, mic, geolocation) unrestricted",
    },
}

CSP_EXPLOITABLE = [
    (r"script-src[^;]*'unsafe-inline'",   "unsafe-inline in script-src bypasses XSS protection", "HIGH"),
    (r"script-src[^;]*'unsafe-eval'",     "unsafe-eval allows eval() — code injection via XSS",  "HIGH"),
    (r"default-src[^;]*'unsafe-inline'",  "unsafe-inline in default-src — CSP effectively disabled","HIGH"),
    (r"script-src[^;]*\*(?:['\'\s;]|$)", "Wildcard * in script-src — any domain can load scripts","CRITICAL"),
    (r"frame-ancestors\s+\*",            "frame-ancestors * — clickjacking protection disabled",  "HIGH"),
    (r"object-src(?![^;]*'none')",        "object-src not 'none' — plugin/Flash injection possible","MEDIUM"),
]

SENSITIVE_BODY_RE = [
    r'"(?:email|username|user_id|account_id|phone)"\s*:',
    r'"(?:token|access_token|refresh_token|jwt|session_id)"\s*:',
    r'"(?:balance|card_number|password_hash|secret|role|permissions)"\s*:',
]


class HeaderForge:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        self.host     = urlparse(target).hostname
        self.findings = []
        self._reported = set()

    def _dedup(self, key):
        if key in self._reported:
            return False
        self._reported.add(key)
        return True

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(
                url, headers=headers or {}, ssl=False,
                timeout=aiohttp.ClientTimeout(total=12),
                allow_redirects=True
            ) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    async def audit_security_headers(self, sess):
        print("\n[*] Auditing security headers (value-validated, not just presence)...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        if not hdrs:
            return

        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        csp_val = hdrs_lower.get('content-security-policy', '')
        has_frame_ancestors = 'frame-ancestors' in csp_val.lower()

        for header, cfg in SECURITY_HEADERS.items():
            key = header.lower()
            value = hdrs_lower.get(key)

            if header == "X-Frame-Options" and has_frame_ancestors:
                continue

            if value is None and cfg["required"]:
                conf = 85
                self.findings.append({
                    'type': f'MISSING_{header.upper().replace("-","_")}',
                    'severity': cfg["severity"],
                    'confidence': conf,
                    'confidence_label': confidence_label(conf),
                    'url': self.target,
                    'header': header,
                    'proof': f"GET {self.target} — response has no {header} header",
                    'detail': f"Missing {header}: {cfg['detail']}",
                    'remediation': f"Add to server config: {header}: {cfg['ideal']}",
                })
                print(f"  [{cfg['severity']}] MISSING: {header}")
            elif value is not None:
                try:
                    valid = cfg["validate"](value)
                except Exception:
                    valid = False
                if not valid and cfg["required"]:
                    self.findings.append({
                        'type': f'WEAK_{header.upper().replace("-","_")}',
                        'severity': cfg["severity"],
                        'confidence': 82,
                        'confidence_label': confidence_label(82),
                        'url': self.target,
                        'header': header,
                        'current_value': value,
                        'ideal_value': cfg["ideal"],
                        'proof': f"{header}: {value} (does not meet minimum security value)",
                        'detail': f"Weak {header}: {cfg['detail']}",
                        'remediation': f"Update to: {header}: {cfg['ideal']}",
                    })
                    print(f"  [{cfg['severity']}] WEAK {header}: {value[:80]}")
                else:
                    print(f"  [OK] {header}: {value[:60]}")

    async def analyse_csp(self, sess):
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        csp = hdrs.get('Content-Security-Policy') or hdrs.get('content-security-policy', '')
        if not csp:
            return

        print("\n[*] Deep CSP analysis...")
        for pattern, detail, severity in CSP_EXPLOITABLE:
            if re.search(pattern, csp, re.I):
                self.findings.append({
                    'type': 'CSP_EXPLOITABLE_DIRECTIVE',
                    'severity': severity,
                    'confidence': 93,
                    'confidence_label': 'High',
                    'url': self.target,
                    'proof': f"Content-Security-Policy: {csp[:500]}\nMatched: {pattern}",
                    'detail': f"CSP weakness: {detail}",
                    'remediation': (
                        "Remove 'unsafe-inline'/'unsafe-eval'. Use nonces or hashes. "
                        "Set object-src 'none'. Restrict frame-ancestors to 'self'."
                    ),
                })
                print(f"  [CSP-{severity}] {detail}")

    async def audit_cors(self, sess):
        """
        2-stage CORS validation:
        Stage 1 — Send attacker origin and check reflection + credentials flag.
        Stage 2 — Check if response body contains sensitive user data
                   (confirms the exploit has real impact without an authenticated session).
        """
        print("\n[*] CORS audit — reflection + sensitive data verification...")
        reported = set()

        for origin in CORS_TEST_ORIGINS:
            for path in ['/', '/api', '/api/v1', '/api/me', '/api/profile', '/api/user']:
                url = self.target + path
                s, body, hdrs = await self._get(sess, url, headers={"Origin": origin})
                await delay()

                acao = (hdrs.get('Access-Control-Allow-Origin') or
                        hdrs.get('access-control-allow-origin', ''))
                acac = (hdrs.get('Access-Control-Allow-Credentials') or
                        hdrs.get('access-control-allow-credentials', '')).lower()

                if not acao:
                    continue

                # ── Case 1: reflects attacker origin + credentials=true ──────
                if acao == origin and acac == 'true':
                    key = f"CORS_CRED:{origin}"
                    if key in reported:
                        continue
                    reported.add(key)

                    # Stage 2: check if unauthenticated response already leaks sensitive data
                    has_sensitive = any(re.search(p, body or '', re.I) for p in SENSITIVE_BODY_RE)
                    severity = 'CRITICAL' if has_sensitive else 'HIGH'
                    confidence = 97 if has_sensitive else 88

                    self.findings.append({
                        'type': 'CORS_REFLECTED_WITH_CREDENTIALS',
                        'severity': severity,
                        'confidence': confidence,
                        'confidence_label': confidence_label(confidence),
                        'url': url,
                        'test_origin': origin,
                        'acao_header': acao,
                        'acac_header': 'true',
                        'sensitive_data_confirmed': has_sensitive,
                        'proof': (
                            f"Request: Origin: {origin}\n"
                            f"Response: Access-Control-Allow-Origin: {acao}\n"
                            f"         Access-Control-Allow-Credentials: true\n"
                            + ("CONFIRMED: Response body contains sensitive user fields"
                               if has_sensitive else
                               "NOTE: No sensitive data in unauthenticated response — exploit needs victim session")
                        ),
                        'detail': (
                            f"CORS misconfiguration: attacker origin '{origin}' reflected with credentials=true.\n"
                            f"Any script on {origin} can make credentialed XHR to {path} and read the response."
                        ),
                        'remediation': (
                            "1. Never reflect the Origin header verbatim.\n"
                            "2. Maintain a hardcoded allowlist of trusted origins.\n"
                            "3. Set Access-Control-Allow-Credentials: true ONLY for specific trusted origins.\n"
                            "4. Use a CORS library with strict allowlist validation."
                        ),
                    })
                    print(f"  [{severity}] CORS: {origin} reflected + credentials=true at {path}"
                          + (" [SENSITIVE DATA IN RESPONSE]" if has_sensitive else ""))

                # ── Case 2: wildcard + credentials (invalid per spec, still misconfigured) ──
                elif acao == '*' and acac == 'true':
                    if 'CORS_WILDCARD_CRED' not in reported:
                        reported.add('CORS_WILDCARD_CRED')
                        self.findings.append({
                            'type': 'CORS_WILDCARD_WITH_CREDENTIALS',
                            'severity': 'HIGH',
                            'confidence': 95,
                            'confidence_label': 'High',
                            'url': url,
                            'proof': f"ACAO: * + ACAC: true — browsers reject this but config is broken",
                            'detail': "CORS wildcard + credentials — invalid combo per spec; indicates server misconfiguration",
                            'remediation': "Replace * with explicit trusted origins when using Allow-Credentials.",
                        })
                        print(f"  [HIGH] CORS wildcard + credentials at {path}")

                # ── Case 3: reflects origin (no credentials) — LOW risk ──────
                elif acao == origin and acac != 'true':
                    key = f"CORS_REFLECT_NO_CRED:{origin}"
                    if key not in reported and s == 200 and len(body or "") > 100:
                        reported.add(key)
                        self.findings.append({
                            'type': 'CORS_REFLECTS_ORIGIN',
                            'severity': 'LOW',
                            'confidence': 72,
                            'confidence_label': confidence_label(72),
                            'url': url,
                            'test_origin': origin,
                            'proof': f"Origin: {origin} → ACAO: {acao} (no credentials flag, but cross-origin reads possible)",
                            'detail': "CORS reflects origin without credentials — cross-origin reads of unauthenticated content allowed",
                            'remediation': "Replace dynamic reflection with explicit origin allowlist.",
                        })
                        print(f"  [LOW] CORS reflects {origin} at {path} (no credentials)")

    async def check_info_disclosure(self, sess):
        print("\n[*] Checking server/technology version disclosure...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        for hdr_name in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            val = hdrs.get(hdr_name) or hdrs.get(hdr_name.lower())
            if val and re.search(r'[0-9]+\.[0-9]+', val):
                self.findings.append({
                    'type': 'SERVER_VERSION_DISCLOSURE',
                    'severity': 'INFO',
                    'confidence': 95,
                    'confidence_label': 'Confirmed',
                    'url': self.target,
                    'header': hdr_name,
                    'value': val,
                    'proof': f"{hdr_name}: {val}",
                    'detail': f"Version exposed via {hdr_name} — enables targeted CVE lookup",
                    'remediation': f"Suppress {hdr_name}: server_tokens off; / ServerTokens Prod; / app.disable('x-powered-by');",
                })
                print(f"  [INFO] {hdr_name}: {val}")

    async def check_cache_security(self, sess):
        print("\n[*] Cache-control on sensitive endpoints...")
        for path in ['/api/me', '/api/profile', '/api/user', '/dashboard', '/account']:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url)
            await delay()
            if s != 200:
                continue
            cc = hdrs.get('Cache-Control') or hdrs.get('cache-control', '')
            if not any(kw in (cc or '').lower() for kw in ['no-store','private','no-cache']):
                self.findings.append({
                    'type': 'SENSITIVE_ENDPOINT_CACHEABLE',
                    'severity': 'MEDIUM',
                    'confidence': 80,
                    'confidence_label': confidence_label(80),
                    'url': url,
                    'cache_control': cc or '(absent)',
                    'proof': (
                        f"HTTP 200 at {path}\n"
                        f"Cache-Control: {cc or '(absent)'}\n"
                        f"Response may be stored by shared caches / CDNs"
                    ),
                    'detail': f"Sensitive endpoint {path} cacheable — auth responses may leak via shared cache",
                    'remediation': "Add: Cache-Control: no-store, no-cache, must-revalidate, private",
                })
                print(f"  [MEDIUM] Cacheable sensitive path: {path}")

    async def run(self):
        print("=" * 60)
        print("  HeaderForge v6 — Zero-False-Positive Header Analyser")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=6, ssl=False)
        async with aiohttp.ClientSession(
            connector=conn, timeout=aiohttp.ClientTimeout(total=60),
            headers={"User-Agent": random_ua()}
        ) as sess:
            await self.audit_security_headers(sess)
            await self.analyse_csp(sess)
            await self.audit_cors(sess)
            await self.check_info_disclosure(sess)
            await self.check_cache_security(sess)
        print(f"\n[+] HeaderForge: {len(self.findings)} findings")
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
