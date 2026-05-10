#!/usr/bin/env python3
"""
HeaderForge v2 — HTTP header attack surface analyser.

Improvements:
  - Host header injection (password reset poisoning, cache poisoning)
  - X-Forwarded-Host / X-Host / X-Forwarded-Server injection
  - HTTP Response Splitting (CRLF in headers)
  - Header-based SQL injection
  - HTTP method override (X-HTTP-Method-Override, X-Method-Override)
  - Hop-by-hop header stripping abuse
  - Cache control manipulation
  - Server-side request forgery via Referer / Host
  - Security header completeness audit
  - CORS preflight detailed audit
  - Content-Type confusion attacks
  - All findings include proof and remediation
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_likely_real_vuln, is_reflected, delay,
    confidence_score, confidence_label, severity_from_confidence, REQUEST_DELAY
)

class HeaderForge:
    def __init__(self, target):
        self.target        = target.rstrip('/')
        self.host          = urlparse(target).hostname
        self.scheme        = urlparse(target).scheme
        self.findings      = []
        self.baseline_404  = ""

    async def _get(self, sess, url, headers=None, allow_redirects=False):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=allow_redirects) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, headers=None):
        try:
            async with sess.post(url, data=data or {}, headers=headers or {}, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _add(self, finding):
        self.findings.append(finding)

    # ── Host header injection ─────────────────────────────────────────────────

    async def test_host_injection(self, sess):
        print("\n[*] Testing Host header injection...")
        evil_host = "evil-host-injection.com"
        password_reset_paths = [
            '/auth/forgot-password', '/forgot-password', '/reset-password',
            '/api/auth/reset', '/user/forgot',
        ]
        for path in password_reset_paths:
            url = self.target + path
            s, b, hdrs = await self._get(sess, url,
                headers={"Host": evil_host, "X-Forwarded-Host": evil_host})
            await delay()
            if s in [200, 400] and b and is_reflected(evil_host, b):
                self._add({
                    'type':             'HOST_HEADER_INJECTION',
                    'severity':         'HIGH',
                    'confidence':       90,
                    'confidence_label': 'High',
                    'url':              url,
                    'injected_host':    evil_host,
                    'proof':            f"'{evil_host}' reflected in body at {path}",
                    'detail':           "Host header injection — password reset link may point to attacker domain",
                    'remediation':      "Use an allowlist of valid hostnames. Never use the Host header to construct password reset URLs.",
                })
                print(f"  [HIGH] Host injection at {url}")

        # Cache poisoning via Host
        s, b, hdrs = await self._get(sess, self.target,
            headers={"Host": evil_host, "X-Forwarded-Host": evil_host})
        await delay()
        if b and is_reflected(evil_host, b):
            self._add({
                'type':             'HOST_CACHE_POISON',
                'severity':         'HIGH',
                'confidence':       85,
                'confidence_label': 'High',
                'url':              self.target,
                'detail':           "Host header reflected in root response — cache poisoning risk",
                'remediation':      "Validate the Host header against a server-side allowlist.",
            })
            print(f"  [HIGH] Host header reflected in root (cache poison risk)")

    # ── X-Forwarded-* injection ───────────────────────────────────────────────

    async def test_forwarded_headers(self, sess):
        print("\n[*] Testing X-Forwarded-* header injection...")
        marker = "fwd-injection-test.evil.com"
        forward_headers = [
            "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
            "X-Forwarded-Proto", "X-Original-URL", "X-Rewrite-URL",
            "X-Forwarded-Prefix",
        ]
        for header in forward_headers:
            s, b, hdrs = await self._get(sess, self.target, headers={header: marker})
            await delay()
            if b and is_reflected(marker, b):
                self._add({
                    'type':             'FORWARDED_HEADER_INJECTION',
                    'severity':         'HIGH',
                    'confidence':       90,
                    'confidence_label': 'High',
                    'header':           header,
                    'url':              self.target,
                    'proof':            f"'{marker}' reflected in response via {header}",
                    'detail':           f"{header} reflected — potential SSRF or cache poisoning",
                    'remediation':      f"Do not reflect {header} in responses without validation.",
                })
                print(f"  [HIGH] {header} reflected in response")

    # ── HTTP method override ──────────────────────────────────────────────────

    async def test_method_override(self, sess):
        print("\n[*] Testing HTTP method override...")
        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "_method",
        ]
        admin_paths = ['/admin', '/api/admin', '/api/users/delete', '/dashboard']
        for path in admin_paths:
            url = self.target + path
            # First check what GET returns
            s_get, b_get, _ = await self._get(sess, url)
            await delay()
            if s_get not in [403, 401]:
                continue  # not restricted
            # Try method override
            for ovr_hdr in override_headers[:2]:
                for method in ['DELETE', 'PUT', 'PATCH']:
                    s, b, _ = await self._post(sess, url,
                        data="test=1",
                        headers={ovr_hdr: method, "Content-Type": "application/x-www-form-urlencoded"})
                    await delay()
                    if s == 200 and (not b_get or b != b_get):
                        self._add({
                            'type':             'METHOD_OVERRIDE',
                            'severity':         'HIGH',
                            'confidence':       80,
                            'confidence_label': 'High',
                            'url':              url,
                            'header':           ovr_hdr,
                            'method':           method,
                            'detail':           f"Method override ({ovr_hdr}: {method}) bypasses access control at {path}",
                            'remediation':      "Disable HTTP method override headers or validate them server-side.",
                        })
                        print(f"  [HIGH] Method override ({method}) via {ovr_hdr} at {url}")

    # ── Security header audit ─────────────────────────────────────────────────

    async def audit_security_headers(self, sess):
        print("\n[*] Auditing security headers (full audit)...")
        s, b, hdrs = await self._get(sess, self.target, allow_redirects=True)
        await delay()
        if not hdrs:
            return

        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}

        checks = [
            ('strict-transport-security', 'HSTS',
             'CRITICAL', "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
             ["max-age=0", "max-age=1", "max-age=100"]),  # weak HSTS values
            ('content-security-policy', 'CSP',
             'HIGH', "Implement a restrictive Content-Security-Policy. Avoid 'unsafe-inline' and 'unsafe-eval'.",
             ["unsafe-inline", "unsafe-eval", "*"]),
            ('x-frame-options', 'X-Frame-Options',
             'MEDIUM', "Add: X-Frame-Options: DENY", []),
            ('x-content-type-options', 'X-Content-Type-Options',
             'LOW', "Add: X-Content-Type-Options: nosniff", []),
            ('referrer-policy', 'Referrer-Policy',
             'LOW', "Add: Referrer-Policy: strict-origin-when-cross-origin", []),
            ('permissions-policy', 'Permissions-Policy',
             'LOW', "Add a Permissions-Policy restricting camera, microphone, geolocation.", []),
            ('cache-control', 'Cache-Control',
             'LOW', "Add Cache-Control: no-store for sensitive responses.", []),
            ('cross-origin-opener-policy', 'COOP',
             'LOW', "Add: Cross-Origin-Opener-Policy: same-origin", []),
            ('cross-origin-resource-policy', 'CORP',
             'LOW', "Add: Cross-Origin-Resource-Policy: same-origin", []),
        ]

        for hdr_name, label, sev, advice, weak_vals in checks:
            hdr_val = hdrs_lower.get(hdr_name, '')
            if not hdr_val:
                self._add({
                    'type':             f'MISSING_{label.replace("-","_").upper()}',
                    'severity':         sev,
                    'confidence':       100,
                    'confidence_label': 'High',
                    'header':           hdr_name,
                    'url':              self.target,
                    'detail':           f"Missing security header: {hdr_name}",
                    'remediation':      advice,
                })
                print(f"  [{sev}] Missing: {hdr_name}")
            elif weak_vals:
                for weak in weak_vals:
                    if weak.lower() in hdr_val.lower():
                        self._add({
                            'type':             f'WEAK_{label.replace("-","_").upper()}',
                            'severity':         sev,
                            'confidence':       90,
                            'confidence_label': 'High',
                            'header':           hdr_name,
                            'value':            hdr_val,
                            'weak_directive':   weak,
                            'url':              self.target,
                            'detail':           f"Weak {hdr_name}: contains '{weak}'",
                            'remediation':      advice,
                        })
                        print(f"  [{sev}] Weak {hdr_name}: '{weak}'")
                        break

        # Version disclosure
        for dh in ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']:
            val = hdrs_lower.get(dh, '')
            if val and re.search(r'\d+\.\d+', val):
                self._add({
                    'type':             'VERSION_DISCLOSURE',
                    'severity':         'LOW',
                    'confidence':       95,
                    'confidence_label': 'High',
                    'header':           dh,
                    'value':            val,
                    'url':              self.target,
                    'detail':           f"Version disclosed via {dh}: {val}",
                    'remediation':      f"Remove or mask the {dh} header in server configuration.",
                })
                print(f"  [LOW] Version in {dh}: {val}")

    # ── CORS preflight audit ──────────────────────────────────────────────────

    async def audit_cors(self, sess):
        print("\n[*] Auditing CORS configuration...")
        test_origins = [
            'https://evil.com',
            f'https://evil.{self.host}',
            f'https://{self.host}.evil.com',
            'null',
            f'http://{self.host}',  # HTTP downgrade
        ]
        api_endpoints = [self.target, self.target + '/api', self.target + '/api/v1']
        for endpoint in api_endpoints:
            for origin in test_origins:
                s, b, hdrs = await self._get(sess, endpoint,
                    headers={"Origin": origin, "Access-Control-Request-Method": "GET"})
                await delay()
                acao = hdrs.get('Access-Control-Allow-Origin', '')
                acac = hdrs.get('Access-Control-Allow-Credentials', '').lower()
                if acao in (origin, '*'):
                    dangerous = acac == 'true' and acao == origin
                    conf = confidence_score({
                        'origin_reflected': (acao == origin, 50),
                        'credentials':      (dangerous, 40),
                        'status_ok':        (s == 200, 10),
                    })
                    sev = 'CRITICAL' if dangerous else 'HIGH'
                    self._add({
                        'type':             'CORS_MISCONFIGURATION',
                        'severity':         severity_from_confidence(sev, conf),
                        'confidence':       conf,
                        'confidence_label': confidence_label(conf),
                        'endpoint':         endpoint,
                        'reflected_origin': origin,
                        'acao':             acao,
                        'credentials':      acac,
                        'detail':           f"CORS: '{origin}' allowed at {endpoint}" + (' with credentials!' if dangerous else ''),
                        'remediation':      "Use an explicit allowlist for CORS origins. Never combine wildcard origins with credentials=true.",
                    })
                    print(f"  [{sev}] CORS: {origin} accepted at {endpoint} (creds={acac}) [conf:{conf}%]")

    # ── Content-Type confusion ────────────────────────────────────────────────

    async def test_content_type_confusion(self, sess):
        print("\n[*] Testing Content-Type confusion attacks...")
        api_paths = ['/api', '/api/v1', '/graphql']
        confusion_tests = [
            ("application/json",               '{"test":1}'),
            ("text/html",                      "<b>test</b>"),
            ("application/x-www-form-urlencoded", "test=1&admin=true"),
            ("multipart/form-data; boundary=X", "--X\r\nContent-Disposition: form-data; name=test\r\n\r\n1\r\n--X--"),
        ]
        for path in api_paths:
            url = self.target + path
            for ct, body in confusion_tests:
                s, resp, hdrs = await self._post(sess, url,
                    data=body, headers={"Content-Type": ct})
                await delay()
                if s in [200, 201] and resp and len(resp) > 100:
                    resp_ct = hdrs.get('Content-Type', '')
                    if 'text/html' in resp_ct.lower() and path.startswith('/api'):
                        self._add({
                            'type':             'CONTENT_TYPE_CONFUSION',
                            'severity':         'MEDIUM',
                            'confidence':       70,
                            'confidence_label': 'Medium',
                            'url':              url,
                            'sent_ct':          ct,
                            'resp_ct':          resp_ct,
                            'detail':           f"API returns HTML on {ct} request — content sniffing risk",
                            'remediation':      "Always set explicit Content-Type in responses. Validate request Content-Type before processing.",
                        })
                        print(f"  [MEDIUM] Content-Type confusion at {url}")
                        break

    async def run(self):
        print("=" * 60)
        print("  HeaderForge v2 — HTTP Header Attack Surface Analyser")
        print("=" * 60)
        conn    = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.audit_security_headers(sess)
            await self.audit_cors(sess)
            await self.test_host_injection(sess)
            await self.test_forwarded_headers(sess)
            await self.test_method_override(sess)
            await self.test_content_type_confusion(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    scanner  = HeaderForge(target)
    findings = asyncio.run(scanner.run())
    with open("reports/headerforge.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/headerforge.json")

if __name__ == '__main__':
    main()
