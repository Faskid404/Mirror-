#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import re
from pathlib import Path
from smart_filter import confidence_score, confidence_label, severity_from_confidence

SECURITY_HEADERS = [
    ('Content-Security-Policy',          'HIGH',   'Prevents XSS and data injection attacks'),
    ('Strict-Transport-Security',        'HIGH',   'Enforces HTTPS; prevents SSL stripping'),
    ('X-Frame-Options',                  'MEDIUM', 'Prevents clickjacking (legacy; prefer frame-ancestors CSP)'),
    ('X-Content-Type-Options',           'MEDIUM', 'Prevents MIME-type sniffing'),
    ('Referrer-Policy',                  'LOW',    'Controls referrer info leakage'),
    ('Permissions-Policy',               'LOW',    'Restricts browser feature access'),
    ('Cross-Origin-Opener-Policy',       'MEDIUM', 'Prevents cross-origin window attacks (Spectre)'),
    ('Cross-Origin-Embedder-Policy',     'MEDIUM', 'Required for SharedArrayBuffer; isolates origin'),
    ('Cross-Origin-Resource-Policy',     'MEDIUM', 'Prevents cross-origin resource reads'),
    ('Cache-Control',                    'MEDIUM', 'Prevents sensitive data caching'),
]

CSP_WEAK_DIRECTIVES = ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes']
CSP_WEAK_SOURCES = ['*', 'http:']

SENSITIVE_BODY_PATTERNS = [
    (r'root:x:0:0',                            'CRITICAL', '/etc/passwd content'),
    (r'uid=\d+\(root\)',                        'CRITICAL', 'root uid in command output'),
    (r'AKIA[0-9A-Z]{16}',                      'CRITICAL', 'AWS access key'),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'CRITICAL', 'private key material'),
    (r'"password"\s*:\s*"[^"]{6,}"',           'HIGH',     'password field in JSON response'),
    (r'"secret"\s*:\s*"[^"]{8,}"',             'HIGH',     'secret field in JSON response'),
    (r'"access_token"\s*:\s*"[^"]{20,}"',      'HIGH',     'access token in response'),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}',        'HIGH',     'Slack token'),
    (r'gh[pousr]_[A-Za-z0-9]{36,}',           'HIGH',     'GitHub token'),
    (r'"client_secret"\s*:\s*"[^"]{16,}"',     'HIGH',     'OAuth client secret'),
    (r'"api_key"\s*:\s*"[^"]{16,}"',           'HIGH',     'API key in response'),
    (r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"',      'HIGH',     'Social Security Number'),
]

SCAN_PATHS = [
    '/', '/login', '/signin', '/api', '/api/health',
    '/admin', '/dashboard', '/account', '/profile',
]

CACHE_SENSITIVE_PATHS = ['/api/profile', '/api/me', '/api/users', '/dashboard', '/account']


class HeaderForge:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []

    async def fetch(self, sess, url):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with sess.get(url, ssl=False, timeout=timeout, allow_redirects=True) as r:
                cookies = r.headers.getall('Set-Cookie', [])
                return dict(r.headers), r.status, await r.text(errors='ignore'), cookies
        except Exception as e:
            return None, str(e), None, []

    def audit_csp(self, csp, url=''):
        issues = []

        for directive in CSP_WEAK_DIRECTIVES:
            if directive in csp:
                issues.append({'issue': f'weak-directive:{directive}', 'severity': 'HIGH',
                                'detail': f"CSP contains '{directive}' — allows inline script/style execution"})

        for src in CSP_WEAK_SOURCES:
            pattern = rf'(?:default-src|script-src|style-src)[^;]*{re.escape(src)}'
            if re.search(pattern, csp):
                issues.append({'issue': f'weak-src:{src}', 'severity': 'HIGH',
                                'detail': f"CSP allows '{src}' in script/style — XSS possible"})

        if re.search(r'script-src[^;]*\*', csp):
            issues.append({'issue': 'wildcard-script-src', 'severity': 'HIGH',
                            'detail': "script-src contains wildcard '*' — any origin can load scripts"})

        if 'object-src' not in csp and "object-src 'none'" not in csp:
            issues.append({'issue': 'missing:object-src', 'severity': 'MEDIUM',
                            'detail': 'No object-src directive — Flash/plugin injection possible'})

        if 'base-uri' not in csp:
            issues.append({'issue': 'missing:base-uri', 'severity': 'MEDIUM',
                            'detail': 'No base-uri directive — base tag injection possible'})

        if 'frame-ancestors' not in csp:
            issues.append({'issue': 'missing:frame-ancestors', 'severity': 'MEDIUM',
                            'detail': 'No frame-ancestors — clickjacking possible via iframes'})

        if 'upgrade-insecure-requests' not in csp and 'block-all-mixed-content' not in csp:
            issues.append({'issue': 'missing:upgrade-insecure-requests', 'severity': 'LOW',
                            'detail': 'CSP does not enforce HTTPS upgrades for mixed content'})

        # Nonce / hash mode is good — detect and acknowledge
        if re.search(r"'nonce-[A-Za-z0-9+/=]+'", csp):
            print(f"    [CSP] Nonce-based CSP detected (good practice)")

        return issues

    def audit_cors(self, headers, url=''):
        issues = []
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '').lower()

        if acao == '*':
            issues.append({'issue': 'cors:wildcard-acao', 'severity': 'HIGH',
                            'proof': 'Access-Control-Allow-Origin: *',
                            'detail': 'Wildcard CORS — any origin can read responses'})

        if acao not in ('', '*') and acac == 'true':
            issues.append({'issue': 'cors:acao-with-credentials', 'severity': 'HIGH',
                            'proof': f'ACAO: {acao} + ACAC: true',
                            'detail': 'Specific ACAO with credentials=true — verify origin is not attacker-controlled'})

        acam = headers.get('Access-Control-Allow-Methods', '')
        if acam and any(m in acam.upper() for m in ['DELETE', 'PUT', 'PATCH']):
            issues.append({'issue': 'cors:dangerous-methods-allowed', 'severity': 'MEDIUM',
                            'proof': f'Access-Control-Allow-Methods: {acam}',
                            'detail': 'CORS allows destructive methods — verify origin restrictions'})

        return issues

    def audit_cookies(self, cookies):
        issues = []
        for cookie in cookies:
            name_match = re.match(r'^([^=]+)=', cookie)
            name = name_match.group(1).strip() if name_match else 'unknown'

            is_session = any(k in name.lower() for k in ['session', 'auth', 'token', 'sid', 'jwt', 'access'])
            sev = 'HIGH' if is_session else 'MEDIUM'

            if 'Secure' not in cookie:
                issues.append({'issue': f'cookie:{name}:no-secure', 'severity': sev, 'cookie': name,
                                'detail': f'Cookie "{name}" missing Secure flag — transmitted over HTTP'})

            if 'HttpOnly' not in cookie:
                issues.append({'issue': f'cookie:{name}:no-httponly', 'severity': sev, 'cookie': name,
                                'detail': f'Cookie "{name}" missing HttpOnly — readable via JavaScript (XSS risk)'})

            if 'SameSite' not in cookie:
                issues.append({'issue': f'cookie:{name}:no-samesite', 'severity': 'MEDIUM', 'cookie': name,
                                'detail': f'Cookie "{name}" missing SameSite — CSRF risk'})
            elif 'SameSite=None' in cookie and 'Secure' not in cookie:
                issues.append({'issue': f'cookie:{name}:samesite-none-no-secure', 'severity': 'HIGH', 'cookie': name,
                                'detail': f'Cookie "{name}" has SameSite=None without Secure — rejected by modern browsers'})

            if re.search(r'Expires=.{1,50}198[0-9]|Expires=.{1,50}197[0-9]', cookie, re.I):
                issues.append({'issue': f'cookie:{name}:expired', 'severity': 'LOW', 'cookie': name,
                                'detail': f'Cookie "{name}" already expired — may be stale session cleanup artifact'})

        return issues

    def check_disclosure(self, headers, body):
        found = []

        disclosure_headers = {
            'Server': 'Web server version disclosed',
            'X-Powered-By': 'Backend technology/version disclosed',
            'X-AspNet-Version': 'ASP.NET version disclosed',
            'X-AspNetMvc-Version': 'ASP.NET MVC version disclosed',
            'X-Generator': 'CMS/framework disclosed',
            'X-Drupal-Cache': 'Drupal version fingerprint',
            'X-Joomla-Token': 'Joomla installation detected',
            'X-CF-Powered-By': 'ColdFusion disclosed',
            'X-Turbo-Charged-By': 'LiteSpeed/hosting stack disclosed',
        }
        for h, desc in disclosure_headers.items():
            if h in headers:
                found.append({
                    'type': 'info_disclosure', 'header': h,
                    'value': headers[h], 'severity': 'LOW',
                    'confidence': 95, 'confidence_label': 'High',
                    'detail': desc,
                })
                print(f"  [LEAK] {h}: {headers[h][:60]} — {desc}")

        if body:
            for pattern, sev, desc in SENSITIVE_BODY_PATTERNS:
                if re.search(pattern, body[:8000], re.I):
                    found.append({
                        'type': 'body_disclosure', 'severity': sev,
                        'confidence': 90, 'confidence_label': 'High',
                        'proof': desc, 'detail': f'Sensitive data in response body: {desc}',
                    })
                    print(f"  [LEAK] Body disclosure: {desc}")

            # Internal IP addresses
            ips = list(set(re.findall(
                r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                r'|192\.168\.\d{1,3}\.\d{1,3}'
                r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
                r'|169\.254\.\d{1,3}\.\d{1,3})\b', body
            )))
            if ips:
                found.append({
                    'type': 'internal_ip_disclosure', 'ips': ips[:10],
                    'severity': 'MEDIUM', 'confidence': 80, 'confidence_label': 'High',
                    'proof': f'Internal IPs in response: {ips[:5]}',
                    'detail': 'Internal IP addresses leaked — reveals network topology',
                })
                print(f"  [LEAK] Internal IPs: {ips[:5]}")

            # Stack trace / exception details
            if re.search(r'(Traceback \(most recent call|at [A-Za-z]+\.[A-Za-z]+\(|NullPointerException|SQLException|ORA-\d{5})', body):
                found.append({
                    'type': 'stack_trace_disclosure', 'severity': 'HIGH',
                    'confidence': 90, 'confidence_label': 'High',
                    'proof': 'Stack trace or exception message in response body',
                    'detail': 'Stack trace leaked — reveals code paths and possible injection points',
                })
                print(f"  [LEAK] Stack trace in response body")

        return found

    async def audit_cache(self, sess, path):
        url = self.target + path
        headers, status, body, _ = await self.fetch(sess, url)
        if not headers:
            return

        cc = headers.get('Cache-Control', '')
        pragma = headers.get('Pragma', '')

        insecure = (
            'no-store' not in cc and
            'private' not in cc and
            status == 200 and
            body and len(body) > 50
        )
        if insecure:
            self.findings.append({
                'type': 'insecure_cache_control',
                'severity': 'MEDIUM',
                'confidence': 75,
                'confidence_label': 'Medium',
                'url': url,
                'cache_control': cc or '(not set)',
                'proof': f'Sensitive path {path} missing Cache-Control: no-store/private',
                'detail': 'Response may be cached by proxies/browsers — sensitive data at risk',
                'remediation': 'Add Cache-Control: no-store, no-cache, private for authenticated endpoints',
            })
            print(f"  [CACHE] Insecure caching on sensitive path: {path}")

    async def run(self):
        print("=" * 60)
        print("  HeaderForge — Security Header & Disclosure Auditor")
        print("=" * 60)

        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(
            connector=conn,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            print(f"[*] Primary audit: {self.target}")
            headers, status, body, cookies = await self.fetch(sess, self.target)

            if headers is None:
                print(f"[X] Unreachable: {status}")
                return []

            print(f"[+] Status: {status}")
            print(f"[+] Server: {headers.get('Server', '(not disclosed)')}\n")

            # Security headers audit
            for header_name, default_sev, description in SECURITY_HEADERS:
                if header_name not in headers:
                    print(f"  [MISSING] {header_name} — {description}")
                    self.findings.append({
                        'type': 'missing_header',
                        'header': header_name,
                        'severity': default_sev,
                        'confidence': 95,
                        'confidence_label': 'High',
                        'detail': description,
                        'remediation': f'Add {header_name} response header',
                    })
                else:
                    val = headers[header_name]
                    print(f"  [OK] {header_name}: {val[:80]}")

                    if header_name == 'Content-Security-Policy':
                        for item in self.audit_csp(val):
                            print(f"    [CSP] {item['issue']}: {item['detail']}")
                            self.findings.append({
                                'type': 'csp_weakness', 'issue': item['issue'],
                                'severity': item['severity'], 'confidence': 90,
                                'confidence_label': 'High', 'detail': item['detail'],
                                'remediation': 'Harden CSP policy — see https://csp.withgoogle.com',
                            })

                    if header_name == 'Strict-Transport-Security':
                        m = re.search(r'max-age=(\d+)', val)
                        if m and int(m.group(1)) < 15768000:
                            print(f"    [HSTS] max-age={m.group(1)}s < 6 months")
                            self.findings.append({
                                'type': 'hsts_short_maxage', 'value': val,
                                'max_age': int(m.group(1)),
                                'severity': 'MEDIUM', 'confidence': 90, 'confidence_label': 'High',
                                'remediation': 'Set max-age to at least 31536000 (1 year)',
                            })
                        if 'includeSubDomains' not in val:
                            self.findings.append({
                                'type': 'hsts_no_subdomains', 'severity': 'LOW',
                                'confidence': 90, 'confidence_label': 'High',
                                'detail': 'HSTS does not cover subdomains',
                            })

                    if header_name == 'X-Frame-Options':
                        if val.upper() not in ('DENY', 'SAMEORIGIN'):
                            self.findings.append({
                                'type': 'x_frame_options_weak', 'value': val,
                                'severity': 'MEDIUM', 'confidence': 85, 'confidence_label': 'High',
                                'detail': f'X-Frame-Options: {val} is non-standard',
                            })

                    if header_name == 'Cache-Control':
                        if 'no-store' not in val and 'private' not in val:
                            self.findings.append({
                                'type': 'permissive_cache_control', 'value': val,
                                'severity': 'LOW', 'confidence': 70, 'confidence_label': 'Medium',
                                'detail': 'Root page may be cached by shared proxies',
                            })

            # Cookie audit (per-cookie, not per-header)
            if cookies:
                print(f"\n[*] Auditing {len(cookies)} Set-Cookie header(s)")
                for issue in self.audit_cookies(cookies):
                    print(f"  [COOKIE] {issue['issue']}: {issue['detail']}")
                    self.findings.append({
                        'type': 'cookie_issue', **issue,
                        'confidence': 90, 'confidence_label': 'High',
                    })

            # CORS audit
            cors_issues = self.audit_cors(headers)
            for issue in cors_issues:
                print(f"  [CORS] {issue['issue']}: {issue['detail']}")
                self.findings.append({
                    'type': 'cors_issue', **issue,
                    'confidence': 90, 'confidence_label': 'High',
                })

            # Information disclosure
            disclosures = self.check_disclosure(headers, body)
            self.findings.extend(disclosures)

            # Cache audit on sensitive paths
            print(f"\n[*] Cache control audit on sensitive paths")
            for path in CACHE_SENSITIVE_PATHS:
                await self.audit_cache(sess, path)

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    print("=" * 60)
    print("  HeaderForge — Security Header Audit")
    print("=" * 60)
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(HeaderForge(target).run())
    with open("reports/headerforge.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/headerforge.json")
    by_sev = {}
    for item in findings:
        s = item.get('severity', 'INFO')
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev in by_sev:
            print(f"   {sev:10s}: {by_sev[sev]}")


if __name__ == '__main__':
    main()
