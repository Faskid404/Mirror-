#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import re
import time
import sys
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_likely_real_vuln, is_reflected,
    confidence_score, confidence_label, severity_from_confidence,
    REQUEST_DELAY
)

class WebProbe:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.host = urlparse(target).hostname
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None, allow_redirects=False):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with sess.get(
                url, headers=headers or {}, ssl=False,
                timeout=timeout, allow_redirects=allow_redirects
            ) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, headers=None):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with sess.post(
                url, json=data or {}, headers=headers or {},
                ssl=False, timeout=timeout
            ) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def scan_modern_frameworks(self, sess):
        print("\n[*] Detecting modern framework vulnerabilities...")

        framework_paths = {
            'Spring': [
                '/actuator/env', '/actuator/heapdump', '/actuator/threaddump',
                '/actuator/mappings', '/h2-console',
            ],
            'Django': ['/admin/login/', '/__debug__/', '/silk/'],
            'Laravel': ['/telescope', '/_ignition/health-check'],
            'Next.js': ['/_next/data', '/api/auth/session'],
            'Express': ['/graphql', '/metrics'],
        }

        for framework, paths in framework_paths.items():
            for path in paths:
                url = self.target + path
                status, body, hdrs = await self._get(sess, url)
                await asyncio.sleep(REQUEST_DELAY)

                if not is_likely_real_vuln(body or "", status or 0, self.baseline_404):
                    continue

                is_critical_path = any(x in path for x in [
                    'heapdump', 'threaddump', 'env', 'actuator',
                    'telescope', 'ignition', 'h2-console', '__debug__'
                ])
                conf = confidence_score({
                    'status_200': (status == 200, 40),
                    'body_size': (len(body or '') > 500, 30),
                    'critical_path': (is_critical_path, 20),
                    'not_404_like': (is_likely_real_vuln(body or "", status or 0, self.baseline_404), 10),
                })
                base_sev = 'CRITICAL' if is_critical_path else 'HIGH'
                sev = severity_from_confidence(base_sev, conf)

                self.findings.append({
                    'type': 'FRAMEWORK_ENDPOINT',
                    'severity': sev,
                    'confidence': conf,
                    'confidence_label': confidence_label(conf),
                    'framework': framework,
                    'url': url,
                    'status': status,
                    'detail': f'{framework} sensitive endpoint exposed: {path}'
                })
                print(f"  [{sev}] {framework}: {url} ({status}) [confidence: {confidence_label(conf)}]")
                self.scan_body_secrets(body, url)

    def scan_body_secrets(self, body, url):
        if not body:
            return
        patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY'),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT_TOKEN'),
            (r'-----BEGIN.*PRIVATE KEY-----', 'PRIVATE_KEY'),
            (r'"password"\s*:\s*"([^"]{8,})"', 'PASSWORD'),
            (r'"secret"\s*:\s*"([^"]{10,})"', 'SECRET'),
            (r'"api[_-]?key"\s*:\s*"([^"]{16,})"', 'API_KEY'),
            (r'mongodb(?:\+srv)?://[^\s"\']+', 'MONGODB_URI'),
            (r'postgres(?:ql)?://[^\s"\']+', 'POSTGRES_URI'),
            (r'mysql://[^\s"\']+', 'MYSQL_URI'),
            (r'redis://[^\s"\']+', 'REDIS_URI'),
        ]
        blacklist = {'password', 'secret', 'key', 'token', 'changeme', 'example', 'test'}
        for pattern, dtype in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                val = match if isinstance(match, str) else str(match)
                if len(val) < 8 or val.lower() in blacklist:
                    continue
                self.findings.append({
                    'type': 'SECRET_EXPOSED',
                    'severity': 'CRITICAL',
                    'confidence': 90,
                    'confidence_label': 'High',
                    'data_type': dtype,
                    'preview': val[:40] + ('...' if len(val) > 40 else ''),
                    'url': url,
                    'detail': f'{dtype} found in response'
                })
                print(f"  [CRITICAL] {dtype} at {url}: {val[:30]}...")

    async def scan_oauth_misconfig(self, sess):
        print("\n[*] Scanning OAuth/SSO misconfigurations...")
        oauth_paths = [
            '/.well-known/openid-configuration',
            '/.well-known/oauth-authorization-server',
            '/oauth/authorize', '/oauth/token',
        ]
        for path in oauth_paths:
            url = self.target + path
            status, body, hdrs = await self._get(sess, url)
            await asyncio.sleep(REQUEST_DELAY)
            if not body or status not in [200, 400, 401]:
                continue
            if not ('token' in body.lower() or 'oauth' in body.lower()):
                continue

            self.findings.append({
                'type': 'OAUTH_ENDPOINT',
                'severity': 'INFO',
                'confidence': 60,
                'confidence_label': 'Medium',
                'url': url,
                'detail': f'OAuth endpoint found: {path}'
            })
            print(f"  [OAUTH] Endpoint: {url}")

            open_redirect_payloads = [
                f"{url}?redirect_uri=https://evil.com",
                f"{url}?redirect_uri=//evil.com",
            ]
            for payload_url in open_redirect_payloads:
                s2, b2, h2 = await self._get(sess, payload_url, allow_redirects=False)
                await asyncio.sleep(REQUEST_DELAY)
                location = h2.get('Location', '')
                if 'evil.com' in location:
                    self.findings.append({
                        'type': 'OAUTH_OPEN_REDIRECT',
                        'severity': 'HIGH',
                        'confidence': 95,
                        'confidence_label': 'High',
                        'url': payload_url,
                        'location': location,
                        'detail': 'OAuth open redirect confirmed — evil.com in Location header'
                    })
                    print(f"  [HIGH] OAuth open redirect confirmed at {payload_url}")

    async def scan_web_cache_poison(self, sess):
        print("\n[*] Scanning for web cache poisoning...")
        cache_headers = [
            ('X-Forwarded-Host', 'evil-cache-test.com'),
            ('X-Host', 'evil-cache-test.com'),
            ('X-Original-URL', '/admin'),
        ]
        status_base, body_base, _ = await self._get(sess, self.target)
        if not body_base:
            return
        for header_name, header_value in cache_headers:
            status, body, _ = await self._get(
                sess, self.target, headers={header_name: header_value}
            )
            await asyncio.sleep(REQUEST_DELAY)
            if body and is_reflected(header_value, body):
                conf = confidence_score({
                    'reflected': (True, 60),
                    'status_200': (status == 200, 30),
                    'not_404': (is_likely_real_vuln(body, status or 0, self.baseline_404), 10),
                })
                self.findings.append({
                    'type': 'WEB_CACHE_POISONING',
                    'severity': severity_from_confidence('HIGH', conf),
                    'confidence': conf,
                    'confidence_label': confidence_label(conf),
                    'url': self.target,
                    'header': header_name,
                    'value': header_value,
                    'detail': f'Response reflects {header_name} — cache poison possible (payload appeared in response)'
                })
                print(f"  [HIGH] Cache poisoning confirmed via {header_name} (value reflected in body)")

    async def scan_server_side_template(self, sess):
        print("\n[*] Scanning for SSTI...")
        ssti_payloads = [
            ('{{7*7}}', '49', 'Jinja2/Twig'),
            ('${7*7}', '49', 'Freemarker/Velocity'),
            ('<%= 7*7 %>', '49', 'ERB/EJS'),
        ]
        ssti_test_endpoints = [
            self.target + '/api/render',
            self.target + '/api/template',
            self.target + '/render',
        ]
        for endpoint in ssti_test_endpoints:
            for payload, expected, engine in ssti_payloads:
                for param in ['template', 'render', 'view', 'page', 'content']:
                    url = f"{endpoint}?{param}={quote(payload)}"
                    status, body, _ = await self._get(sess, url)
                    await asyncio.sleep(REQUEST_DELAY)
                    if not body:
                        continue
                    evaluated = expected in body
                    not_reflected_raw = payload not in body
                    if evaluated and not_reflected_raw:
                        self.findings.append({
                            'type': 'SSTI_DETECTED',
                            'severity': 'CRITICAL',
                            'confidence': 95,
                            'confidence_label': 'High',
                            'url': url,
                            'engine': engine,
                            'payload': payload,
                            'proof': f'Expression evaluated: {payload} → {expected}',
                            'detail': f'SSTI confirmed with {engine}: payload evaluated to {expected}'
                        })
                        print(f"  [CRITICAL] SSTI ({engine}) confirmed at {url} — {payload}={expected}")

    async def scan_dependency_confusion(self, sess):
        print("\n[*] Scanning for exposed dependency files...")
        supply_chain_paths = [
            '/package.json', '/.npmrc', '/composer.json',
            '/requirements.txt', '/go.mod', '/Gemfile',
        ]
        for path in supply_chain_paths:
            url = self.target + path
            status, body, _ = await self._get(sess, url)
            await asyncio.sleep(REQUEST_DELAY)
            if not is_likely_real_vuln(body or "", status or 0, self.baseline_404):
                continue
            if len(body or '') < 50:
                continue
            conf = confidence_score({
                'status_200': (status == 200, 40),
                'has_content': (len(body or '') > 100, 40),
                'looks_real': (is_likely_real_vuln(body or "", status or 0, self.baseline_404), 20),
            })
            self.findings.append({
                'type': 'DEPENDENCY_FILE_EXPOSED',
                'severity': severity_from_confidence('MEDIUM', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'size': len(body or ''),
                'preview': (body or '')[:200],
                'detail': f'Dependency file exposed: {path}'
            })
            print(f"  [MEDIUM] Dependency file: {url} ({len(body or '')}b) [confidence: {confidence_label(conf)}]")

            vuln_indicators = ['lodash', 'log4j', 'struts', 'jackson', 'commons-']
            for indicator in vuln_indicators:
                if indicator in (body or '').lower():
                    self.findings.append({
                        'type': 'VULNERABLE_DEPENDENCY',
                        'severity': 'HIGH',
                        'confidence': 70,
                        'confidence_label': 'Medium',
                        'url': url,
                        'dependency': indicator,
                        'detail': f'Potentially vulnerable library detected: {indicator}'
                    })
                    print(f"  [HIGH] Vulnerable dep '{indicator}' in {url}")

    async def run(self):
        print("="*60)
        print("  WebProbe — Modern Web Vulnerability Scanner")
        print("="*60)

        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=conn, timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        ) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)

            await self.scan_modern_frameworks(sess)
            await self.scan_oauth_misconfig(sess)
            await self.scan_web_cache_poison(sess)
            await self.scan_server_side_template(sess)
            await self.scan_dependency_confusion(sess)

        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    print("="*60)
    print("  WebProbe — Modern Web Vulnerability Scanner")
    print("="*60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)

    scanner = WebProbe(target)
    findings = asyncio.run(scanner.run())

    with open("reports/webprobe.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)

    print(f"\n[+] {len(findings)} findings -> reports/webprobe.json")
    by_sev = {}
    for f in findings:
        s = f.get('severity', 'INFO')
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
        if sev in by_sev:
            print(f"    {sev:8s}: {by_sev[sev]}")

if __name__ == '__main__':
    main()
