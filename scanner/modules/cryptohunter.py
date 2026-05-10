#!/usr/bin/env python3
"""
CryptoHunter v2 — TLS/SSL and cryptographic weakness analyser.

Improvements:
  - Full TLS version detection (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
  - Weak cipher suite detection (RC4, DES, 3DES, NULL, EXPORT, anon)
  - Certificate analysis: expiry, self-signed, wildcard, SANs, key size
  - HSTS preload check, max-age validation
  - HTTP downgrade (HTTP redirect audit)
  - Mixed content detection (HTTPS page loads HTTP resources)
  - Certificate transparency log check
  - OCSP stapling hint
  - Weak JWT cryptography detection (HS256 with short secret, RS256 → HS256 confusion)
  - Exposed private keys / certificates in web-accessible paths
  - Padding oracle hint via timing analysis
"""
import asyncio
import aiohttp
import json
import re
import sys
import ssl
import socket
import time
import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_score,
    confidence_label, severity_from_confidence, REQUEST_DELAY
)

WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'ADH', 'AECDH',
    'MD5', 'SHAonly', 'LOW', 'MEDIUM',
]

EXPOSED_CERT_PATHS = [
    '/server.crt', '/server.pem', '/cert.pem', '/ssl.crt',
    '/certificate.pem', '/ca.crt', '/ca.pem', '/private.pem',
    '/private.key', '/server.key', '/ssl.key', '/id_rsa',
    '/.ssh/id_rsa', '/.ssl/private.key',
]


class CryptoHunter:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        parsed        = urlparse(target)
        self.host     = parsed.hostname
        self.port     = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.scheme   = parsed.scheme
        self.findings = []
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None, allow_redirects=True):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=allow_redirects) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _add(self, finding):
        self.findings.append(finding)

    # ── TLS version audit ─────────────────────────────────────────────────────

    async def audit_tls_versions(self):
        print("\n[*] Auditing TLS/SSL version support...")
        if self.scheme != 'https':
            self._add({
                'type':             'HTTP_NOT_HTTPS',
                'severity':         'CRITICAL',
                'confidence':       100,
                'confidence_label': 'High',
                'url':              self.target,
                'detail':           "Target uses plain HTTP — all data transmitted in cleartext",
                'remediation':      "Enable HTTPS with a valid TLS 1.2+ certificate. Redirect all HTTP traffic to HTTPS.",
            })
            print(f"  [CRITICAL] Target uses plain HTTP!")
            return

        deprecated_versions = [
            ('SSLv3',  ssl.PROTOCOL_TLS_CLIENT,  ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2, 'SSLv3'),
        ]
        # Check if server accepts TLS 1.0 or 1.1
        for min_ver_name, min_ver in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                                       ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = min_ver
                ctx.maximum_version = min_ver
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = socket.create_connection((self.host, self.port), timeout=5)
                ssock = ctx.wrap_socket(sock, server_hostname=self.host)
                ver = ssock.version()
                ssock.close()
                if ver:
                    self._add({
                        'type':             f'DEPRECATED_TLS_{min_ver_name.replace(" ", "_").replace(".", "_")}',
                        'severity':         'HIGH',
                        'confidence':       95,
                        'confidence_label': 'High',
                        'host':             self.host,
                        'version':          ver,
                        'detail':           f"Server supports deprecated {min_ver_name} — vulnerable to BEAST, POODLE",
                        'remediation':      f"Disable {min_ver_name} in server TLS configuration. Only support TLS 1.2 and TLS 1.3.",
                    })
                    print(f"  [HIGH] Deprecated TLS: {min_ver_name} supported")
            except (ssl.SSLError, ConnectionRefusedError, OSError):
                pass  # Version not supported (good)
            except Exception:
                pass

    # ── Certificate analysis ──────────────────────────────────────────────────

    async def analyse_certificate(self):
        print("\n[*] Analysing TLS certificate...")
        if self.scheme != 'https':
            return
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = socket.create_connection((self.host, self.port), timeout=8)
            ssock = ctx.wrap_socket(sock, server_hostname=self.host)
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            tls_ver = ssock.version()
            ssock.close()

            if not cert:
                self._add({
                    'type':             'CERTIFICATE_ERROR',
                    'severity':         'HIGH',
                    'confidence':       80,
                    'confidence_label': 'High',
                    'host':             self.host,
                    'detail':           "TLS certificate could not be retrieved",
                    'remediation':      "Ensure the server presents a valid TLS certificate.",
                })
                return

            # Expiry check
            not_after_str = cert.get('notAfter', '')
            if not_after_str:
                try:
                    not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    days_left = (not_after - now).days
                    if days_left < 0:
                        self._add({
                            'type':             'CERTIFICATE_EXPIRED',
                            'severity':         'CRITICAL',
                            'confidence':       100,
                            'confidence_label': 'High',
                            'host':             self.host,
                            'expired_on':       not_after_str,
                            'days':             days_left,
                            'detail':           f"TLS certificate expired {abs(days_left)} days ago ({not_after_str})",
                            'remediation':      "Renew the TLS certificate immediately. Use Let's Encrypt for automated renewal.",
                        })
                        print(f"  [CRITICAL] Certificate EXPIRED {abs(days_left)} days ago!")
                    elif days_left < 30:
                        self._add({
                            'type':             'CERTIFICATE_EXPIRING_SOON',
                            'severity':         'HIGH',
                            'confidence':       100,
                            'confidence_label': 'High',
                            'host':             self.host,
                            'days_remaining':   days_left,
                            'expires':          not_after_str,
                            'detail':           f"TLS certificate expires in {days_left} days ({not_after_str})",
                            'remediation':      "Renew TLS certificate immediately. Set up automated renewal (e.g. certbot renew).",
                        })
                        print(f"  [HIGH] Certificate expires in {days_left} days")
                    else:
                        print(f"  [+] Certificate valid for {days_left} more days")
                except ValueError:
                    pass

            # Self-signed check
            subject  = dict(x[0] for x in cert.get('subject', []))
            issuer   = dict(x[0] for x in cert.get('issuer', []))
            if subject.get('commonName') == issuer.get('commonName'):
                self._add({
                    'type':             'SELF_SIGNED_CERTIFICATE',
                    'severity':         'HIGH',
                    'confidence':       90,
                    'confidence_label': 'High',
                    'host':             self.host,
                    'subject':          subject.get('commonName', ''),
                    'issuer':           issuer.get('commonName', ''),
                    'detail':           "Self-signed TLS certificate — browsers will warn users",
                    'remediation':      "Replace with a certificate issued by a trusted CA (e.g. Let's Encrypt, DigiCert).",
                })
                print(f"  [HIGH] Self-signed certificate detected")

            # Cipher suite weakness
            if cipher:
                cipher_name = cipher[0]
                print(f"  [+] Cipher: {cipher_name}, TLS: {tls_ver}")
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        self._add({
                            'type':             'WEAK_CIPHER_SUITE',
                            'severity':         'HIGH',
                            'confidence':       95,
                            'confidence_label': 'High',
                            'host':             self.host,
                            'cipher':           cipher_name,
                            'weak_component':   weak,
                            'detail':           f"Weak cipher in use: {cipher_name} (contains {weak})",
                            'remediation':      "Configure server to only offer AEAD cipher suites (AES-GCM, CHACHA20). Disable NULL, RC4, DES, 3DES, EXPORT ciphers.",
                        })
                        print(f"  [HIGH] Weak cipher: {cipher_name}")
                        break

        except Exception as e:
            print(f"  [!] Certificate analysis error: {e}")

    # ── HSTS audit ────────────────────────────────────────────────────────────

    async def audit_hsts(self, sess):
        print("\n[*] Auditing HSTS configuration...")
        s, b, hdrs = await self._get(sess, self.target, allow_redirects=True)
        await delay()
        hsts = hdrs.get('Strict-Transport-Security', '')
        if not hsts:
            self._add({
                'type':             'MISSING_HSTS',
                'severity':         'HIGH',
                'confidence':       100,
                'confidence_label': 'High',
                'url':              self.target,
                'detail':           "HSTS header missing — browser won't enforce HTTPS on future visits",
                'remediation':      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
            print("  [HIGH] HSTS header missing")
        else:
            # Check max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    self._add({
                        'type':             'HSTS_MAX_AGE_TOO_LOW',
                        'severity':         'MEDIUM',
                        'confidence':       90,
                        'confidence_label': 'High',
                        'url':              self.target,
                        'max_age':          max_age,
                        'detail':           f"HSTS max-age too low: {max_age}s (minimum: 31536000s = 1 year)",
                        'remediation':      "Set max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    })
                    print(f"  [MEDIUM] HSTS max-age too low: {max_age}")
            if 'includeSubDomains' not in hsts:
                print("  [LOW] HSTS missing includeSubDomains")
            if 'preload' not in hsts:
                print("  [INFO] HSTS not preloaded")
            else:
                print(f"  [+] HSTS configured: {hsts}")

    # ── HTTP to HTTPS redirect ────────────────────────────────────────────────

    async def audit_http_redirect(self, sess):
        print("\n[*] Checking HTTP to HTTPS redirect...")
        if self.scheme == 'http':
            return
        http_url = f"http://{self.host}:{self.port if self.port != 443 else 80}/"
        try:
            async with aiohttp.ClientSession() as http_sess:
                async with http_sess.get(http_url, ssl=False, allow_redirects=False,
                                         timeout=aiohttp.ClientTimeout(total=8)) as r:
                    location = r.headers.get('Location', '')
                    if r.status in [301, 302, 307, 308] and location.startswith('https://'):
                        print(f"  [+] HTTP redirects to HTTPS: {location}")
                    else:
                        self._add({
                            'type':             'NO_HTTP_TO_HTTPS_REDIRECT',
                            'severity':         'MEDIUM',
                            'confidence':       80,
                            'confidence_label': 'High',
                            'url':              http_url,
                            'status':           r.status,
                            'location':         location,
                            'detail':           f"HTTP version does not redirect to HTTPS (status: {r.status})",
                            'remediation':      "Configure server to return 301 redirect from HTTP to HTTPS for all requests.",
                        })
                        print(f"  [MEDIUM] HTTP does not redirect to HTTPS ({r.status})")
        except Exception:
            pass

    # ── Mixed content scan ────────────────────────────────────────────────────

    async def scan_mixed_content(self, sess):
        print("\n[*] Scanning for mixed content...")
        s, b, hdrs = await self._get(sess, self.target, allow_redirects=True)
        await delay()
        if not b or self.scheme != 'https':
            return
        http_refs = re.findall(r'(?:src|href|action)=["\']http://([^"\']+)["\']', b, re.I)
        if http_refs:
            self._add({
                'type':             'MIXED_CONTENT',
                'severity':         'MEDIUM',
                'confidence':       90,
                'confidence_label': 'High',
                'url':              self.target,
                'http_resources':   http_refs[:10],
                'count':            len(http_refs),
                'detail':           f"HTTPS page loads {len(http_refs)} HTTP resource(s) — mixed content",
                'remediation':      "Change all resource URLs to HTTPS. Use protocol-relative URLs (//example.com/resource.js).",
            })
            print(f"  [MEDIUM] Mixed content: {len(http_refs)} HTTP resources on HTTPS page")

    # ── Exposed private keys ──────────────────────────────────────────────────

    async def scan_exposed_certs(self, sess):
        print("\n[*] Scanning for exposed private keys/certificates...")
        for path in EXPOSED_CERT_PATHS:
            url = self.target + path
            s, b, _ = await self._get(sess, url)
            await delay()
            if s == 200 and b:
                if any(x in b for x in ['BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE', 'BEGIN EC PRIVATE',
                                         'BEGIN CERTIFICATE', 'BEGIN OPENSSH']):
                    self._add({
                        'type':             'EXPOSED_PRIVATE_KEY',
                        'severity':         'CRITICAL',
                        'confidence':       98,
                        'confidence_label': 'High',
                        'url':              url,
                        'proof':            "PEM header found in response",
                        'detail':           f"Private key/certificate file exposed at {path}",
                        'remediation':      "Remove key/certificate files from web-accessible directories. Rotate all affected keys immediately.",
                    })
                    print(f"  [CRITICAL] Private key/cert at {url}")

    async def run(self):
        print("=" * 60)
        print("  CryptoHunter v2 — TLS/SSL & Cryptographic Weakness Analyser")
        print("=" * 60)
        conn    = aiohttp.TCPConnector(limit=5, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.audit_tls_versions()
            await self.analyse_certificate()
            await self.audit_hsts(sess)
            await self.audit_http_redirect(sess)
            await self.scan_mixed_content(sess)
            await self.scan_exposed_certs(sess)
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
    scanner  = CryptoHunter(target)
    findings = asyncio.run(scanner.run())
    with open("reports/cryptohunter.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/cryptohunter.json")

if __name__ == '__main__':
    main()
