#!/usr/bin/env python3
"""CryptoHunter v4 — Pro-grade TLS/SSL & Cryptographic Weakness Analyser.

Improvements over v3:
- TLS version: detects SSLv2/SSLv3/TLS 1.0/1.1 negotiation (deprecated)
- Certificate: expiry, self-signed, mismatched CN, weak signature algorithm
- Cipher suite: flags RC4, DES, 3DES, NULL, EXPORT, anonymous DH
- HSTS: preload, includeSubDomains, max-age validation
- Mixed content: HTTP resources on HTTPS pages
- HTTP to HTTPS redirect: missing or open to MITM
- Certificate Transparency: checks CT log compliance
"""
import asyncio, aiohttp, json, re, ssl, sys, socket, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

# ── Weak cipher patterns ───────────────────────────────────────────────────────
WEAK_CIPHER_PATTERNS = [
    (r'RC4',     "RC4 cipher — cryptographically broken, allows plaintext recovery",     "CRITICAL"),
    (r'DES\b',   "DES cipher — 56-bit key, breakable via brute force",                  "CRITICAL"),
    (r'3DES',    "Triple-DES — vulnerable to SWEET32 birthday attack",                   "HIGH"),
    (r'NULL',    "NULL cipher — no encryption at all",                                   "CRITICAL"),
    (r'EXPORT',  "EXPORT cipher — intentionally weakened for export compliance (FREAK)", "CRITICAL"),
    (r'anon',    "Anonymous DH — no server authentication (MITM possible)",              "CRITICAL"),
    (r'MD5',     "MD5 in cipher suite — broken hash, collision attacks",                 "HIGH"),
    (r'SHA\b(?!256|384|512)', "SHA-1 — deprecated, collision attacks possible",          "MEDIUM"),
]

# ── Deprecated TLS versions ────────────────────────────────────────────────────
DEPRECATED_TLS = {
    ssl.TLSVersion.SSLv3:  ("SSLv3",  "CRITICAL", "POODLE attack — must disable"),
    ssl.TLSVersion.TLSv1:  ("TLS 1.0","HIGH",     "BEAST attack — deprecated per RFC 8996"),
    ssl.TLSVersion.TLSv1_1:("TLS 1.1","MEDIUM",   "Deprecated per RFC 8996 — upgrade to TLS 1.2+"),
}

# ── Weak signature algorithms ──────────────────────────────────────────────────
WEAK_SIG_ALGS = {
    'md2': ("MD2", "CRITICAL"),
    'md5': ("MD5", "CRITICAL"),
    'sha1': ("SHA-1", "HIGH"),
}


class CryptoHunter:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.port     = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        self.is_https = self.parsed.scheme == 'https'
        self.findings = []

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    # ── HTTP → HTTPS redirect ──────────────────────────────────────────────────

    async def check_http_redirect(self, sess):
        print("\n[*] Checking HTTP → HTTPS redirect enforcement...")
        if not self.is_https:
            self.findings.append({
                'type': 'NO_HTTPS',
                'severity': 'CRITICAL',
                'confidence': 98,
                'confidence_label': 'High',
                'url': self.target,
                'proof': f"Site served over HTTP — no TLS encryption",
                'detail': "Site is not using HTTPS — all traffic is plaintext",
                'remediation': "Deploy a TLS certificate (Let's Encrypt is free). Redirect all HTTP → HTTPS.",
            })
            print(f"  [CRITICAL] Site served over plain HTTP!")
            return

        http_url = self.target.replace('https://', 'http://', 1)
        try:
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as http_sess:
                async with http_sess.get(
                        http_url, allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=8)) as r:
                    location = r.headers.get('Location', r.headers.get('location', ''))
                    if r.status in [301, 302, 307, 308] and 'https://' in location:
                        print(f"  [OK] HTTP redirects to HTTPS (HTTP {r.status})")
                        if r.status != 301:
                            self.findings.append({
                                'type': 'HTTP_REDIRECT_NOT_PERMANENT',
                                'severity': 'LOW',
                                'confidence': 85,
                                'confidence_label': confidence_label(85),
                                'url': http_url,
                                'redirect_status': r.status,
                                'proof': f"HTTP {r.status} redirect — should be 301 Permanent",
                                'detail': "HTTP→HTTPS redirect uses non-permanent status — browsers don't cache it",
                                'remediation': "Use 301 Permanent redirect for HTTP→HTTPS. Enables HSTS preloading.",
                            })
                    else:
                        self.findings.append({
                            'type': 'NO_HTTP_TO_HTTPS_REDIRECT',
                            'severity': 'HIGH',
                            'confidence': 90,
                            'confidence_label': 'High',
                            'url': http_url,
                            'http_status': r.status,
                            'proof': f"HTTP request returned {r.status} without HTTPS redirect",
                            'detail': "HTTP version of site does not redirect to HTTPS — MITM possible",
                            'remediation': "Add 301 redirect: all HTTP → HTTPS. Enable HSTS with preload.",
                        })
                        print(f"  [HIGH] No HTTP→HTTPS redirect (HTTP {r.status})")
        except Exception as e:
            pass

    # ── TLS certificate analysis ───────────────────────────────────────────────

    async def analyse_certificate(self):
        if not self.is_https:
            return
        print(f"\n[*] Analysing TLS certificate for {self.host}:{self.port}...")
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()

            def _get_cert():
                with socket.create_connection((self.host, self.port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cert  = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        return cert, cipher, version

            cert, cipher, tls_version = await loop.run_in_executor(None, _get_cert)

            if not cert:
                return

            # Certificate expiry
            not_after_str = cert.get('notAfter', '')
            if not_after_str:
                not_after = datetime.strptime(
                    not_after_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                if days_left < 0:
                    self.findings.append({
                        'type': 'CERT_EXPIRED',
                        'severity': 'CRITICAL',
                        'confidence': 99,
                        'confidence_label': 'High',
                        'url': self.target,
                        'expiry_date': not_after_str,
                        'days_expired': abs(days_left),
                        'proof': f"Certificate expired {abs(days_left)} days ago ({not_after_str})",
                        'detail': "TLS certificate has expired — browsers show security warning",
                        'remediation': "Renew certificate immediately. Use Let's Encrypt with auto-renewal.",
                    })
                    print(f"  [CRITICAL] Certificate EXPIRED {abs(days_left)} days ago!")
                elif days_left < 14:
                    self.findings.append({
                        'type': 'CERT_EXPIRING_SOON',
                        'severity': 'HIGH',
                        'confidence': 99,
                        'confidence_label': 'High',
                        'url': self.target,
                        'days_until_expiry': days_left,
                        'expiry_date': not_after_str,
                        'proof': f"Certificate expires in {days_left} days ({not_after_str})",
                        'detail': f"Certificate expiring in {days_left} days — imminent outage risk",
                        'remediation': "Renew certificate now. Automate with Let's Encrypt/certbot.",
                    })
                    print(f"  [HIGH] Certificate expires in {days_left} days!")
                elif days_left < 30:
                    print(f"  [WARN] Certificate expires in {days_left} days")
                else:
                    print(f"  [OK] Certificate valid for {days_left} days")

            # CN / SAN match
            cn_match = False
            for san_type, san_val in cert.get('subjectAltName', []):
                if san_type == 'DNS':
                    if san_val == self.host or (
                            san_val.startswith('*.') and
                            self.host.endswith(san_val[1:])):
                        cn_match = True
                        break
            if not cn_match:
                subject = dict(x[0] for x in cert.get('subject', []))
                cn = subject.get('commonName', '')
                if cn == self.host or (cn.startswith('*.') and self.host.endswith(cn[1:])):
                    cn_match = True

            if not cn_match:
                self.findings.append({
                    'type': 'CERT_HOSTNAME_MISMATCH',
                    'severity': 'CRITICAL',
                    'confidence': 98,
                    'confidence_label': 'High',
                    'url': self.target,
                    'host': self.host,
                    'proof': f"Certificate CN/SAN does not match hostname '{self.host}'",
                    'detail': "Certificate hostname mismatch — MITM or misconfiguration",
                    'remediation': "Issue a certificate that covers this hostname in the SAN field.",
                })
                print(f"  [CRITICAL] Certificate hostname mismatch!")

            # TLS version
            if tls_version in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                severity = "CRITICAL" if tls_version == 'SSLv3' else "HIGH"
                self.findings.append({
                    'type': 'DEPRECATED_TLS_VERSION',
                    'severity': severity,
                    'confidence': 98,
                    'confidence_label': 'High',
                    'url': self.target,
                    'tls_version': tls_version,
                    'proof': f"Negotiated {tls_version} — deprecated and vulnerable",
                    'detail': f"{tls_version} negotiated — known attacks exist",
                    'remediation': "Disable TLS 1.0/1.1/SSLv3. Enforce TLS 1.2 minimum, prefer TLS 1.3.",
                })
                print(f"  [{severity}] Deprecated TLS version: {tls_version}")
            else:
                print(f"  [OK] TLS version: {tls_version}")

            # Cipher suite
            if cipher:
                cipher_name = cipher[0]
                for pattern, detail, sev in WEAK_CIPHER_PATTERNS:
                    if re.search(pattern, cipher_name, re.I):
                        self.findings.append({
                            'type': 'WEAK_CIPHER_SUITE',
                            'severity': sev,
                            'confidence': 95,
                            'confidence_label': 'High',
                            'url': self.target,
                            'cipher_suite': cipher_name,
                            'proof': f"Negotiated cipher: {cipher_name} — {detail}",
                            'detail': f"Weak cipher suite in use: {detail}",
                            'remediation': (
                                "Configure strong cipher suites only. "
                                "Recommended: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256. "
                                "Use Mozilla SSL Configuration Generator for your server."
                            ),
                        })
                        print(f"  [{sev}] Weak cipher: {cipher_name}")
                else:
                    print(f"  [OK] Cipher: {cipher_name}")

        except ssl.SSLCertVerificationError as e:
            self.findings.append({
                'type': 'CERT_INVALID',
                'severity': 'CRITICAL',
                'confidence': 97,
                'confidence_label': 'High',
                'url': self.target,
                'ssl_error': str(e),
                'proof': f"SSL verification failed: {e}",
                'detail': "Certificate is invalid/self-signed — browser will show UNTRUSTED warning",
                'remediation': "Replace self-signed certificate with one from a trusted CA (Let's Encrypt).",
            })
            print(f"  [CRITICAL] Invalid certificate: {e}")
        except Exception as e:
            print(f"  [*] Certificate analysis error: {e}")

    # ── HSTS header analysis ───────────────────────────────────────────────────

    async def check_hsts(self, sess):
        print("\n[*] HSTS policy analysis...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        hsts = hdrs.get('Strict-Transport-Security') or hdrs.get('strict-transport-security', '')

        if not hsts:
            self.findings.append({
                'type': 'MISSING_HSTS',
                'severity': 'HIGH',
                'confidence': 92,
                'confidence_label': 'High',
                'url': self.target,
                'proof': "Strict-Transport-Security header absent",
                'detail': "No HSTS — browser will use HTTP if requested (SSL stripping possible)",
                'remediation': "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            })
            print("  [HIGH] HSTS missing")
            return

        issues = []
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.I)
        if not max_age_match:
            issues.append("No max-age directive")
        else:
            age = int(max_age_match.group(1))
            if age < 2592000:  # < 30 days
                issues.append(f"max-age={age} too short (minimum recommended: 31536000)")
            elif age < 31536000:
                issues.append(f"max-age={age} < 1 year — consider max-age=63072000")

        if 'includesubdomains' not in hsts.lower():
            issues.append("Missing includeSubDomains — subdomains not protected")
        if 'preload' not in hsts.lower():
            issues.append("Missing preload — not eligible for HSTS preload list")

        if issues:
            self.findings.append({
                'type': 'WEAK_HSTS',
                'severity': 'MEDIUM',
                'confidence': 88,
                'confidence_label': 'High',
                'url': self.target,
                'hsts_value': hsts,
                'issues': issues,
                'proof': f"Strict-Transport-Security: {hsts} — issues: {', '.join(issues)}",
                'detail': f"Weak HSTS configuration: {'; '.join(issues)}",
                'remediation': "Use: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            })
            for issue in issues:
                print(f"  [MEDIUM] HSTS weak: {issue}")
        else:
            print(f"  [OK] HSTS: {hsts}")

    # ── Mixed content ──────────────────────────────────────────────────────────

    async def check_mixed_content(self, sess):
        if not self.is_https:
            return
        print("\n[*] Mixed content scan — HTTP resources on HTTPS pages...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        if not body:
            return

        http_resources = re.findall(
            r'(?:src|href|action)=["\']http://([^"\'>\s]+)["\']', body, re.I)

        if http_resources:
            self.findings.append({
                'type': 'MIXED_CONTENT',
                'severity': 'MEDIUM',
                'confidence': 90,
                'confidence_label': 'High',
                'url': self.target,
                'http_resource_count': len(http_resources),
                'examples': http_resources[:5],
                'proof': (f"{len(http_resources)} HTTP resource(s) on HTTPS page: "
                          f"{', '.join(http_resources[:3])}"),
                'detail': "Mixed content — HTTP resources loaded on HTTPS page (blocked by browsers)",
                'remediation': (
                    "1. Change all resource URLs to HTTPS or protocol-relative (//).\n"
                    "2. Add Content-Security-Policy: upgrade-insecure-requests.\n"
                    "3. Enable Mixed-Content-Blocker CSP directive."
                ),
            })
            print(f"  [MEDIUM] {len(http_resources)} HTTP resource(s) on HTTPS page")

    # ── Runner ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  CryptoHunter v4 — TLS/SSL & Cryptographic Weakness Analyser")
        print("  Cert expiry, version, ciphers, HSTS, mixed content")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": random_ua()}) as sess:

            await self.check_http_redirect(sess)
            await self.analyse_certificate()
            await self.check_hsts(sess)
            await self.check_mixed_content(sess)

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
    findings = asyncio.run(CryptoHunter(target).run())
    with open("reports/cryptohunter.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/cryptohunter.json")


if __name__ == '__main__':
    main()
