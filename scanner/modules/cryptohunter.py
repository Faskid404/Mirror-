#!/usr/bin/env python3
"""CryptoHunter v3 — fixes: cert-only TLS scan, confidence floor, proxy support."""
import asyncio, aiohttp, json, re, sys, ssl, socket, time, datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_score, confidence_label,
    severity_from_confidence, meets_confidence_floor, random_ua, PROXY_URL, REQUEST_DELAY
)

WEAK_CIPHERS = ['RC4','DES','3DES','NULL','EXPORT','anon','ADH','AECDH','MD5']
EXPOSED_KEY_PATHS = ['/server.key','/private.pem','/private.key','/.ssl/private.key','/id_rsa','/.ssh/id_rsa']

class CryptoHunter:
    def __init__(self, target):
        self.target = target.rstrip('/')
        parsed = urlparse(target)
        self.host   = parsed.hostname
        self.port   = parsed.port or (443 if parsed.scheme=='https' else 80)
        self.scheme = parsed.scheme
        self.findings = []
        self.baseline_404 = ""

    async def _get(self, sess, url, allow_redirects=True):
        try:
            async with sess.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=allow_redirects) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def audit_tls_versions(self):
        print("\n[*] Checking TLS version support...")
        if self.scheme != 'https':
            self.findings.append({
                'type':'HTTP_NOT_HTTPS','severity':'CRITICAL','confidence':100,
                'confidence_label':'High','url':self.target,
                'proof':"Target URL uses http:// scheme — no TLS encryption",
                'detail':"Target uses plain HTTP — all data transmitted in cleartext",
                'remediation':"Enable HTTPS with TLS 1.2+ certificate. Redirect all HTTP to HTTPS (301).",
            })
            print("  [CRITICAL] Plain HTTP — no TLS!")
            return
        for name, ver in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ver; ctx.maximum_version = ver
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                sock = socket.create_connection((self.host, self.port), timeout=5)
                ssock = ctx.wrap_socket(sock, server_hostname=self.host)
                got_ver = ssock.version(); ssock.close()
                if got_ver:
                    self.findings.append({
                        'type':f'DEPRECATED_TLS','severity':'HIGH','confidence':95,
                        'confidence_label':'High','host':self.host,'version':got_ver,
                        'proof':f"Server completed handshake using {got_ver}",
                        'detail':f"Deprecated {name} supported — vulnerable to BEAST/POODLE",
                        'remediation':f"Disable {name}. Only support TLS 1.2 and 1.3.",
                    })
                    print(f"  [HIGH] Deprecated {name} accepted")
            except (ssl.SSLError, ConnectionRefusedError, OSError): pass
            except Exception: pass

    async def analyse_certificate(self):
        print("\n[*] Analysing TLS certificate...")
        if self.scheme != 'https': return
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((self.host, self.port), timeout=8)
            ssock = ctx.wrap_socket(sock, server_hostname=self.host)
            cert   = ssock.getpeercert()
            cipher = ssock.cipher(); ssock.close()
            if not cert: return
            na_str = cert.get('notAfter','')
            if na_str:
                try:
                    na = datetime.datetime.strptime(na_str, "%b %d %H:%M:%S %Y %Z")
                    days = (na - datetime.datetime.utcnow()).days
                    if days < 0:
                        self.findings.append({
                            'type':'CERTIFICATE_EXPIRED','severity':'CRITICAL','confidence':100,
                            'confidence_label':'High','host':self.host,'days':days,
                            'proof':f"Certificate notAfter={na_str} is {abs(days)} days in the past",
                            'detail':f"TLS certificate expired {abs(days)} days ago",
                            'remediation':"Renew TLS cert immediately. Use certbot for automated renewal.",
                        })
                        print(f"  [CRITICAL] Certificate EXPIRED {abs(days)} days ago!")
                    elif days < 30:
                        self.findings.append({
                            'type':'CERTIFICATE_EXPIRING_SOON','severity':'HIGH','confidence':100,
                            'confidence_label':'High','host':self.host,'days_remaining':days,
                            'proof':f"Certificate expires {na_str} ({days} days from now)",
                            'detail':f"TLS certificate expires in {days} days",
                            'remediation':"Renew TLS cert now. Set up automated renewal.",
                        })
                        print(f"  [HIGH] Cert expires in {days} days")
                    else:
                        print(f"  [+] Certificate valid for {days} more days")
                except ValueError: pass
            subj   = dict(x[0] for x in cert.get('subject',[]))
            issuer = dict(x[0] for x in cert.get('issuer',[]))
            if subj.get('commonName') == issuer.get('commonName'):
                self.findings.append({
                    'type':'SELF_SIGNED_CERTIFICATE','severity':'HIGH','confidence':90,
                    'confidence_label':'High','host':self.host,
                    'proof':f"Subject CN == Issuer CN: '{subj.get('commonName','')}' — self-signed",
                    'detail':"Self-signed TLS certificate — browsers will warn users",
                    'remediation':"Replace with a CA-issued certificate (e.g. Let's Encrypt).",
                })
                print("  [HIGH] Self-signed certificate")
            if cipher:
                print(f"  [+] Cipher: {cipher[0]}")
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher[0].upper():
                        self.findings.append({
                            'type':'WEAK_CIPHER_SUITE','severity':'HIGH','confidence':95,
                            'confidence_label':'High','host':self.host,
                            'cipher':cipher[0],'weak_component':weak,
                            'proof':f"Active cipher suite '{cipher[0]}' contains weak component '{weak}'",
                            'detail':f"Weak cipher in use: {cipher[0]}",
                            'remediation':"Only offer AEAD ciphers (AES-GCM, CHACHA20). Disable NULL/RC4/DES/EXPORT.",
                        })
                        print(f"  [HIGH] Weak cipher: {cipher[0]}")
        except Exception as e:
            print(f"  [!] Certificate analysis error: {e}")

    async def audit_hsts(self, sess):
        print("\n[*] Auditing HSTS configuration...")
        s, b, hdrs = await self._get(sess, self.target, allow_redirects=True); await delay()
        hsts = hdrs.get('Strict-Transport-Security','')
        if not hsts:
            self.findings.append({
                'type':'MISSING_HSTS','severity':'HIGH','confidence':100,'confidence_label':'High',
                'url':self.target,'proof':"No Strict-Transport-Security header in response",
                'detail':"HSTS header missing — browser won't enforce HTTPS on future visits",
                'remediation':"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
            print("  [HIGH] HSTS missing")
        else:
            m = re.search(r'max-age=(\d+)', hsts)
            if m and int(m.group(1)) < 31536000:
                self.findings.append({
                    'type':'HSTS_MAX_AGE_LOW','severity':'MEDIUM','confidence':90,
                    'confidence_label':'High','url':self.target,'max_age':int(m.group(1)),
                    'proof':f"Strict-Transport-Security: {hsts}",
                    'detail':f"HSTS max-age too low: {m.group(1)}s (should be 31536000s)",
                    'remediation':"Set max-age to at least 31536000 and add includeSubDomains.",
                })
                print(f"  [MEDIUM] HSTS max-age low: {m.group(1)}")
            else:
                print(f"  [+] HSTS: {hsts}")

    async def scan_exposed_keys(self, sess):
        print("\n[*] Scanning for exposed private keys...")
        for path in EXPOSED_KEY_PATHS:
            url = self.target + path
            s, b, _ = await self._get(sess, url); await delay()
            if s == 200 and b and 'BEGIN' in b and ('PRIVATE KEY' in b or 'CERTIFICATE' in b):
                self.findings.append({
                    'type':'EXPOSED_PRIVATE_KEY','severity':'CRITICAL','confidence':98,
                    'confidence_label':'High','url':url,
                    'proof':"PEM header ('BEGIN PRIVATE KEY' or 'BEGIN CERTIFICATE') found in HTTP 200 response",
                    'detail':f"Private key/cert file exposed at {path}",
                    'remediation':"Remove from web root. Rotate all affected keys immediately.",
                })
                print(f"  [CRITICAL] Private key/cert at {url}")

    async def run(self):
        print("="*60)
        print("  CryptoHunter v3 — TLS/SSL & Cryptographic Weakness Analyser")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=30),
                proxy=PROXY_URL or None,
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.audit_tls_versions()
            await self.analyse_certificate()
            await self.audit_hsts(sess)
            await self.scan_exposed_keys(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(CryptoHunter(target).run())
    with open("reports/cryptohunter.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/cryptohunter.json")

if __name__ == '__main__': main()
