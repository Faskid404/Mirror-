#!/usr/bin/env python3
"""HeaderForge v3 — fixes: 403 clarification, confidence floor, proxy support."""
import asyncio
import aiohttp
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, is_reflected, delay,
    confidence_score, confidence_label, severity_from_confidence,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

class HeaderForge:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.host   = urlparse(target).hostname
        self.findings = []
        self.baseline_404 = ""

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

    async def test_host_injection(self, sess):
        print("\n[*] Testing Host header injection (password reset poisoning)...")
        evil = "evil-host-injection.com"
        for path in ['/forgot-password','/auth/forgot-password','/reset-password','/api/auth/reset']:
            s, b, hdrs = await self._get(sess, self.target + path,
                headers={"Host": evil, "X-Forwarded-Host": evil})
            await delay()
            if s in [200,400] and b and is_reflected(evil, b):
                conf = 90
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type':'HOST_HEADER_INJECTION','severity':'HIGH',
                        'confidence':conf,'confidence_label':confidence_label(conf),
                        'url':self.target+path,'injected_host':evil,
                        'proof':f"'{evil}' reflected verbatim in response body at {path}",
                        'detail':"Host header injection — password reset link may point to attacker domain",
                        'remediation':"Use a server-side allowlist for valid hostnames. Never use the Host header to build URLs.",
                    })
                    print(f"  [HIGH] Host injection: '{evil}' reflected at {path}")

        # Cache poisoning via root
        s, b, _ = await self._get(sess, self.target,
            headers={"Host": evil, "X-Forwarded-Host": evil})
        await delay()
        if b and is_reflected(evil, b):
            if meets_confidence_floor(85):
                self.findings.append({
                    'type':'HOST_CACHE_POISON','severity':'HIGH','confidence':85,
                    'confidence_label':'High','url':self.target,
                    'proof':f"'{evil}' reflected in root response — cache poisoning possible",
                    'detail':"Host header reflected in root response — cache poisoning risk",
                    'remediation':"Validate Host header against a server-side allowlist of known hostnames.",
                })
                print("  [HIGH] Host reflected in root — cache poison risk")

    async def test_forwarded_headers(self, sess):
        print("\n[*] Testing X-Forwarded-* reflection...")
        marker = "fwd-inject.evil.com"
        for header in ["X-Forwarded-Host","X-Host","X-Forwarded-Server","X-Original-URL"]:
            s, b, _ = await self._get(sess, self.target, headers={header: marker})
            await delay()
            if b and is_reflected(marker, b):
                if meets_confidence_floor(90):
                    self.findings.append({
                        'type':'FORWARDED_HEADER_INJECTION','severity':'HIGH',
                        'confidence':90,'confidence_label':'High',
                        'header':header,'url':self.target,
                        'proof':f"'{marker}' reflected in response via {header}",
                        'detail':f"{header} reflected — SSRF or cache poisoning risk",
                        'remediation':f"Do not reflect {header} in responses. Validate against an allowlist.",
                    })
                    print(f"  [HIGH] {header} reflected")

    async def audit_security_headers(self, sess):
        print("\n[*] Auditing security headers (complete audit)...")
        s, b, hdrs = await self._get(sess, self.target, allow_redirects=True)
        await delay()
        if not hdrs: return
        hdrs_lower = {k.lower(): v for k,v in hdrs.items()}
        checks = [
            ('strict-transport-security','HSTS','CRITICAL',
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
             ["max-age=0","max-age=1"]),
            ('content-security-policy','CSP','HIGH',
             "Implement a restrictive Content-Security-Policy. Avoid 'unsafe-inline' and 'unsafe-eval'.",
             ["unsafe-inline","unsafe-eval","*"]),
            ('x-frame-options','X-Frame-Options','MEDIUM',
             "Add: X-Frame-Options: DENY",[]  ),
            ('x-content-type-options','X-Content-Type-Options','LOW',
             "Add: X-Content-Type-Options: nosniff",[]),
            ('referrer-policy','Referrer-Policy','LOW',
             "Add: Referrer-Policy: strict-origin-when-cross-origin",[]),
            ('permissions-policy','Permissions-Policy','LOW',
             "Add a Permissions-Policy restricting camera, microphone, geolocation.",[]),
        ]
        for hdr_name, label, sev, advice, weak_vals in checks:
            hdr_val = hdrs_lower.get(hdr_name,'')
            if not hdr_val:
                self.findings.append({
                    'type':f'MISSING_{label.replace("-","_").upper()}','severity':sev,
                    'confidence':100,'confidence_label':'High',
                    'header':hdr_name,'url':self.target,
                    'proof':f"Response headers contain no '{hdr_name}' header",
                    'detail':f"Missing security header: {hdr_name}",
                    'remediation':advice,
                })
                print(f"  [{sev}] Missing: {hdr_name}")
            elif weak_vals:
                for weak in weak_vals:
                    if weak.lower() in hdr_val.lower():
                        self.findings.append({
                            'type':f'WEAK_{label.replace("-","_").upper()}','severity':sev,
                            'confidence':90,'confidence_label':'High',
                            'header':hdr_name,'value':hdr_val,'weak_directive':weak,
                            'url':self.target,
                            'proof':f"'{hdr_name}: {hdr_val}' contains weak directive '{weak}'",
                            'detail':f"Weak {hdr_name}: contains '{weak}'",
                            'remediation':advice,
                        })
                        print(f"  [{sev}] Weak {hdr_name}: '{weak}'")
                        break
        for dh in ['server','x-powered-by','x-aspnet-version']:
            val = hdrs_lower.get(dh,'')
            if val and re.search(r'\d+\.\d+',val):
                self.findings.append({
                    'type':'VERSION_DISCLOSURE','severity':'LOW','confidence':95,
                    'confidence_label':'High','header':dh,'value':val,'url':self.target,
                    'proof':f"Header '{dh}: {val}' reveals version number",
                    'detail':f"Version disclosed via {dh}: {val}",
                    'remediation':f"Remove or redact the {dh} header in server configuration.",
                })
                print(f"  [LOW] Version in {dh}: {val}")

    async def audit_cors(self, sess):
        print("\n[*] Auditing CORS (5 origin patterns)...")
        test_origins = [
            'https://evil.com',
            f'https://evil.{self.host}',
            f'https://{self.host}.evil.com',
            'null',
            f'http://{self.host}',
        ]
        for endpoint in [self.target, self.target+'/api', self.target+'/api/v1']:
            for origin in test_origins:
                s, b, hdrs = await self._get(sess, endpoint,
                    headers={"Origin":origin,"Access-Control-Request-Method":"GET"})
                await delay()
                acao = hdrs.get('Access-Control-Allow-Origin','')
                acac = hdrs.get('Access-Control-Allow-Credentials','').lower()
                if acao in (origin,'*'):
                    dangerous = acac == 'true' and acao == origin
                    conf = confidence_score({
                        'origin_reflected':(acao==origin,50),
                        'credentials':(dangerous,40),
                        'status_ok':(s==200,10),
                    })
                    sev = 'CRITICAL' if dangerous else 'HIGH'
                    if meets_confidence_floor(conf):
                        self.findings.append({
                            'type':'CORS_MISCONFIGURATION',
                            'severity':severity_from_confidence(sev,conf),
                            'confidence':conf,'confidence_label':confidence_label(conf),
                            'endpoint':endpoint,'reflected_origin':origin,
                            'acao':acao,'credentials':acac,
                            'proof':f"Access-Control-Allow-Origin: {acao}" + (f" + Allow-Credentials: true" if dangerous else ""),
                            'detail':f"CORS: '{origin}' accepted at {endpoint}" + (' with credentials!' if dangerous else ''),
                            'remediation':"Use an explicit origin allowlist. Never combine wildcard ACAO with credentials=true.",
                        })
                        print(f"  [{sev}] CORS: {origin} accepted at {endpoint} (creds={acac}) [conf:{conf}%]")

    async def run(self):
        print("="*60)
        print("  HeaderForge v3 — HTTP Header Attack Surface Analyser")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.audit_security_headers(sess)
            await self.audit_cors(sess)
            await self.test_host_injection(sess)
            await self.test_forwarded_headers(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(HeaderForge(target).run())
    with open("reports/headerforge.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/headerforge.json")

if __name__ == '__main__': main()
