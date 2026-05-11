#!/usr/bin/env python3
"""DeepLogic v3 — fixes: require proof, confidence floor, proxy support."""
import asyncio, aiohttp, json, sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, body_changed_significantly,
    delay, confidence_score, confidence_label, severity_from_confidence,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

class DeepLogic:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, json_data=None, data=None, headers=None):
        try:
            kw = dict(headers=headers or {}, ssl=False, timeout=aiohttp.ClientTimeout(total=10))
            if json_data is not None: kw['json'] = json_data
            elif data is not None: kw['data'] = data
            async with sess.post(url, **kw) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment...")
        endpoints = ['/api/user','/api/profile','/api/account','/api/me','/api/register']
        privilege_fields = [
            {"admin":True}, {"role":"admin"}, {"is_admin":True},
            {"account_type":"premium"}, {"verified":True},
        ]
        for endpoint in endpoints:
            url = self.target + endpoint
            for extra in privilege_fields:
                payload = {"name":"test","email":"test@test.com",**extra}
                s, b, _ = await self._post(sess, url, json_data=payload)
                await delay()
                if is_truly_accessible(s) and b:
                    field_key = list(extra.keys())[0]
                    field_val = str(list(extra.values())[0]).lower()
                    if field_key in b.lower() and field_val in b.lower():
                        if meets_confidence_floor(80):
                            self.findings.append({
                                'type':'MASS_ASSIGNMENT','severity':'HIGH','confidence':80,
                                'confidence_label':'High','url':url,
                                'field':field_key,'value':extra[field_key],
                                'proof':f"Field '{field_key}={extra[field_key]}' reflected in HTTP {s} response body",
                                'detail':f"Mass assignment: '{field_key}' accepted and reflected at {endpoint}",
                                'remediation':"Use an allowlist of permitted fields. Never bind raw request JSON to model objects.",
                            })
                            print(f"  [HIGH] Mass assignment: '{field_key}' reflected at {url}")
                            break

    async def test_race_condition(self, sess):
        print("\n[*] Testing race conditions (8 concurrent requests)...")
        race_endpoints = [
            ('/api/coupon/apply','coupon','COUPON10'),
            ('/api/redeem','code','PROMO2024'),
            ('/api/vote','post_id','1'),
        ]
        for path, param, value in race_endpoints:
            url = self.target + path
            payload = {param: value, "user_id": 1}
            results = await asyncio.gather(*[self._post(sess, url, json_data=payload) for _ in range(8)],
                                           return_exceptions=True)
            successes = [r[0] for r in results if isinstance(r, tuple) and is_truly_accessible(r[0])]
            if len(successes) >= 3:
                if meets_confidence_floor(75):
                    self.findings.append({
                        'type':'RACE_CONDITION','severity':'HIGH','confidence':75,
                        'confidence_label':'Medium','url':url,
                        'concurrent':8,'successes':len(successes),
                        'proof':f"{len(successes)}/8 concurrent requests returned HTTP 200 — non-atomic operation",
                        'detail':f"Race condition: {len(successes)}/8 concurrent requests succeeded at {path}",
                        'remediation':"Use DB-level transactions and atomic operations. Add idempotency tokens.",
                    })
                    print(f"  [HIGH] Race condition: {len(successes)}/8 succeeded at {url}")
            await delay()

    async def test_business_logic(self, sess):
        print("\n[*] Testing business logic (negative/overflow values)...")
        cart_endpoints = ['/api/cart','/api/order','/api/checkout','/api/purchase']
        abuse_payloads = [
            {"quantity":-1,"product_id":1},
            {"price":-100,"product_id":1},
            {"quantity":999999,"product_id":1},
            {"discount":101,"product_id":1},
        ]
        for path in cart_endpoints:
            url = self.target + path
            for payload in abuse_payloads:
                s, b, _ = await self._post(sess, url, json_data=payload)
                await delay()
                if is_truly_accessible(s) and b and len(b) > 20:
                    suspicious = ['quantity','price','total','amount','discount','order']
                    if any(k in b.lower() for k in suspicious):
                        if meets_confidence_floor(75):
                            self.findings.append({
                                'type':'BUSINESS_LOGIC_ABUSE','severity':'HIGH','confidence':75,
                                'confidence_label':'Medium','url':url,'payload':payload,'status':s,
                                'proof':f"HTTP {s} accepted payload {payload} — response contains business data",
                                'detail':f"Business logic: abusive value accepted at {path}",
                                'remediation':"Validate all numeric inputs server-side: enforce min/max, reject negative quantities.",
                            })
                            print(f"  [HIGH] Biz logic: {list(payload.keys())[0]} abuse at {url}")
                            break

    async def test_api_version_drift(self, sess):
        print("\n[*] Testing API version security drift...")
        for v1, v2 in [('/api/v1/user','/api/v2/user'),('/api/v1/admin','/api/v2/admin')]:
            s1, b1, _ = await self._get(sess, self.target+v1); await delay()
            s2, b2, _ = await self._get(sess, self.target+v2); await delay()
            if s1 is None or s2 is None: continue
            if is_truly_accessible(s1) and s2 in [401,403] and b1 and len(b1) > 20:
                if meets_confidence_floor(85):
                    self.findings.append({
                        'type':'API_VERSION_SECURITY_DRIFT','severity':'HIGH','confidence':85,
                        'confidence_label':'High','v1_url':self.target+v1,'v2_url':self.target+v2,
                        'v1_status':s1,'v2_status':s2,
                        'proof':f"v1 returns HTTP {s1} (accessible), v2 returns HTTP {s2} (auth required)",
                        'detail':f"Old API version {v1} lacks auth controls present in {v2}",
                        'remediation':"Apply identical auth/authz to all API versions. Deprecate and remove old versions.",
                    })
                    print(f"  [HIGH] Version drift: {v1} ({s1}) vs {v2} ({s2})")

    async def run(self):
        print("="*60)
        print("  DeepLogic v3 — Business Logic Vulnerability Analyser")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_mass_assignment(sess)
            await self.test_race_condition(sess)
            await self.test_business_logic(sess)
            await self.test_api_version_drift(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(DeepLogic(target).run())
    with open("reports/deeplogic.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/deeplogic.json")

if __name__ == '__main__': main()
