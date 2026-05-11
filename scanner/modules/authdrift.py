#!/usr/bin/env python3
"""AuthDrift v3 — fixes: proof requirement, confidence floor, proxy, 403-clarity."""
import asyncio, aiohttp, json, re, sys, base64, hashlib, hmac, time
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, body_changed_significantly,
    delay, confidence_score, confidence_label, severity_from_confidence,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),("admin","admin123"),
    ("root","root"),("root","toor"),("admin","letmein"),("admin","qwerty"),
    ("admin","welcome"),("admin","changeme"),("superuser","superuser"),("test","test"),
]

AUTH_PATHS = [
    '/login','/signin','/auth/login','/api/login','/api/auth/login',
    '/api/v1/auth/login','/api/v1/login','/user/login','/account/login',
]

class AuthDrift:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.baseline_404 = ""
        self.login_url = None

    async def _get(self, sess, url, headers=None, allow_redirects=True):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=allow_redirects) as r:
                cookies = {k:v.value for k,v in r.cookies.items()}
                return r.status, await r.text(errors='ignore'), dict(r.headers), cookies
        except Exception:
            return None, None, {}, {}

    async def _post(self, sess, url, json_data=None, data=None, headers=None):
        try:
            kw = dict(headers=headers or {}, ssl=False, timeout=aiohttp.ClientTimeout(total=10))
            if json_data is not None: kw['json'] = json_data
            elif data is not None: kw['data'] = data
            async with sess.post(url, **kw) as r:
                cookies = {k:v.value for k,v in r.cookies.items()}
                return r.status, await r.text(errors='ignore'), dict(r.headers), cookies
        except Exception:
            return None, None, {}, {}

    async def find_login_endpoint(self, sess):
        print("\n[*] Locating login endpoints...")
        for path in AUTH_PATHS:
            url = self.target + path
            s, b, hdrs, _ = await self._get(sess, url)
            await delay()
            if is_truly_accessible(s) and b:
                if any(x in b.lower() for x in ['password','login','signin','username','email']):
                    self.login_url = url
                    print(f"  [+] Login endpoint: {url}")
                    return url
            elif s in [401, 403]:
                pass  # Protected — expected, not a finding
        return None

    async def test_user_enumeration(self, sess):
        print("\n[*] Testing account enumeration via response differences...")
        if not self.login_url: return
        resp = []
        for email, pw in [("admin@example.com","badpass_xyz"),("notreal_xyz@noexist.invalid","badpass_xyz")]:
            s, b, hdrs, _ = await self._post(sess, self.login_url, json_data={"email":email,"password":pw})
            await delay()
            resp.append((s, len(b or ''), b or ''))
        if len(resp) == 2:
            s1,l1,b1 = resp[0]; s2,l2,b2 = resp[1]
            if s1 != s2:
                if meets_confidence_floor(90):
                    self.findings.append({
                        'type':'USER_ENUMERATION_STATUS','severity':'MEDIUM','confidence':90,
                        'confidence_label':'High','url':self.login_url,
                        'proof':f"Known user: HTTP {s1}, Unknown user: HTTP {s2} — different status codes",
                        'detail':"Account enumeration via HTTP status code differences",
                        'remediation':"Return identical status codes for valid and invalid usernames.",
                    })
                    print(f"  [MEDIUM] User enum via status: {s1} vs {s2}")
            elif abs(l1-l2) > 80:
                if meets_confidence_floor(75):
                    self.findings.append({
                        'type':'USER_ENUMERATION_BODY','severity':'MEDIUM','confidence':75,
                        'confidence_label':'Medium','url':self.login_url,
                        'proof':f"Body length: known user={l1}b, unknown user={l2}b (diff={abs(l1-l2)}b)",
                        'detail':"Account enumeration via response body length differences",
                        'remediation':"Return uniform response bodies for all login attempts.",
                    })
                    print(f"  [MEDIUM] User enum via body length: {abs(l1-l2)}b diff")

    async def spray_default_creds(self, sess):
        print("\n[*] Testing default credentials...")
        if not self.login_url: return
        s_fail, b_fail, _, _ = await self._post(sess, self.login_url,
            json_data={"username":"definitely_no_such_user_xyz","password":"wrong_pass_xyz"})
        await delay()
        for username, password in DEFAULT_CREDS:
            for payload in [
                {"username":username,"password":password},
                {"email":username,"password":password},
            ]:
                s, b, hdrs, cookies = await self._post(sess, self.login_url, json_data=payload)
                await delay()
                success = any([
                    is_truly_accessible(s) and cookies,
                    is_truly_accessible(s) and b and any(x in b.lower() for x in ['dashboard','welcome','token']),
                    'authorization' in hdrs,
                    any('token' in k.lower() or 'session' in k.lower() for k in cookies),
                ])
                if success and s != s_fail:
                    if meets_confidence_floor(90):
                        self.findings.append({
                            'type':'DEFAULT_CREDENTIALS','severity':'CRITICAL','confidence':90,
                            'confidence_label':'High','url':self.login_url,
                            'username':username,'password':password,'status':s,
                            'proof':f"Login succeeded with {username}:{password} (HTTP {s}, cookies: {list(cookies.keys())})",
                            'detail':f"Default credentials accepted: {username}:{password}",
                            'remediation':"Change default credentials immediately. Enforce strong password policy.",
                        })
                        print(f"  [CRITICAL] Default creds work: {username}:{password}")
                        return

    async def test_lockout(self, sess):
        print("\n[*] Testing brute-force protection (15 attempts)...")
        if not self.login_url: return
        statuses = []
        for i in range(15):
            s, b, _, _ = await self._post(sess, self.login_url,
                json_data={"username":"admin","password":f"wrong_pw_{i}"})
            await asyncio.sleep(0.12)
            if s: statuses.append(s)
            if s in [429,423,503]:
                print(f"  [+] Rate limiting triggered after {i+1} attempts (HTTP {s})")
                return
        if statuses and not any(s in [429,423,503] for s in statuses):
            if meets_confidence_floor(85):
                self.findings.append({
                    'type':'NO_BRUTE_FORCE_PROTECTION','severity':'HIGH','confidence':85,
                    'confidence_label':'High','url':self.login_url,
                    'requests_sent':len(statuses),'statuses':list(set(statuses)),
                    'proof':f"Sent {len(statuses)} failed login requests — no 429/lockout received. Statuses: {list(set(statuses))}",
                    'detail':f"No brute-force protection: {len(statuses)} failed logins without lockout",
                    'remediation':"Implement exponential backoff, account lockout after 5-10 failures, and CAPTCHA.",
                })
                print(f"  [HIGH] No lockout after {len(statuses)} attempts")

    async def test_jwt_attacks(self, sess):
        print("\n[*] Testing JWT vulnerabilities...")
        api_paths = ['/api/me','/api/user','/api/profile','/api/v1/user']
        header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"1","admin":true,"role":"admin","iat":9999999999}').rstrip(b'=').decode()
        none_token = f"{header}.{payload}."
        for path in api_paths:
            url = self.target + path
            s, b, hdrs, _ = await self._get(sess, url, headers={"Authorization":f"Bearer {none_token}"})
            await delay()
            if is_truly_accessible(s) and b and len(b) > 20:
                reject = ['unauthorized','invalid token','forbidden','error','invalid','malformed']
                if not any(x in b.lower() for x in reject):
                    if meets_confidence_floor(90):
                        self.findings.append({
                            'type':'JWT_NONE_ALGORITHM','severity':'CRITICAL','confidence':90,
                            'confidence_label':'High','url':url,
                            'proof':f"Token with alg=none accepted — HTTP {s}, {len(b)}b response without error",
                            'detail':"JWT none-algorithm accepted — signature verification bypassed",
                            'remediation':"Reject JWTs with alg=none. Always verify signatures server-side.",
                        })
                        print(f"  [CRITICAL] JWT none-algorithm accepted at {url}")

    async def test_idor(self, sess):
        print("\n[*] Testing IDOR (unauthenticated object access)...")
        id_paths = ['/api/user/{id}','/api/users/{id}','/api/order/{id}','/api/v1/user/{id}']
        pii_signals = ['email','phone','address','password','ssn','credit','dob']
        for tmpl in id_paths:
            for id_val in ['1','2','100']:
                url = self.target + tmpl.replace('{id}',id_val)
                s, b, _, _ = await self._get(sess, url)
                await delay()
                if is_truly_accessible(s) and b and len(b) > 50:
                    has_pii = any(x in b.lower() for x in pii_signals)
                    if has_pii:
                        if meets_confidence_floor(80):
                            self.findings.append({
                                'type':'IDOR_UNAUTHENTICATED','severity':'HIGH','confidence':80,
                                'confidence_label':'High','url':url,'id':id_val,
                                'proof':f"HTTP {s} returned {len(b)}b response containing PII signals ({[x for x in pii_signals if x in b.lower()][:3]})",
                                'detail':f"IDOR: unauthenticated access to user object at {url}",
                                'remediation':"Implement object-level authorization. Verify the requesting user owns the resource.",
                            })
                            print(f"  [HIGH] IDOR at {url} — PII returned unauthenticated")
                            return

    async def run(self):
        print("="*60)
        print("  AuthDrift v3 — Authentication Security Analyser")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.find_login_endpoint(sess)
            await self.test_user_enumeration(sess)
            await self.spray_default_creds(sess)
            await self.test_lockout(sess)
            await self.test_jwt_attacks(sess)
            await self.test_idor(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(AuthDrift(target).run())
    with open("reports/authdrift.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/authdrift.json")

if __name__ == '__main__': main()
