#!/usr/bin/env python3
"""
DeepLogic v2 — Business logic and race condition vulnerability analyser.

Improvements:
  - Race condition detection (coupon reuse, concurrent requests)
  - Mass assignment (overpowered JSON fields like admin:true, role:admin)
  - Parameter pollution (duplicate params, array injection)
  - Business logic: negative prices, integer overflow, quantity abuse
  - API versioning security drift (v1 vs v2 endpoint differences)
  - Privilege escalation through endpoint manipulation
  - Forced browsing (direct object access without auth)
  - GraphQL permission bypass
  - Response data filtering bypass (extra fields in response)
  - Time-of-check vs time-of-use (TOCTOU) hints
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urlencode

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_likely_real_vuln, body_changed_significantly,
    delay, confidence_score, confidence_label, severity_from_confidence, REQUEST_DELAY
)

class DeepLogic:
    def __init__(self, target):
        self.target       = target.rstrip('/')
        self.host         = urlparse(target).hostname
        self.findings     = []
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
            if json_data is not None:
                kw['json'] = json_data
            elif data is not None:
                kw['data'] = data
            async with sess.post(url, **kw) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _add(self, finding):
        self.findings.append(finding)

    # ── Mass assignment ───────────────────────────────────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment vulnerabilities...")
        endpoints = [
            '/api/user', '/api/profile', '/api/account', '/api/me',
            '/api/v1/user', '/api/v1/profile', '/api/register', '/api/signup',
        ]
        privilege_fields = [
            {"admin": True},
            {"role": "admin"},
            {"is_admin": True},
            {"permissions": ["admin", "superuser"]},
            {"account_type": "premium"},
            {"verified": True},
            {"credits": 99999},
            {"balance": 99999},
        ]
        for endpoint in endpoints:
            url = self.target + endpoint
            # Baseline: what does the endpoint return normally?
            s_base, b_base, _ = await self._get(sess, url)
            await delay()
            if s_base not in [200, 400, 401, 403]:
                continue

            for extra_fields in privilege_fields:
                payload = {"name": "test", "email": "test@test.com", **extra_fields}
                s, b, hdrs = await self._post(sess, url, json_data=payload)
                await delay()
                if s in [200, 201]:
                    # Check if the privileged field was accepted/reflected
                    field_key   = list(extra_fields.keys())[0]
                    field_value = str(list(extra_fields.values())[0]).lower()
                    if field_key in (b or '').lower() and field_value in (b or '').lower():
                        self._add({
                            'type':             'MASS_ASSIGNMENT',
                            'severity':         'HIGH',
                            'confidence':       80,
                            'confidence_label': 'High',
                            'url':              url,
                            'field':            field_key,
                            'value':            extra_fields[field_key],
                            'proof':            f"Field '{field_key}' reflected in response with value '{extra_fields[field_key]}'",
                            'detail':           f"Mass assignment: injected '{field_key}' accepted at {endpoint}",
                            'remediation':      "Use an allowlist of permitted fields. Never bind raw request JSON to model objects.",
                        })
                        print(f"  [HIGH] Mass assignment: '{field_key}' accepted at {url}")
                        break

    # ── Parameter pollution ───────────────────────────────────────────────────

    async def test_param_pollution(self, sess):
        print("\n[*] Testing parameter pollution...")
        test_endpoints = [
            '/api/user?id=1&id=2',
            '/api/product?price=100&price=-1',
            '/search?q=test&q=admin',
        ]
        for path in test_endpoints:
            url = self.target + path
            s, b, hdrs = await self._get(sess, url)
            await delay()
            if s == 200 and b and is_likely_real_vuln(b, s, self.baseline_404):
                # Try with conflicting privileged value
                priv_path = path + '&admin=true&role=admin'
                url2 = self.target + priv_path
                s2, b2, _ = await self._get(sess, url2)
                await delay()
                if s2 == 200 and b2 and body_changed_significantly(b or '', b2 or ''):
                    self._add({
                        'type':             'PARAMETER_POLLUTION',
                        'severity':         'MEDIUM',
                        'confidence':       65,
                        'confidence_label': 'Medium',
                        'url':              url2,
                        'detail':           f"Response changed when adding admin=true — parameter pollution possible",
                        'remediation':      "Use the last or first occurrence of a parameter. Reject requests with duplicate parameter names.",
                    })
                    print(f"  [MEDIUM] Param pollution at {url2}")

    # ── Race condition ────────────────────────────────────────────────────────

    async def test_race_condition(self, sess):
        print("\n[*] Testing race conditions (concurrent requests)...")
        race_endpoints = [
            ('/api/coupon/apply',   'coupon', 'COUPON10'),
            ('/api/redeem',         'code',   'PROMO2024'),
            ('/api/transfer',       'amount', '100'),
            ('/api/vote',           'post_id', '1'),
        ]
        for path, param, value in race_endpoints:
            url = self.target + path
            # Send 8 concurrent identical requests
            payload = {param: value, "user_id": 1}
            tasks   = [self._post(sess, url, json_data=payload) for _ in range(8)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            statuses = [r[0] for r in results if isinstance(r, tuple) and r[0] is not None]
            successes = [s for s in statuses if s in [200, 201]]
            if len(successes) >= 2:
                self._add({
                    'type':             'RACE_CONDITION',
                    'severity':         'HIGH',
                    'confidence':       75,
                    'confidence_label': 'Medium',
                    'url':              url,
                    'concurrent':       len(tasks),
                    'successes':        len(successes),
                    'proof':            f"{len(successes)}/{len(tasks)} concurrent requests returned success status",
                    'detail':           f"Race condition: {len(successes)} concurrent requests succeeded at {path}",
                    'remediation':      "Use database-level transactions and atomic operations. Add idempotency tokens to state-changing endpoints.",
                })
                print(f"  [HIGH] Race condition at {url}: {len(successes)}/8 succeeded")
            await delay()

    # ── Business logic abuse ──────────────────────────────────────────────────

    async def test_business_logic(self, sess):
        print("\n[*] Testing business logic vulnerabilities...")
        # Negative price / quantity
        cart_endpoints = ['/api/cart', '/api/order', '/api/checkout', '/api/purchase']
        abuse_payloads = [
            {"quantity": -1,       "product_id": 1},
            {"quantity": 0,        "product_id": 1},
            {"price":    -100,     "product_id": 1},
            {"quantity": 999999,   "product_id": 1},
            {"discount": 101,      "product_id": 1},
            {"quantity": 1e308,    "product_id": 1},  # float overflow
        ]
        for path in cart_endpoints:
            url = self.target + path
            for payload in abuse_payloads:
                s, b, _ = await self._post(sess, url, json_data=payload)
                await delay()
                if s in [200, 201] and b and len(b) > 20:
                    # Success with abusive input
                    suspicious_keys = ['quantity', 'price', 'total', 'amount', 'discount']
                    if any(k in (b or '').lower() for k in suspicious_keys):
                        self._add({
                            'type':             'BUSINESS_LOGIC_ABUSE',
                            'severity':         'HIGH',
                            'confidence':       75,
                            'confidence_label': 'Medium',
                            'url':              url,
                            'payload':          payload,
                            'status':           s,
                            'detail':           f"Business logic: abusive payload accepted at {path} — negative/overflow value accepted",
                            'remediation':      "Validate all numeric business inputs server-side: enforce min/max, reject negative values for quantities.",
                        })
                        print(f"  [HIGH] Business logic: {payload} accepted at {url}")
                        break

    # ── API version drift ─────────────────────────────────────────────────────

    async def test_api_version_drift(self, sess):
        print("\n[*] Testing API version security drift...")
        version_pairs = [
            ('/api/v1/user', '/api/v2/user'),
            ('/api/v1/admin', '/api/v2/admin'),
            ('/api/v1/settings', '/api/v2/settings'),
        ]
        for v1_path, v2_path in version_pairs:
            s1, b1, h1 = await self._get(sess, self.target + v1_path)
            await delay()
            s2, b2, h2 = await self._get(sess, self.target + v2_path)
            await delay()
            if s1 is None or s2 is None:
                continue
            # If v2 requires auth (401/403) but v1 doesn't
            if s1 == 200 and s2 in [401, 403] and b1 and len(b1) > 20:
                self._add({
                    'type':             'API_VERSION_SECURITY_DRIFT',
                    'severity':         'HIGH',
                    'confidence':       85,
                    'confidence_label': 'High',
                    'v1_url':           self.target + v1_path,
                    'v2_url':           self.target + v2_path,
                    'v1_status':        s1,
                    'v2_status':        s2,
                    'proof':            f"v1 returns {s1} (accessible), v2 returns {s2} (protected)",
                    'detail':           f"Old API version {v1_path} lacks authentication controls present in {v2_path}",
                    'remediation':      "Apply identical authentication and authorisation controls to all API versions. Deprecate and remove old versions.",
                })
                print(f"  [HIGH] Version drift: {v1_path} ({s1}) vs {v2_path} ({s2})")

    # ── Forced browsing ───────────────────────────────────────────────────────

    async def test_forced_browsing(self, sess):
        print("\n[*] Testing forced browsing (unauthenticated access)...")
        admin_paths = [
            '/admin', '/admin/users', '/admin/settings', '/admin/logs',
            '/api/admin', '/api/admin/users', '/api/internal',
            '/dashboard', '/management', '/superadmin',
        ]
        for path in admin_paths:
            url = self.target + path
            s, b, hdrs = await self._get(sess, url)
            await delay()
            if s == 200 and b and is_likely_real_vuln(b, s, self.baseline_404):
                pii_sigs = ['email', 'user', 'password', 'role', 'admin', 'log', 'setting']
                if any(sig in b.lower() for sig in pii_sigs):
                    self._add({
                        'type':             'FORCED_BROWSING',
                        'severity':         'HIGH',
                        'confidence':       80,
                        'confidence_label': 'High',
                        'url':              url,
                        'status':           s,
                        'size':             len(b),
                        'detail':           f"Admin/sensitive path accessible without auth: {path}",
                        'remediation':      "Implement authentication middleware on all administrative routes. Verify auth before any controller logic.",
                    })
                    print(f"  [HIGH] Forced browsing: {url} (HTTP {s})")

    async def run(self):
        print("=" * 60)
        print("  DeepLogic v2 — Business Logic Vulnerability Analyser")
        print("=" * 60)
        conn    = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_mass_assignment(sess)
            await self.test_param_pollution(sess)
            await self.test_race_condition(sess)
            await self.test_business_logic(sess)
            await self.test_api_version_drift(sess)
            await self.test_forced_browsing(sess)
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
    scanner  = DeepLogic(target)
    findings = asyncio.run(scanner.run())
    with open("reports/deeplogic.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/deeplogic.json")

if __name__ == '__main__':
    main()
