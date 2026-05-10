#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import hashlib
import time
from pathlib import Path
from smart_filter import REQUEST_DELAY, confidence_score, confidence_label, severity_from_confidence

class DeepLogic:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []

    async def _post(self, sess, url, data):
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with sess.post(url, json=data, ssl=False, timeout=timeout) as r:
                return r.status
        except Exception:
            return None

    async def _get(self, sess, url, params=None):
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with sess.get(url, params=params, ssl=False, timeout=timeout) as r:
                return r.status, await r.text(errors='ignore')
        except Exception:
            return None, None

    async def test_race_condition(self, sess, endpoint):
        print(f"\n[*] Race condition: {endpoint}")
        tasks = [self._post(sess, endpoint, {'quantity': 1, 'action': 'buy', 'amount': 1}) for _ in range(20)]
        t0 = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - t0
        ok = sum(1 for r in responses if not isinstance(r, Exception) and r == 200)

        if ok > 3 and elapsed < 2.0:
            conf = confidence_score({
                'many_successes': (ok > 5, 50),
                'fast_window': (elapsed < 1.0, 30),
                'concurrent': (True, 20),
            })
            self.findings.append({
                'type': 'RACE_CONDITION',
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'endpoint': endpoint,
                'concurrent_successes': ok,
                'window': f"{elapsed:.3f}s",
                'detail': f'{ok} concurrent successes in {elapsed:.3f}s'
            })
            print(f"  [RACE] {ok} concurrent successes in {elapsed:.3f}s at {endpoint} [confidence: {confidence_label(conf)}]")
        await asyncio.sleep(REQUEST_DELAY)

    async def test_mass_assignment(self, sess, endpoint):
        print(f"\n[*] Mass assignment: {endpoint}")
        inject_fields = {
            'isAdmin': True,
            'role': 'admin',
            'admin': True,
            'privilege': 9,
            'access_level': 999,
        }
        for field, value in inject_fields.items():
            data = {'username': 'testuser', 'email': 'test@test.com', field: value}
            status = await self._post(sess, endpoint, data)
            await asyncio.sleep(REQUEST_DELAY)
            if status in [200, 201]:
                self.findings.append({
                    'type': 'MASS_ASSIGNMENT',
                    'severity': 'HIGH',
                    'confidence': 60,
                    'confidence_label': 'Medium',
                    'endpoint': endpoint,
                    'field': field,
                    'value': str(value),
                    'detail': f'Sensitive field accepted — verify manually if it was actually stored'
                })
                print(f"  [MASS] Field '{field}={value}' accepted at {endpoint} — manual verification required")

    async def test_idor(self, sess, endpoint):
        print(f"\n[*] IDOR testing: {endpoint}")
        unique_responses = {}
        for i in range(1, 20):
            test_url = f"{endpoint}/{i}"
            status, body = await self._get(sess, test_url)
            await asyncio.sleep(REQUEST_DELAY)
            if status == 200 and body and len(body) > 100:
                h = hashlib.md5(body.encode()).hexdigest()
                if h not in unique_responses:
                    unique_responses[h] = {'id': str(i), 'len': len(body)}

        if len(unique_responses) > 5:
            conf = confidence_score({
                'many_unique': (len(unique_responses) > 10, 50),
                'some_unique': (len(unique_responses) > 5, 30),
                'consistent': (True, 20),
            })
            self.findings.append({
                'type': 'IDOR_ENUMERATION',
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'endpoint': endpoint,
                'accessible_objects': len(unique_responses),
                'detail': f'{len(unique_responses)} unique objects accessible via sequential ID enumeration'
            })
            print(f"  [IDOR] {len(unique_responses)} objects enumerable at {endpoint} [confidence: {confidence_label(conf)}]")

    async def test_negative_values(self, sess, endpoint):
        print(f"\n[*] Business logic: {endpoint}")
        payloads = [
            {'amount': -100, 'currency': 'USD'},
            {'price': -50},
            {'quantity': -1},
            {'discount': 99999},
        ]
        for data in payloads:
            status = await self._post(sess, endpoint, data)
            await asyncio.sleep(REQUEST_DELAY)
            if status in [200, 201]:
                self.findings.append({
                    'type': 'BUSINESS_LOGIC_BYPASS',
                    'severity': 'MEDIUM',
                    'confidence': 50,
                    'confidence_label': 'Medium',
                    'endpoint': endpoint,
                    'payload': data,
                    'detail': 'Invalid amount accepted — manually verify if transaction was processed'
                })
                print(f"  [LOGIC] Invalid value {data} accepted at {endpoint} — manual verification required")

    async def test_parameter_pollution(self, sess, endpoint):
        print(f"\n[*] Parameter pollution: {endpoint}")
        pairs = [
            ('role', 'user', 'admin'),
            ('admin', 'false', 'true'),
        ]
        for param, v1, v2 in pairs:
            url = f"{endpoint}?{param}={v1}&{param}={v2}"
            status, body = await self._get(sess, url)
            await asyncio.sleep(REQUEST_DELAY)
            if body and v2 in body and v1 not in body:
                self.findings.append({
                    'type': 'HTTP_PARAMETER_POLLUTION',
                    'severity': 'MEDIUM',
                    'confidence': 70,
                    'confidence_label': 'Medium',
                    'endpoint': endpoint,
                    'parameter': param,
                    'proof': f'Second value ({v2}) overrode first ({v1}) in response',
                    'detail': f'HPP confirmed — second {param} value overrides first'
                })
                print(f"  [HPP] Parameter '{param}' pollutable at {endpoint}")

    async def run(self):
        print("="*60)
        print("  DeepLogic — Business Logic Vulnerability Scanner")
        print("="*60)

        endpoints = {
            'purchase': ['/api/purchase', '/api/order', '/api/checkout'],
            'user': ['/api/users', '/api/user', '/api/profile'],
            'payment': ['/api/payment', '/api/transfer', '/api/billing'],
        }

        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=conn, timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            for category, paths in endpoints.items():
                for path in paths:
                    ep = self.target + path
                    if category == 'purchase':
                        await self.test_race_condition(sess, ep)
                        await self.test_negative_values(sess, ep)
                    if category == 'user':
                        await self.test_idor(sess, ep)
                        await self.test_mass_assignment(sess, ep)
                    await self.test_parameter_pollution(sess, ep)

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://"+u


def main():
    print("="*60)
    print("  DeepLogic — Business Logic Scanner")
    print("="*60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    scanner = DeepLogic(target)
    findings = asyncio.run(scanner.run())
    with open("reports/deeplogic.json", 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] {len(findings)} findings -> reports/deeplogic.json")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM']:
        items = [f for f in findings if f.get('severity') == sev]
        if items:
            print(f"\n[!] {len(items)} {sev}:")
            for c in items:
                print(f"    - {c['type']}: {c['endpoint']}")

if __name__ == '__main__':
    main()
