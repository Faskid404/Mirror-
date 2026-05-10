#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
import json
import os
import re
from pathlib import Path
from smart_filter import REQUEST_DELAY, confidence_score, confidence_label, severity_from_confidence, is_demo_value

DEFAULT_PATHS = [
    # User / profile resources
    "/api/users/1", "/api/users/2", "/api/users/3", "/api/users/me",
    "/api/user", "/api/profile", "/api/me", "/me",
    "/api/account", "/api/account/settings",
    # Admin resources
    "/admin", "/admin/users", "/admin/dashboard", "/admin/config",
    "/api/admin", "/api/admin/users", "/api/admin/logs", "/api/admin/settings",
    "/api/internal/config", "/api/internal/metrics",
    # Data / object endpoints (IDOR targets)
    "/api/orders/1", "/api/orders/2", "/api/orders/3",
    "/api/documents/1", "/api/documents/2",
    "/api/reports/1", "/api/invoices/1",
    # Token / key endpoints
    "/api/keys", "/api/tokens", "/api/api-keys",
    # Version variants
    "/api/v1/users", "/api/v1/users/1", "/api/v1/admin",
    "/api/v2/users", "/api/v2/users/1",
    # Audit / log endpoints
    "/api/logs", "/api/audit", "/api/audit-log",
    "/api/billing", "/api/debug", "/api/settings",
    # GraphQL introspection
    "/graphql", "/api/graphql",
]

NOT_FOUND_PHRASES = [
    "page not found", "404", "not found", "does not exist",
    "no page found", "could not find", "resource not found",
    "invalid route", "no route", "unknown endpoint",
]

LEAK_PATTERNS = [
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT'),
    (r'"password"\s*:\s*"([^"]{8,})"', 'PASSWORD'),
    (r'"passwd"\s*:\s*"([^"]{8,})"', 'PASSWORD'),
    (r'"token"\s*:\s*"([^"]{20,})"', 'TOKEN'),
    (r'"access_token"\s*:\s*"([^"]{20,})"', 'ACCESS_TOKEN'),
    (r'"refresh_token"\s*:\s*"([^"]{20,})"', 'REFRESH_TOKEN'),
    (r'"api[_-]?key"\s*:\s*"([^"]{20,})"', 'API_KEY'),
    (r'"secret"\s*:\s*"([^"]{16,})"', 'SECRET'),
    (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY'),
    (r'"aws_secret_access_key"\s*:\s*"([^"]{30,})"', 'AWS_SECRET_KEY'),
    (r'-----BEGIN.*?PRIVATE KEY-----', 'PRIVATE_KEY'),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', 'SLACK_TOKEN'),
    (r'gh[pousr]_[A-Za-z0-9]{36,}', 'GITHUB_TOKEN'),
    (r'"client_secret"\s*:\s*"([^"]{20,})"', 'OAUTH_SECRET'),
    (r'"private_key"\s*:\s*"([^"]{30,})"', 'PRIVATE_KEY_JSON'),
    (r'-----BEGIN CERTIFICATE-----', 'CERTIFICATE'),
    (r'"ssn"\s*:\s*"(\d{3}-\d{2}-\d{4})"', 'SSN'),
    (r'"credit_card"\s*:\s*"([^"]{13,19})"', 'CREDIT_CARD'),
]

LEAK_BLACKLIST = {
    'password', 'token', 'api_key', 'changeme', 'example',
    'test', 'your_token', 'your_key', 'undefined', 'null',
    'placeholder', 'insert_here',
}

SENSITIVE_FIELDS = [
    'ssn', 'social_security', 'credit_card', 'card_number', 'cvv',
    'dob', 'date_of_birth', 'salary', 'bank_account', 'routing_number',
    'private_key', 'secret_key', 'encryption_key', 'is_admin', 'role',
    'permission', 'admin', 'superuser', 'internal_id',
]

VERBS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']


class AuthDrift:
    def __init__(self, base, paths, anon, low, high):
        self.base = base.rstrip('/')
        self.paths = paths
        self.personas = {'anon': anon, 'low': low, 'high': high}
        self.findings = []
        self.leaks = []

    def is_404_like(self, body):
        if not body:
            return True
        bl = body.lower()
        return any(p in bl for p in NOT_FOUND_PHRASES)

    def extract_json_keys(self, body):
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return set(data.keys())
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return set(data[0].keys())
        except Exception:
            pass
        return set(re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,40})"', body))

    def scan_body_for_leaks(self, body, url, persona):
        for pattern, ltype in LEAK_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                val = match if isinstance(match, str) else str(match)
                if val.lower() in LEAK_BLACKLIST or len(val) < 8:
                    continue
                if is_demo_value(val):
                    continue
                self.leaks.append({
                    'type': ltype,
                    'value': val[:80],
                    'url': url,
                    'persona': persona,
                    'severity': 'CRITICAL' if ltype in ('AWS_ACCESS_KEY', 'PRIVATE_KEY', 'PRIVATE_KEY_JSON') else 'HIGH',
                    'confidence': 85,
                    'confidence_label': 'High',
                })
                print(f"  [LEAK] {ltype} found via {persona} at {url}")

    def scan_sensitive_fields(self, body, url, persona):
        keys = self.extract_json_keys(body)
        found = [k for k in keys if any(sf in k.lower() for sf in SENSITIVE_FIELDS)]
        if found:
            self.leaks.append({
                'type': 'SENSITIVE_FIELD_EXPOSURE',
                'fields': found,
                'url': url,
                'persona': persona,
                'severity': 'HIGH',
                'confidence': 70,
                'confidence_label': 'Medium',
                'detail': f'Sensitive JSON fields visible to {persona}: {found}',
            })
            print(f"  [FIELD] Sensitive fields visible to {persona} at {url}: {found}")

    async def fetch(self, sess, url, hdrs, method='GET'):
        try:
            timeout = aiohttp.ClientTimeout(total=12)
            req = getattr(sess, method.lower())
            async with req(
                url, headers=hdrs, ssl=False,
                timeout=timeout, allow_redirects=False
            ) as r:
                body = await r.read()
                body_text = body.decode('utf-8', errors='ignore')
                return {
                    'status': r.status,
                    'len': len(body),
                    'hash': hashlib.md5(body).hexdigest()[:10],
                    'body': body_text,
                    'headers': dict(r.headers),
                }
        except Exception as e:
            return {'error': str(e)[:80]}

    def analyze(self, url, res):
        a, l, h = res['anon'], res['low'], res['high']

        if any('error' in x for x in (a, l, h)):
            return None

        a_body = a.get('body', '')
        l_body = l.get('body', '')
        h_body = h.get('body', '')

        if self.is_404_like(h_body) or h.get('len', 0) < 100:
            return None

        # 1. Anonymous == privileged (fully broken auth — CRITICAL)
        if (a['status'] == h['status'] == 200
                and a['hash'] == h['hash']
                and a['len'] > 100
                and not self.is_404_like(a_body)):
            conf = confidence_score({
                'same_hash': (True, 60),
                'both_200': (True, 30),
                'large_body': (a['len'] > 500, 10),
            })
            return {
                'severity': severity_from_confidence('CRITICAL', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'issue': 'anonymous == privileged response (broken authentication)',
                'proof': f'anon hash {a["hash"]} == high-priv hash {h["hash"]}, len={a["len"]}',
                'remediation': 'Enforce authentication middleware on this endpoint',
            }

        # 2. Low-priv == high-priv (IDOR / BOLA — HIGH)
        if (l['status'] == h['status'] == 200
                and l['hash'] == h['hash']
                and l['len'] > 100
                and not self.is_404_like(l_body)):
            conf = confidence_score({
                'same_hash': (True, 60),
                'both_200': (True, 30),
                'large_body': (l['len'] > 500, 10),
            })
            return {
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'issue': 'low-priv == high-priv (IDOR/BOLA — broken object-level authorization)',
                'proof': f'low-priv hash {l["hash"]} == high-priv hash {h["hash"]}, len={l["len"]}',
                'remediation': 'Add object-level authorization checks per request',
            }

        # 3. Anon gets 200 while expecting 401/403 (unauthenticated access)
        if (a['status'] == 200 and h['status'] == 200
                and a['hash'] != h['hash']
                and a['len'] > 100
                and not self.is_404_like(a_body)):
            conf = confidence_score({
                'anon_200': (True, 50),
                'different_content': (True, 30),
                'large': (a['len'] > 300, 20),
            })
            return {
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'issue': 'anonymous gets 200 with content (possible partial auth bypass)',
                'proof': f'anon status=200 len={a["len"]}, high-priv len={h["len"]}',
                'remediation': 'Verify what data is exposed to unauthenticated requests',
            }

        # 4. Low-priv overlaps high-priv by size ratio (MEDIUM)
        if (l['status'] == 200 and h['status'] == 200
                and h['len'] > 0
                and l['len'] / h['len'] > 0.75
                and l['hash'] != h['hash']
                and not self.is_404_like(l_body)):
            ratio = l['len'] / h['len']
            conf = confidence_score({
                'high_ratio': (ratio > 0.9, 50),
                'medium_ratio': (ratio > 0.75, 30),
                'both_200': (True, 20),
            })
            return {
                'severity': severity_from_confidence('MEDIUM', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'issue': f'low-priv response is {ratio:.0%} size of high-priv (content overlap)',
                'proof': f'low len={l["len"]} vs high len={h["len"]} ratio={ratio:.2f}',
                'remediation': 'Verify field-level authorization — low-priv user may see extra data',
            }

        # 5. Sensitive JSON fields exposed to low-priv but not anon
        if (l['status'] == 200 and not self.is_404_like(l_body)):
            l_keys = self.extract_json_keys(l_body)
            h_keys = self.extract_json_keys(h_body)
            sensitive_in_low = [
                k for k in l_keys
                if any(sf in k.lower() for sf in SENSITIVE_FIELDS) and k in h_keys
            ]
            if sensitive_in_low:
                conf = confidence_score({
                    'sensitive_field': (True, 70),
                    'multiple_fields': (len(sensitive_in_low) > 1, 30),
                })
                return {
                    'severity': severity_from_confidence('MEDIUM', conf),
                    'confidence': conf,
                    'confidence_label': confidence_label(conf),
                    'url': url,
                    'issue': 'Sensitive fields exposed to low-privilege user',
                    'proof': f'Fields in low-priv response: {sensitive_in_low}',
                    'remediation': 'Apply field-level access control / response filtering',
                }

        return None

    async def test_verb_tampering(self, sess, url):
        results = {}
        for verb in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                req = getattr(sess, verb.lower())
                async with req(url, ssl=False, timeout=timeout, allow_redirects=False) as r:
                    results[verb] = r.status
                await asyncio.sleep(REQUEST_DELAY)
            except Exception:
                results[verb] = None

        # Flag if a non-GET verb returns 200 on a protected resource
        if results.get('GET') in (401, 403):
            bypassed = [v for v in ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
                        if results.get(v) == 200]
            if bypassed:
                self.findings.append({
                    'type': 'VERB_TAMPERING_BYPASS',
                    'severity': 'HIGH',
                    'confidence': 85,
                    'confidence_label': 'High',
                    'url': url,
                    'bypassed_verbs': bypassed,
                    'proof': f'GET={results["GET"]} but {bypassed} returned 200',
                    'remediation': 'Apply authorization checks per HTTP method, not just on GET',
                })
                print(f"  [VERB] HTTP verb bypass at {url}: {bypassed} -> 200")

    async def test_idor_enumeration(self, sess, base_path, hdrs_low):
        print(f"\n[*] IDOR enumeration: {base_path}")
        successful_ids = []
        for i in range(1, 25):
            url = f"{self.base}{base_path}/{i}"
            r = await self.fetch(sess, url, hdrs_low)
            await asyncio.sleep(REQUEST_DELAY)
            if r.get('status') == 200 and r.get('len', 0) > 50 and not self.is_404_like(r.get('body', '')):
                successful_ids.append(i)
            if len(successful_ids) >= 10:
                break

        if len(successful_ids) >= 5:
            conf = confidence_score({
                'many_ids': (len(successful_ids) >= 10, 60),
                'some_ids': (len(successful_ids) >= 5, 30),
                'sequential': (True, 10),
            })
            self.findings.append({
                'type': 'IDOR_SEQUENTIAL_ENUMERATION',
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'base_path': base_path,
                'accessible_ids': successful_ids[:10],
                'proof': f'{len(successful_ids)} objects accessible via sequential ID at {base_path}/N',
                'remediation': 'Use UUIDs or opaque IDs; add object-level authorization',
            })
            print(f"  [IDOR] {len(successful_ids)} objects at {base_path}/N [confidence: {confidence_label(conf)}]")

    async def run(self):
        print("=" * 60)
        print("  AuthDrift — Access Control & Leak Scanner")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            for path in self.paths:
                url = self.base + '/' + path.lstrip('/')
                print(f"\n[*] {path}")
                res = {}
                for pname, hdrs in self.personas.items():
                    r = await self.fetch(sess, url, hdrs)
                    res[pname] = r
                    if 'body' in r and r.get('status') == 200:
                        self.scan_body_for_leaks(r['body'], url, pname)
                        self.scan_sensitive_fields(r['body'], url, pname)
                    await asyncio.sleep(REQUEST_DELAY)

                f = self.analyze(url, res)
                if f:
                    print(f"  [{f['severity']}] {f['issue']} [confidence: {f['confidence_label']}]")
                    self.findings.append(f)
                else:
                    print(f"  [OK] {url}")

                # HTTP verb tampering check (anon context)
                await self.test_verb_tampering(sess, url)

            # IDOR enumeration on object endpoints
            idor_bases = ['/api/users', '/api/orders', '/api/documents', '/api/reports', '/api/invoices']
            for base_path in idor_bases:
                await self.test_idor_enumeration(sess, base_path, self.personas.get('low', {}))

        return self.findings


def parse_h(s):
    if not s.strip():
        return {}
    out = {}
    for ln in s.split(';'):
        if ':' in ln:
            k, v = ln.split(':', 1)
            out[k.strip()] = v.strip()
    return out


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Base URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    print("=" * 60)
    print("  AuthDrift — Access Control + Leak Scanner")
    print("=" * 60)
    target = get_target()
    print(f"[+] Base: {target}")

    non_interactive = bool(os.environ.get('ARSENAL_TARGET'))

    if non_interactive:
        paths = DEFAULT_PATHS
        anon = {}
        low = {}
        high = {}
        print(f"[+] Non-interactive mode: {len(paths)} default paths, no auth tokens")
    else:
        print("\n[?] Paths (one per line, blank = use defaults):")
        paths = []
        while True:
            p = input()
            if not p.strip():
                break
            paths.append(p.strip())
        if not paths:
            paths = DEFAULT_PATHS
            print(f"[+] Using {len(paths)} default paths")

        print("\n[?] Anon headers (blank=none, format 'Header: Value; Header2: Value2'):")
        anon = parse_h(input().strip())
        print("[?] Low-priv headers (e.g. 'Authorization: Bearer LOW_TOKEN'):")
        low = parse_h(input().strip())
        print("[?] High-priv headers (e.g. 'Authorization: Bearer ADMIN_TOKEN'):")
        high = parse_h(input().strip())

    Path("reports").mkdir(exist_ok=True)
    drift = AuthDrift(target, paths, anon, low, high)
    findings = asyncio.run(drift.run())

    with open("reports/authdrift.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/authdrift.json")

    by_sev = {}
    for item in findings:
        s = item.get('severity', 'INFO')
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev in by_sev:
            print(f"   {sev:10s}: {by_sev[sev]}")

    if drift.leaks:
        with open("reports/authdrift_leaks.json", 'w') as f:
            json.dump(drift.leaks, f, indent=2)
        print(f"[!] {len(drift.leaks)} leaks -> reports/authdrift_leaks.json")


if __name__ == '__main__':
    main()
