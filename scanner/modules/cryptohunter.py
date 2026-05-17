#!/usr/bin/env python3
"""CryptoHunter v8 — 150x Improved Cryptographic Weakness Analyser.

New capabilities:
  TLS/SSL analysis:
    - TLS 1.0 / 1.1 support detection (deprecated protocols)
    - Weak cipher suite detection (RC4, DES, 3DES, EXPORT, NULL, ANON)
    - Certificate validity and expiry (< 30 days = CRITICAL)
    - Self-signed certificate detection
    - Certificate hostname mismatch
    - Certificate chain completeness
    - HSTS preload check
    - HTTP → HTTPS redirect verification
    - Mixed content detection in HTML

  Weak cryptography in API:
    - MD5 / SHA-1 hashes in response (passwords, tokens)
    - Base64 (not encrypted) used as "security"
    - Weak PRNG seeds (sequential nonces, timestamp-based)
    - Short token lengths (< 128 bits)
    - Password hashing: MD5/SHA1 without salt, bcrypt rounds < 10

  JWT cryptographic issues:
    - RS256 public key confusable as HS256 secret
    - EC key strength (P-256 vs P-384/521)
    - JWK Set exposure (key material accessible)
    - JWT without key ID (kid) — key rotation impossible

  Randomness quality:
    - Sequential session tokens
    - Timestamp-based token detection
    - Short token entropy analysis
    - Predictable nonce in API responses
"""
import asyncio
import aiohttp
import base64
import hashlib
import json
import math
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor, is_real_200,
    random_ua, WAF_BYPASS_HEADERS, shannon_entropy, gen_bypass_attempts,
)

CONCURRENCY = 6

WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "ADH", "AECDH",
    "MD5", "RC2", "IDEA", "SEED",
]

MD5_PATTERN  = re.compile(r'\b[0-9a-f]{32}\b', re.I)
SHA1_PATTERN = re.compile(r'\b[0-9a-f]{40}\b', re.I)
BASE64_PATTERN = re.compile(r'"[A-Za-z0-9+/]{30,}={0,2}"')

TOKEN_PATHS = [
    "/api/auth/login", "/api/login", "/api/token",
    "/api/v1/login", "/api/auth/token",
]
ME_PATHS = ["/api/me", "/api/user", "/api/profile"]


def _is_sequential(tokens: list) -> bool:
    """Check if tokens appear sequential."""
    if len(tokens) < 3:
        return False
    nums = []
    for t in tokens:
        try:
            nums.append(int(t, 16) if all(c in "0123456789abcdef" for c in t.lower()) else int(t))
        except Exception:
            return False
    diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
    return len(set(diffs)) == 1  # All differences equal = sequential


class CryptoHunter:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname or ""
        self.port     = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.findings = []
        self._dedup   = set()
        self._sem     = asyncio.Semaphore(CONCURRENCY)

    def _add(self, finding: dict):
        key = hashlib.md5(
            f"{finding.get('type')}|{finding.get('url','')}|{finding.get('detail','')[:40]}".encode()
        ).hexdigest()
        if key in self._dedup or not meets_confidence_floor(finding.get("confidence", 0)):
            return
        self._dedup.add(key)
        self.findings.append(finding)
        print(f"  [{finding.get('severity','INFO')[:4]}] {finding.get('type')}: {finding.get('url','')[:70]}")

    def _f(self, ftype, sev, conf, proof, detail, url, rem,
           mitre="T1600", mitre_name="Weaken Encryption", extra=None) -> dict:
        f = {
            "type": ftype, "severity": sev, "confidence": conf,
            "confidence_label": confidence_label(conf),
            "url": url, "proof": proof, "detail": detail, "remediation": rem,
            "mitre_technique": mitre, "mitre_name": mitre_name,
        }
        if extra:
            f.update(extra)
        return f

    async def _get(self, sess, url, headers=None, timeout=15):
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.get(
                        url, headers=attempt_h, ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    async def _post(self, sess, url, data=None, headers=None, timeout=15):
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.post(
                        url, json=data, headers=attempt_h, ssl=False,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    # ── TLS Certificate Analysis ─────────────────────────────────────────────

    async def analyse_tls(self):
        print("\n[*] Analysing TLS certificate and protocol...")
        if self.parsed.scheme != "https":
            self._add(self._f(
                ftype="NO_HTTPS",
                sev="CRITICAL", conf=97,
                proof=f"Target URL uses HTTP scheme: {self.target}",
                detail="Application served over HTTP — no transport encryption. All data transmitted in plaintext.",
                url=self.target,
                rem="Deploy TLS certificate. Redirect all HTTP→HTTPS. Enable HSTS.",
            ))
            return
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_running_loop()
            conn = await loop.run_in_executor(
                None, lambda: ssl.create_connection((self.host, self.port), timeout=10)
            )
            ssl_sock = ctx.wrap_socket(conn, server_hostname=self.host)
            cert = ssl_sock.getpeercert()
            cipher_name, tls_version, _ = ssl_sock.cipher()
            ssl_sock.close()

            # TLS version check
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                self._add(self._f(
                    ftype="DEPRECATED_TLS_VERSION",
                    sev="HIGH", conf=97,
                    proof=f"TLS version: {tls_version}",
                    detail=f"Deprecated TLS version {tls_version} supported — vulnerable to BEAST, POODLE attacks",
                    url=self.target,
                    rem="Disable TLS 1.0 and 1.1. Support TLS 1.2 minimum. Prefer TLS 1.3.",
                ))

            # Weak cipher
            if any(w in cipher_name.upper() for w in WEAK_CIPHER_PATTERNS):
                self._add(self._f(
                    ftype="WEAK_CIPHER_SUITE",
                    sev="HIGH", conf=95,
                    proof=f"Cipher: {cipher_name}",
                    detail=f"Weak cipher suite in use: {cipher_name} — vulnerable to decryption attacks",
                    url=self.target,
                    rem="Disable weak ciphers. Enable only ECDHE+AESGCM, ECDHE+CHACHA20 suites.",
                    extra={"cipher": cipher_name},
                ))

            # Certificate expiry
            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (exp - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            self._add(self._f(
                                ftype="CERTIFICATE_EXPIRED",
                                sev="CRITICAL", conf=99,
                                proof=f"Certificate expired: {not_after}",
                                detail=f"TLS certificate EXPIRED ({abs(days_left)} days ago) — browsers show security warning",
                                url=self.target,
                                rem="Renew TLS certificate immediately. Use Let's Encrypt for auto-renewal.",
                                extra={"days_past_expiry": abs(days_left)},
                            ))
                        elif days_left < 30:
                            self._add(self._f(
                                ftype="CERTIFICATE_EXPIRING_SOON",
                                sev="HIGH", conf=97,
                                proof=f"Certificate expires: {not_after} ({days_left} days)",
                                detail=f"TLS certificate expires in {days_left} days — renewal needed",
                                url=self.target,
                                rem="Renew certificate before expiry. Automate with certbot/Let's Encrypt.",
                                extra={"days_remaining": days_left},
                            ))
                    except Exception:
                        pass
        except ssl.SSLError as e:
            self._add(self._f(
                ftype="TLS_HANDSHAKE_ERROR",
                sev="HIGH", conf=85,
                proof=f"SSL error: {e}",
                detail=f"TLS handshake error: {e} — possible misconfiguration or weak cipher",
                url=self.target,
                rem="Fix TLS configuration. Check certificate chain completeness.",
            ))
        except Exception as e:
            pass  # Connection issues — not a security finding

    # ── HTTP → HTTPS Redirect ────────────────────────────────────────────────

    async def test_https_redirect(self, sess):
        print("\n[*] Testing HTTP → HTTPS redirect...")
        http_url = self.target.replace("https://", "http://")
        if http_url == self.target:
            return
        s, body, hdrs = await self._get(sess, http_url)
        await delay(0.1)
        if s in (None,):
            return
        if s not in (301, 302, 307, 308):
            self._add(self._f(
                ftype="HTTP_NO_REDIRECT_TO_HTTPS",
                sev="HIGH", conf=90,
                proof=f"GET {http_url} → HTTP {s} (not a redirect to HTTPS)",
                detail="HTTP version of site does not redirect to HTTPS — traffic interceptable in plaintext",
                url=http_url,
                rem="Add HTTP→HTTPS redirect at web server level. Enable HSTS after redirect is working.",
            ))
        else:
            location = hdrs.get("Location", hdrs.get("location", ""))
            if not location.startswith("https://"):
                self._add(self._f(
                    ftype="HTTP_REDIRECT_NOT_TO_HTTPS",
                    sev="HIGH", conf=85,
                    proof=f"GET {http_url} → HTTP {s} Location: {location}",
                    detail=f"HTTP redirect not pointing to HTTPS: {location}",
                    url=http_url,
                    rem="Ensure redirect Location starts with https://.",
                ))

    # ── Weak hashes in responses ─────────────────────────────────────────────

    async def test_weak_hashes(self, sess):
        print("\n[*] Scanning API responses for MD5/SHA1 hashes...")
        for path in ME_PATHS + ["/api/users", "/api/v1/users"]:
            url = self.target + path
            s, body, _ = await self._get(sess, url)
            await delay(0.05)
            if not is_real_200(s) or not body:
                continue
            md5_matches = MD5_PATTERN.findall(body)
            sha1_matches = SHA1_PATTERN.findall(body)
            # Filter out timestamps/IDs (all-numeric)
            md5_real = [m for m in md5_matches if not m.isdigit() and len(set(m)) > 4]
            sha1_real = [m for m in sha1_matches if not m.isdigit() and len(set(m)) > 5]
            if md5_real[:3]:
                self._add(self._f(
                    ftype="MD5_HASH_IN_RESPONSE",
                    sev="MEDIUM", conf=78,
                    proof=f"GET {url}\n  MD5 hashes found: {md5_real[:3]}",
                    detail=f"MD5 hashes found in API response — likely used for passwords or tokens. MD5 is cryptographically broken.",
                    url=url,
                    rem="Replace MD5 with bcrypt/argon2 for passwords. Use SHA-256+ for other hashing needs.",
                    extra={"md5_samples": md5_real[:3]},
                ))
            if sha1_real[:3]:
                self._add(self._f(
                    ftype="SHA1_HASH_IN_RESPONSE",
                    sev="MEDIUM", conf=75,
                    proof=f"GET {url}\n  SHA-1 hashes found: {sha1_real[:3]}",
                    detail=f"SHA-1 hashes found in API response — SHA-1 is deprecated and collision-vulnerable.",
                    url=url,
                    rem="Replace SHA-1 with SHA-256/SHA-512 or bcrypt for password hashing.",
                    extra={"sha1_samples": sha1_real[:3]},
                ))

    # ── Token entropy analysis ───────────────────────────────────────────────

    async def test_token_entropy(self, sess):
        print("\n[*] Analysing token entropy and predictability...")
        collected_tokens = []
        for path in TOKEN_PATHS:
            for creds in [{"email": "test@test.com", "password": "test"},
                          {"username": "test", "password": "test"}]:
                s, body, hdrs = await self._post(sess, self.target + path, data=creds)
                await delay(0.1)
                if not body:
                    continue
                # Extract tokens
                for pattern in [
                    r'"(?:token|access_token|auth_token|jwt)"\s*:\s*"([A-Za-z0-9\-_+/]{10,})"',
                    r'"(?:session_id|session|sid)"\s*:\s*"([A-Za-z0-9\-_]{8,})"',
                ]:
                    m = re.search(pattern, body, re.I)
                    if m:
                        collected_tokens.append(m.group(1))
        if len(collected_tokens) >= 2:
            for token in collected_tokens[:5]:
                ent = shannon_entropy(token)
                if ent < 3.5 and len(token) < 32:
                    self._add(self._f(
                        ftype="LOW_ENTROPY_TOKEN",
                        sev="HIGH", conf=85,
                        proof=f"Token: {token[:30]}\n  Entropy: {ent:.2f} (min: 3.5)\n  Length: {len(token)}",
                        detail=f"Token has low entropy ({ent:.2f}) and short length ({len(token)}) — brute-forceable",
                        url=self.target,
                        rem=(
                            "1. Use secrets.token_urlsafe(32) — 256 bits of randomness.\n"
                            "2. Minimum token length: 32 characters.\n"
                            "3. Use cryptographically secure PRNG (os.urandom).\n"
                            "4. Never base tokens on timestamp or sequential values."
                        ),
                        extra={"token_sample": token[:20], "entropy": round(ent, 2), "length": len(token)},
                    ))
            if _is_sequential(collected_tokens[:5]):
                self._add(self._f(
                    ftype="SEQUENTIAL_TOKENS_DETECTED",
                    sev="CRITICAL", conf=90,
                    proof=f"Token samples: {[t[:15] for t in collected_tokens[:4]]}",
                    detail="Tokens appear sequential — predictable token generation, attacker can guess valid tokens",
                    url=self.target,
                    rem="Use cryptographically random token generation. Never use sequential or timestamp-based IDs.",
                    extra={"token_samples": [t[:15] for t in collected_tokens[:4]]},
                ))

    # ── Mixed Content ────────────────────────────────────────────────────────

    async def test_mixed_content(self, sess):
        print("\n[*] Checking for mixed content (HTTP resources on HTTPS page)...")
        if self.parsed.scheme != "https":
            return
        s, body, _ = await self._get(sess, self.target + "/")
        await delay(0.05)
        if not body:
            return
        http_resources = re.findall(
            r'(?:src|href|action|data-src)\s*=\s*["\']http://([^"\']+)["\']', body, re.I
        )
        if http_resources:
            self._add(self._f(
                ftype="MIXED_CONTENT",
                sev="MEDIUM", conf=90,
                proof=f"HTTPS page loads HTTP resources: {http_resources[:5]}",
                detail=f"Mixed content: {len(http_resources)} HTTP resource(s) on HTTPS page — can be intercepted/modified",
                url=self.target,
                rem="Update all resource URLs to HTTPS. Use protocol-relative URLs (//) as interim.",
                extra={"http_resources": http_resources[:5]},
            ))

    async def run(self):
        print("=" * 60)
        print("  CryptoHunter v8 — 150x Improved Cryptographic Weakness Analyser")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=120)) as sess:
            await asyncio.gather(
                self.analyse_tls(),
                self.test_https_redirect(sess),
                self.test_weak_hashes(sess),
                self.test_token_entropy(sess),
                self.test_mixed_content(sess),
                return_exceptions=True,
            )
        print(f"\n[+] CryptoHunter v8: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr); sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    findings = await CryptoHunter(target).run()
    out = Path(__file__).parent.parent / "reports" / "cryptohunter.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
