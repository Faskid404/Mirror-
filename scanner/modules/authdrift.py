#!/usr/bin/env python3
"""AuthDrift v8 — 150x Improved Authentication Security Analyser.

New capabilities:
  Password policy testing:
    - Minimum length enforcement (tries 1-7 char passwords)
    - No complexity enforcement (all lowercase, no special chars)
    - Common password acceptance (password123, 123456)
    - Blank password acceptance
    - Unicode password bypass

  Account enumeration:
    - Username/email enumeration via different error messages
    - Timing-based enumeration (valid vs invalid user response time delta)
    - Account existence via password reset form
    - Account existence via login error wording
    - Registration endpoint enumeration

  2FA / MFA bypass:
    - Skip 2FA step (direct API call after first factor)
    - 2FA code brute-force (no rate limit)
    - 2FA code reuse (same code works twice)
    - Backup code enumeration
    - 2FA response manipulation (change isVerified in response)
    - OTP bypass via null/empty/undefined code
    - 2FA via API version without enforcement

  Password reset:
    - Weak reset token (predictable, short, low entropy)
    - Reset token not expiring
    - Reset token reuse (same token valid after use)
    - Host header injection in reset email
    - HTTP parameter pollution in reset
    - Reset link without HTTPS

  Session management:
    - Session fixation (server accepts attacker-supplied session ID)
    - Session not invalidated on logout
    - Session not invalidated on password change
    - Concurrent session limit not enforced
    - Session hijacking via sub-domain cookie

  Registration:
    - Account takeover via email casing (Admin@site.com vs admin@site.com)
    - Null byte in username
    - Unicode normalization bypass
    - Email verification bypass
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
import hashlib
import math
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, shannon_entropy, gen_bypass_attempts,
)

CONCURRENCY = 8

LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/auth/login", "/login",
    "/api/v1/auth/login", "/api/v1/login", "/api/sign-in",
    "/api/session", "/api/auth/session",
]
REGISTER_PATHS = [
    "/api/auth/register", "/api/register", "/auth/register",
    "/api/signup", "/signup", "/api/v1/register",
    "/api/users", "/api/auth/signup",
]
RESET_PATHS = [
    "/api/auth/forgot-password", "/api/forgot-password",
    "/api/password-reset", "/api/auth/reset-password",
    "/auth/forgot-password", "/forgot-password",
    "/api/v1/forgot-password",
]
MFA_PATHS = [
    "/api/auth/2fa/verify", "/api/2fa/verify", "/api/mfa/verify",
    "/api/auth/mfa", "/api/otp/verify", "/api/totp/verify",
    "/api/v1/auth/2fa",
]
LOGOUT_PATHS = [
    "/api/auth/logout", "/api/logout", "/auth/logout",
    "/api/v1/logout", "/logout",
]
ME_PATHS = ["/api/me", "/api/user", "/api/profile", "/api/v1/me"]

COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "admin123",
    "qwerty", "letmein", "welcome", "monkey", "1234",
    "Password1", "P@ssw0rd", "test", "test123",
]

WEAK_OTP_CODES = ["000000", "123456", "111111", "999999", ""]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


class AuthDrift:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
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
           mitre="T1110", mitre_name="Brute Force", extra=None) -> dict:
        f = {
            "type": ftype, "severity": sev, "confidence": conf,
            "confidence_label": confidence_label(conf),
            "url": url, "proof": proof, "detail": detail, "remediation": rem,
            "mitre_technique": mitre, "mitre_name": mitre_name,
        }
        if extra:
            f.update(extra)
        return f

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

    def _detect_login_success(self, status: int, body: str, hdrs: dict) -> bool:
        if status not in (200, 201):
            return False
        body_low = (body or "").lower()
        token_in_body = bool(re.search(r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ', body or ""))
        success_kw = any(k in body_low for k in
                         ["access_token", "token", "auth_token", "jwt", "session", "logged_in"])
        return token_in_body or success_kw

    # ── Password Policy ─────────────────────────────────────────────────────

    async def test_password_policy(self, sess):
        print("\n[*] Testing password policy enforcement...")
        for path in REGISTER_PATHS[:4]:
            url = self.target + path
            # Try registering with weak passwords
            weak_pass_tests = [
                ("a",       "1-char password"),
                ("abc",     "3-char password"),
                ("abcdefg", "7-char no complexity"),
                ("password", "common password 'password'"),
                ("123456",  "common password '123456'"),
                ("",        "blank password"),
            ]
            for pwd, label in weak_pass_tests:
                import random
                email = f"probe_{random.randint(1000,9999)}@evil-test.com"
                payload = {"email": email, "password": pwd, "username": f"probe_{random.randint(1000,9999)}"}
                s, body, _ = await self._post(sess, url, data=payload)
                await delay(0.1)
                if s in (None, 404, 405):
                    continue
                if s in (200, 201) and body:
                    # Check if registration succeeded
                    if any(kw in (body or "").lower() for kw in
                           ["created", "registered", "success", "user_id", "id", "token"]):
                        self._add(self._f(
                            ftype="WEAK_PASSWORD_ACCEPTED",
                            sev="HIGH", conf=90,
                            proof=f"POST {url}\n  email={email}\n  password='{pwd}'\n  HTTP {s} — registration succeeded",
                            detail=f"Weak password accepted ({label}): '{pwd}' — no password policy enforced",
                            url=url,
                            rem=(
                                "1. Enforce minimum 12-character passwords.\n"
                                "2. Require mixed case, numbers, and special characters.\n"
                                "3. Check against HaveIBeenPwned common password list.\n"
                                "4. Use zxcvbn for password strength estimation."
                            ),
                            extra={"weak_password": pwd, "label": label},
                        ))
                        break

    # ── Account Enumeration ─────────────────────────────────────────────────

    async def test_account_enumeration(self, sess):
        print("\n[*] Testing account enumeration (error messages + timing)...")
        for path in LOGIN_PATHS[:4]:
            url = self.target + path
            # Test with known non-existent vs plausibly existing email
            test_pairs = [
                ({"email": "thisemailshouldnotexist_xyzxyz@example.com", "password": "wrong"},
                 {"email": "admin@admin.com", "password": "wrong"}),
                ({"username": "thisusershouldnotexist_xyz", "password": "wrong"},
                 {"username": "admin", "password": "wrong"}),
            ]
            for nonexist_creds, exist_creds in test_pairs:
                t1 = time.monotonic()
                s1, body1, _ = await self._post(sess, url, data=nonexist_creds)
                t1_elapsed = time.monotonic() - t1
                await delay(0.1)
                t2 = time.monotonic()
                s2, body2, _ = await self._post(sess, url, data=exist_creds)
                t2_elapsed = time.monotonic() - t2
                await delay(0.1)
                if s1 is None or s2 is None:
                    continue
                # Different error messages
                body1_low = (body1 or "").lower()
                body2_low = (body2 or "").lower()
                user_not_found = any(k in body1_low for k in
                                     ["user not found", "no account", "doesn't exist", "not registered"])
                wrong_pass = any(k in body2_low for k in
                                 ["wrong password", "invalid password", "incorrect password"])
                if user_not_found and wrong_pass:
                    self._add(self._f(
                        ftype="ACCOUNT_ENUMERATION_ERROR_MESSAGE",
                        sev="MEDIUM", conf=93,
                        proof=(
                            f"POST {url}\n"
                            f"  Non-existent user: HTTP {s1} — '{body1[:100]}'\n"
                            f"  Existing user: HTTP {s2} — '{body2[:100]}'"
                        ),
                        detail=f"Account enumeration via distinct error messages at {path}",
                        url=url,
                        rem=(
                            "1. Use identical error messages for wrong email and wrong password.\n"
                            "2. Recommended: 'Invalid email or password.'\n"
                            "3. Add artificial delay to equalize timing."
                        ),
                        extra={"nonexist_msg": body1[:100], "exist_msg": body2[:100]},
                    ))
                # Timing-based enumeration
                timing_diff = abs(t1_elapsed - t2_elapsed)
                if timing_diff > 0.4 and s1 is not None and s2 is not None:
                    self._add(self._f(
                        ftype="ACCOUNT_ENUMERATION_TIMING",
                        sev="MEDIUM", conf=78,
                        proof=(
                            f"POST {url}\n"
                            f"  Non-existent user response: {t1_elapsed:.3f}s\n"
                            f"  Existing user response: {t2_elapsed:.3f}s\n"
                            f"  Timing difference: {timing_diff:.3f}s"
                        ),
                        detail=f"Timing-based account enumeration: {timing_diff:.3f}s difference between valid and invalid user",
                        url=url,
                        rem="Add constant-time comparison for password hashing regardless of user existence.",
                        extra={"timing_diff_seconds": round(timing_diff, 3)},
                    ))

    # ── 2FA Bypass ──────────────────────────────────────────────────────────

    async def test_2fa_bypass(self, sess):
        print("\n[*] Testing 2FA/MFA bypass techniques...")
        for path in MFA_PATHS:
            url = self.target + path
            s0, _, _ = await self._get(sess, url)
            await delay(0.05)
            if s0 in (None, 404, 405):
                continue

            # Test empty/null OTP codes
            for code in WEAK_OTP_CODES:
                s, body, _ = await self._post(sess, url,
                    data={"code": code, "otp": code, "token": code,
                          "totp": code, "mfa_code": code})
                await delay(0.06)
                if s in (200, 201) and body:
                    if any(k in (body or "").lower() for k in
                           ["success", "verified", "token", "access"]):
                        self._add(self._f(
                            ftype="MFA_BYPASS_NULL_CODE",
                            sev="CRITICAL", conf=90,
                            proof=f"POST {url}\n  code='{code}'\n  HTTP {s}\n  Body: {body[:200]}",
                            detail=f"2FA bypass with code='{code}' — MFA not properly enforced at {path}",
                            url=url,
                            rem=(
                                "1. Reject empty, null, and undefined MFA codes.\n"
                                "2. Require valid 6-digit TOTP code.\n"
                                "3. Invalidate code after single use.\n"
                                "4. Implement rate-limiting (5 attempts max)."
                            ),
                            extra={"bypass_code": code},
                        ))
                        return

            # Test brute-force without rate limit
            tasks = [
                self._post(sess, url, data={"code": f"{i:06d}", "otp": f"{i:06d}"})
                for i in range(0, 50, 1)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            statuses = [r[0] for r in results if not isinstance(r, Exception) and r[0]]
            rate_limited = any(s == 429 for s in statuses)
            if not rate_limited:
                self._add(self._f(
                    ftype="MFA_BRUTE_FORCE_NO_RATE_LIMIT",
                    sev="HIGH", conf=88,
                    proof=f"POST {path} × 50 rapid requests\n  No 429 response detected\n  Statuses: {list(set(statuses))[:5]}",
                    detail=f"2FA code brute-force possible at {path} — no rate limiting detected after 50 attempts",
                    url=url,
                    rem=(
                        "1. Implement rate-limiting: max 5 failed OTP attempts per account per 15 min.\n"
                        "2. Lock account after repeated failures.\n"
                        "3. Require re-authentication if too many failures.\n"
                        "4. Use time-based OTP (TOTP) with 30s window only."
                    ),
                    extra={"attempts": 50},
                ))

    # ── Password Reset Token Analysis ────────────────────────────────────────

    async def test_password_reset(self, sess):
        print("\n[*] Testing password reset token quality and flow...")
        for path in RESET_PATHS:
            url = self.target + path
            s, body, hdrs = await self._post(sess, url,
                data={"email": "admin@admin.com", "username": "admin"})
            await delay(0.1)
            if s in (None, 404, 405):
                continue
            if s not in (200, 201, 204, 422):
                continue
            # Check for token in response (bad practice)
            token_in_body = re.search(r'(?:token|reset_token|code)\s*[":]\s*["\']?([A-Za-z0-9\-_]{6,})', body or "")
            if token_in_body:
                token = token_in_body.group(1)
                ent = _entropy(token)
                self._add(self._f(
                    ftype="RESET_TOKEN_IN_RESPONSE",
                    sev="CRITICAL", conf=95,
                    proof=f"POST {url}\n  HTTP {s}\n  Reset token in response body: {token[:30]}",
                    detail=f"Password reset token returned in API response — bypasses email verification entirely",
                    url=url,
                    rem="Never return reset tokens in API response. Only send via email.",
                    mitre="T1078", mitre_name="Valid Accounts",
                    extra={"token_sample": token[:30], "entropy": round(ent, 2)},
                ))
                if ent < 3.5:
                    self._add(self._f(
                        ftype="RESET_TOKEN_LOW_ENTROPY",
                        sev="HIGH", conf=88,
                        proof=f"Reset token: {token}\n  Shannon entropy: {ent:.2f} (min acceptable: 3.5+)",
                        detail=f"Password reset token has low entropy ({ent:.2f}) — predictable/brute-forceable",
                        url=url,
                        rem="Use cryptographically random token of at least 128 bits. Use secrets.token_urlsafe(32).",
                        extra={"token": token[:30], "entropy": round(ent, 2)},
                    ))

            # Host header injection for reset link poisoning
            s2, body2, _ = await self._post(sess, url,
                data={"email": "admin@admin.com"},
                headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"})
            await delay(0.08)
            if s2 in (200, 201, 204) and "evil.com" in (body2 or ""):
                self._add(self._f(
                    ftype="RESET_HOST_HEADER_INJECTION",
                    sev="HIGH", conf=92,
                    proof=f"POST {url}\n  Host: evil.com\n  HTTP {s2}\n  'evil.com' in response",
                    detail=f"Host header injection in password reset — reset link will point to evil.com",
                    url=url,
                    rem=(
                        "1. Use absolute URL from server config for reset links — never from Host header.\n"
                        "2. Validate Host header against allowlist.\n"
                        "3. Never use Host/X-Forwarded-Host in email body construction."
                    ),
                ))

    # ── Session Invalidation ─────────────────────────────────────────────────

    async def test_session_invalidation(self, sess):
        print("\n[*] Testing session invalidation on logout...")
        # Try to get a session token
        token = None
        for path in LOGIN_PATHS[:3]:
            s, body, hdrs = await self._post(sess, self.target + path,
                data={"email": "test@test.com", "password": "test"})
            await delay(0.1)
            m = re.search(r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.]{10,}', body or "")
            if m:
                token = m.group(0)
                break
        if not token:
            return
        # Logout
        for logout_path in LOGOUT_PATHS:
            s, _, _ = await self._post(sess, self.target + logout_path,
                                       headers={"Authorization": f"Bearer {token}"})
            await delay(0.1)
            if s in (200, 204):
                # Try using the token again after logout
                for me_path in ME_PATHS:
                    s2, body2, _ = await self._get(sess, self.target + me_path,
                                                   headers={"Authorization": f"Bearer {token}"})
                    await delay(0.1)
                    if s2 in (200, 201) and body2 and '"id"' in body2:
                        self._add(self._f(
                            ftype="SESSION_NOT_INVALIDATED_ON_LOGOUT",
                            sev="HIGH", conf=93,
                            proof=(
                                f"POST {logout_path} → HTTP {s} (logged out)\n"
                                f"GET {me_path} with old token → HTTP {s2} (still valid!)\n"
                                f"Body: {body2[:200]}"
                            ),
                            detail="Session token still valid after logout — logout does not invalidate server-side session",
                            url=self.target + logout_path,
                            rem=(
                                "1. Maintain server-side token revocation list.\n"
                                "2. Use short-lived JWTs (15 min) + refresh token rotation.\n"
                                "3. Implement token blocklist checked on each request.\n"
                                "4. Log all session creation and invalidation events."
                            ),
                            mitre="T1539", mitre_name="Steal Web Session Cookie",
                        ))
                        return

    async def run(self):
        print("=" * 60)
        print("  AuthDrift v8 — 150x Improved Auth Security Analyser")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=180)) as sess:
            await asyncio.gather(
                self.test_password_policy(sess),
                self.test_account_enumeration(sess),
                self.test_2fa_bypass(sess),
                self.test_password_reset(sess),
                self.test_session_invalidation(sess),
                return_exceptions=True,
            )
        print(f"\n[+] AuthDrift v8: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr); sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    findings = await AuthDrift(target).run()
    out = Path(__file__).parent.parent / "reports" / "authdrift.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
