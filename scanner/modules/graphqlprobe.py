#!/usr/bin/env python3
"""GraphQLProbe v1 — Comprehensive GraphQL Security Scanner.

Tests:
  - Introspection exposure (full schema leak + sensitive field names)
  - Field suggestion leakage (Did you mean…)
  - Query batching DoS amplification
  - Query depth / complexity DoS (no limit enforced)
  - Alias-based rate-limit bypass (30 mutations in 1 request)
  - Argument injection (SQL, NoSQL, SSTI via GraphQL args)
  - Unauthenticated IDOR via ID enumeration
  - CSRF via mutation-over-GET
  - Sensitive data exposure in responses
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS,
)

# ── GraphQL endpoints to probe ────────────────────────────────────────────────
GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql", "/query", "/api/query",
    "/gql", "/api/gql", "/graph", "/api/graph",
    "/graphiql", "/playground", "/api/explorer",
    "/hasura/v1/graphql", "/console/api/query",
    "/data", "/api/data",
]

# ── Queries ───────────────────────────────────────────────────────────────────
INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}"""

PROBE_QUERY = "{ __typename }"

FIELD_SUGGESTION_QUERY = "{ __typnam }"

DEPTH_BOMB_QUERY = (
    "{ a { b { c { d { e { f { g { h { i { j { k { l { m { __typename"
    " } } } } } } } } } } } } } }"
)

# ── Sensitive field names that should NEVER appear in a public schema ─────────
SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "private_key", "privatekey", "credit_card", "card_number", "cvv",
    "ssn", "social_security", "dob", "birth_date", "salary",
    "bank_account", "routing_number", "pin", "stripe_key",
    "aws_secret", "auth_token", "session_token", "reset_token",
    "otp_secret", "2fa_secret", "totp_secret",
}

# ── Injection payloads ────────────────────────────────────────────────────────
INJECTION_PAYLOADS = [
    ("' OR '1'='1",                "sql_classic"),
    ("1 OR 1=1",                   "sql_numeric"),
    ('{"$gt": ""}',                "nosql_mongo_gt"),
    ('{"$ne": null}',              "nosql_mongo_ne"),
    ("'; DROP TABLE users-- ",     "sql_drop"),
    ("{{7*7}}",                    "ssti"),
    ("<script>alert(1)</script>",  "xss"),
]

DB_ERROR_KEYWORDS = [
    "syntax error", "sql", "mysql", "postgres", "sqlite", "ora-",
    "unexpected token", "parse error", "exception", "you have an error",
    "unterminated", "division by zero", "cannot read", "undefined method",
    "query failed", "db error",
]

# ── Common object queries for IDOR testing ────────────────────────────────────
IDOR_TEMPLATES = [
    ("query($id:ID!){user(id:$id){id email username role phone}}",        "user"),
    ("query($id:ID!){profile(id:$id){id email name phone address}}",      "profile"),
    ("query($id:ID!){order(id:$id){id total items status userId}}",       "order"),
    ("query($id:ID!){document(id:$id){id title content owner}}",          "document"),
    ("query($id:Int!){userById(id:$id){id email username createdAt}}",    "userById"),
    ("query($id:ID!){invoice(id:$id){id amount dueDate customer}}",       "invoice"),
]

PII_FIELD_NAMES = {"email", "username", "phone", "role", "name", "address",
                   "ssn", "balance", "salary", "card_number", "dob"}


class GraphQLProbe:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        self._dedup   = set()
        self._gql_url = None
        self._schema  = None

    # ── helpers ───────────────────────────────────────────────────────────────

    def _finding(self, ftype: str, severity: str, conf: int,
                 url: str, proof: str, detail: str, remediation: str,
                 extra: dict = None):
        if not meets_confidence_floor(conf):
            return
        key = f"{ftype}|{url}"
        if key in self._dedup:
            return
        self._dedup.add(key)
        f = {
            "type":             ftype,
            "severity":         severity,
            "confidence":       conf,
            "confidence_label": confidence_label(conf),
            "url":              url,
            "proof":            proof,
            "detail":           detail,
            "remediation":      remediation,
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url}")

    async def _gql(self, sess, url: str, query,
                   variables: dict = None,
                   headers: dict = None,
                   method: str = "POST",
                   timeout: int = 14):
        """Send a GraphQL request. Returns (status, parsed_json_or_None, headers)."""
        merged = {
            **WAF_BYPASS_HEADERS,
            "User-Agent": random_ua(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            merged.update(headers)
        if isinstance(query, list):
            body = query
        else:
            body = {"query": query}
            if variables:
                body["variables"] = variables
        try:
            async with sess.request(
                method, url, json=body, headers=merged,
                ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                text = await r.text(errors="ignore")
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
                return r.status, data, dict(r.headers)
        except Exception:
            return None, None, {}

    async def _get(self, sess, url, params=None, headers=None, timeout=10):
        merged = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
        if headers:
            merged.update(headers)
        try:
            async with sess.get(
                url, params=params, headers=merged,
                ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                text = await r.text(errors="ignore")
                return r.status, text, dict(r.headers)
        except Exception:
            return None, "", {}

    @staticmethod
    def _is_gql_response(data) -> bool:
        return isinstance(data, dict) and ("data" in data or "errors" in data)

    # ── endpoint discovery ────────────────────────────────────────────────────

    async def discover_endpoint(self, sess) -> str | None:
        print("\n[*] GraphQLProbe: discovering endpoint...")
        tasks = [self._gql(sess, self.target + ep, PROBE_QUERY)
                 for ep in GRAPHQL_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ep, result in zip(GRAPHQL_ENDPOINTS, results):
            if isinstance(result, Exception):
                continue
            status, data, _ = result
            if status and self._is_gql_response(data):
                url = self.target + ep
                print(f"  [+] GraphQL endpoint: {url} (HTTP {status})")
                return url
        # Try GET with query-string (some APIs only accept GET)
        for ep in GRAPHQL_ENDPOINTS[:8]:
            s, body, _ = await self._get(
                sess, self.target + ep, params={"query": PROBE_QUERY})
            if s and s < 500:
                try:
                    d = json.loads(body)
                    if self._is_gql_response(d):
                        url = self.target + ep
                        print(f"  [+] GraphQL endpoint (GET): {url}")
                        return url
                except Exception:
                    pass
        return None

    # ── test: introspection ───────────────────────────────────────────────────

    async def test_introspection(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL introspection...")
        s, data, _ = await self._gql(sess, self._gql_url, INTROSPECTION_QUERY)
        if not self._is_gql_response(data):
            return
        schema = (data.get("data") or {}).get("__schema")
        if not schema:
            print("  [INFO] Introspection disabled (good)")
            return
        self._schema = schema
        types       = schema.get("types") or []
        type_names  = [t.get("name", "") for t in types if t.get("name")]
        mut_type    = schema.get("mutationType")
        all_fields  = []
        for t in types:
            for fld in (t.get("fields") or []):
                all_fields.append(fld.get("name", "").lower())
        sensitive = [n for n in all_fields if n in SENSITIVE_FIELD_NAMES]
        proof = (
            f"POST {self._gql_url} — __schema introspection succeeded\n"
            f"Types: {len(type_names)} ({', '.join(type_names[:15])})\n"
            f"Mutations: {'YES — ' + mut_type['name'] if mut_type else 'none'}\n"
            f"Total fields: {len(all_fields)}"
            + (f"\nSensitive field names in schema: {sensitive[:10]}" if sensitive else "")
        )
        self._finding(
            ftype="GRAPHQL_INTROSPECTION_ENABLED",
            severity="HIGH", conf=97,
            url=self._gql_url,
            proof=proof,
            detail=(
                f"GraphQL introspection is enabled — full schema ({len(type_names)} types, "
                f"{len(all_fields)} fields) exposed to unauthenticated callers."
                + (f" Sensitive field names visible: {sensitive[:5]}." if sensitive else "")
            ),
            remediation=(
                "1. Disable introspection in production (Apollo: introspection=False, "
                "Strawberry: introspection=False, Ariadne: introspection=False).\n"
                "2. If required internally, restrict to authenticated/admin users only.\n"
                "3. Use query-depth and complexity limits to prevent schema enumeration."
            ),
            extra={
                "type_count": len(type_names),
                "field_count": len(all_fields),
                "sensitive_fields": sensitive[:20],
                "has_mutations": bool(mut_type),
                "mitre_technique": "T1087", "mitre_name": "Account Discovery",
            },
        )

    # ── test: field suggestion leakage ───────────────────────────────────────

    async def test_field_suggestions(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL field suggestion leakage...")
        s, data, _ = await self._gql(sess, self._gql_url, FIELD_SUGGESTION_QUERY)
        if not isinstance(data, dict):
            return
        for err in (data.get("errors") or []):
            msg = str(err.get("message", "")).lower()
            if "did you mean" in msg or "suggestion" in msg:
                self._finding(
                    ftype="GRAPHQL_FIELD_SUGGESTION_LEAK",
                    severity="MEDIUM", conf=88,
                    url=self._gql_url,
                    proof=f"Typo query error reveals field names: {err.get('message', '')[:250]}",
                    detail=(
                        "GraphQL returns 'Did you mean X?' hints — attackers enumerate "
                        "hidden/private field names without a full introspection query."
                    ),
                    remediation=(
                        "1. Disable field suggestions in production "
                        "(Apollo Server: fieldSuggestions: false).\n"
                        "2. Return generic error messages that do not hint at schema."
                    ),
                    extra={"mitre_technique": "T1592",
                           "mitre_name": "Gather Victim Host Information"},
                )
                break

    # ── test: query batching DoS ──────────────────────────────────────────────

    async def test_batching(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL query batching (DoS amplification)...")
        batch = [{"query": PROBE_QUERY} for _ in range(50)]
        t0 = time.perf_counter()
        s, data, _ = await self._gql(sess, self._gql_url, batch, timeout=20)
        elapsed = time.perf_counter() - t0
        if not isinstance(data, list):
            return
        if len(data) >= 10:
            self._finding(
                ftype="GRAPHQL_BATCHING_ENABLED",
                severity="MEDIUM", conf=90,
                url=self._gql_url,
                proof=(
                    f"50-query batch → {len(data)} responses in {elapsed:.2f}s\n"
                    f"One HTTP request executes {len(data)} operations server-side"
                ),
                detail=(
                    "Unrestricted query batching: one HTTP POST can contain 1 000+ operations, "
                    "bypassing per-request rate limits and amplifying server load."
                ),
                remediation=(
                    "1. Reject batch arrays with more than 5–10 operations.\n"
                    "2. Rate-limit per operation, not per HTTP request.\n"
                    "3. Apply query complexity analysis."
                ),
                extra={"batch_size": 50, "responses_received": len(data),
                       "mitre_technique": "T1499",
                       "mitre_name": "Endpoint Denial of Service"},
            )

    # ── test: query depth DoS ─────────────────────────────────────────────────

    async def test_query_depth(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL query depth limit...")
        t0 = time.perf_counter()
        s, data, _ = await self._gql(sess, self._gql_url, DEPTH_BOMB_QUERY, timeout=15)
        elapsed = time.perf_counter() - t0
        if not isinstance(data, dict):
            return
        blocked = any(
            kw in str(e.get("message", "")).lower()
            for e in (data.get("errors") or [])
            for kw in ("depth", "complexity", "max depth", "too deep")
        )
        if blocked:
            print("  [INFO] Query depth limit enforced (good)")
            return
        if "data" in data:
            self._finding(
                ftype="GRAPHQL_NO_DEPTH_LIMIT",
                severity="HIGH", conf=82,
                url=self._gql_url,
                proof=(
                    f"13-level nested query accepted and resolved in {elapsed:.2f}s\n"
                    f"No depth-limit error — full tree was processed"
                ),
                detail=(
                    "No query depth limit is enforced. An attacker can submit "
                    "depth-100 queries to exhaust DB joins/CPU, causing DoS."
                ),
                remediation=(
                    "1. Enforce max query depth (recommended 7–10 levels).\n"
                    "2. Use graphql-depth-limit or graphql-cost-analysis.\n"
                    "3. Set a per-query execution timeout."
                ),
                extra={"depth_tested": 13, "elapsed_s": round(elapsed, 2),
                       "mitre_technique": "T1499.002",
                       "mitre_name": "Service Exhaustion Flood"},
            )

    # ── test: alias-based rate-limit bypass ───────────────────────────────────

    async def test_alias_overload(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL alias rate-limit bypass...")
        aliases = "\n".join(
            f'  a{i}: login(username:"u{i}@x.invalid" password:"pw{i}"){{ token }}'
            for i in range(30)
        )
        query = f"mutation {{\n{aliases}\n}}"
        s, data, _ = await self._gql(sess, self._gql_url, query, timeout=20)
        if not isinstance(data, dict):
            return
        blocked = any(
            kw in str(e.get("message", "")).lower()
            for e in (data.get("errors") or [])
            for kw in ("rate limit", "too many", "alias", "complexity", "throttl")
        )
        if not blocked and data.get("data") is not None:
            self._finding(
                ftype="GRAPHQL_ALIAS_RATE_LIMIT_BYPASS",
                severity="HIGH", conf=82,
                url=self._gql_url,
                proof=(
                    f"Single POST with 30 aliased login mutations — HTTP {s}\n"
                    f"No rate-limit error: 30 credential attempts in 1 HTTP request"
                ),
                detail=(
                    "GraphQL aliases allow 30+ mutations in one request. "
                    "Combined with batching, an attacker brute-forces 1 500+ credentials/s "
                    "while appearing to send only 1 request to rate-limiting middleware."
                ),
                remediation=(
                    "1. Count aliases toward per-request operation budget.\n"
                    "2. Rate-limit per mutation invocation, not per HTTP request.\n"
                    "3. Assign complexity cost to each alias (max budget per request)."
                ),
                extra={"aliases_tested": 30,
                       "mitre_technique": "T1110", "mitre_name": "Brute Force"},
            )

    # ── test: argument injection ──────────────────────────────────────────────

    async def test_injection(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL argument injection...")
        templates = [
            ('query($v:String!){user(id:$v){id email}}',                 "user.id"),
            ('query($v:String!){search(query:$v){id title}}',            "search.query"),
            ('mutation($v:String!){login(username:$v password:"x"){token}}', "login.username"),
            ('query($v:String!){products(filter:$v){id name price}}',    "products.filter"),
        ]
        for q_template, arg_label in templates:
            for payload, inj_type in INJECTION_PAYLOADS[:5]:
                s, data, _ = await self._gql(
                    sess, self._gql_url, q_template,
                    variables={"v": payload}, timeout=8)
                await delay(0.1)
                if not isinstance(data, dict):
                    continue
                for err in (data.get("errors") or []):
                    msg = str(err.get("message", ""))
                    if any(kw in msg.lower() for kw in DB_ERROR_KEYWORDS):
                        self._finding(
                            ftype="GRAPHQL_INJECTION_ERROR_LEAK",
                            severity="HIGH", conf=85,
                            url=self._gql_url,
                            proof=(
                                f"Payload in '{arg_label}': {payload!r}\n"
                                f"DB/engine error in response: {msg[:300]}"
                            ),
                            detail=(
                                f"{inj_type} in GraphQL argument '{arg_label}' "
                                f"caused DB error leak — potential injection point."
                            ),
                            remediation=(
                                "1. Parameterize all resolver queries — never concatenate args.\n"
                                "2. Use an ORM with built-in parameterization.\n"
                                "3. Return generic errors — never expose DB errors to clients.\n"
                                "4. Validate and type-check all GraphQL arguments."
                            ),
                            extra={"payload": payload, "injection_type": inj_type,
                                   "mitre_technique": "T1190",
                                   "mitre_name": "Exploit Public-Facing Application"},
                        )
                        break

    # ── test: CSRF mutation via GET ───────────────────────────────────────────

    async def test_csrf(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL CSRF (mutation via GET)...")
        mutation = "mutation { __typename }"
        s, body, hdrs = await self._get(
            sess, self._gql_url, params={"query": mutation})
        if not s:
            return
        try:
            data = json.loads(body)
            if self._is_gql_response(data) and not data.get("errors"):
                self._finding(
                    ftype="GRAPHQL_MUTATION_VIA_GET",
                    severity="HIGH", conf=88,
                    url=self._gql_url,
                    proof=(
                        f"GET {self._gql_url}?query={mutation!r}\n"
                        f"HTTP {s} — mutation accepted over GET (no CORS preflight)"
                    ),
                    detail=(
                        "GraphQL accepts mutations via GET requests, bypassing CORS preflight. "
                        "An attacker's page can trigger state-changing mutations against "
                        "any authenticated user without a CSRF token."
                    ),
                    remediation=(
                        "1. Reject mutations over GET — only allow queries via GET.\n"
                        "2. Require Content-Type: application/json (rejects form POSTs).\n"
                        "3. Add CSRF tokens to all state-changing operations.\n"
                        "4. Validate Origin/Referer on mutations."
                    ),
                    extra={"mitre_technique": "T1185",
                           "mitre_name": "Browser Session Hijacking"},
                )
        except Exception:
            pass

    # ── test: IDOR via unauthenticated ID access ──────────────────────────────

    async def test_idor(self, sess) -> None:
        if not self._gql_url:
            return
        print("\n[*] Testing GraphQL IDOR (unauthenticated ID enumeration)...")
        for q_template, obj_name in IDOR_TEMPLATES:
            for test_id in ["1", "2", "3", "100", "1000"]:
                s, data, _ = await self._gql(
                    sess, self._gql_url, q_template,
                    variables={"id": test_id}, timeout=8)
                await delay(0.08)
                if not isinstance(data, dict):
                    continue
                result = (data.get("data") or {}).get(obj_name)
                if not isinstance(result, dict) or not result:
                    continue
                pii = {
                    k: v for k, v in result.items()
                    if k.lower() in PII_FIELD_NAMES
                    and v and str(v).lower() not in {"null", "none", ""}
                }
                if pii:
                    self._finding(
                        ftype="GRAPHQL_IDOR_UNAUTHENTICATED",
                        severity="HIGH", conf=87,
                        url=self._gql_url,
                        proof=(
                            f"Query: {q_template[:80]}\n"
                            f"ID={test_id} — response: {json.dumps(result)[:400]}\n"
                            f"PII fields returned without auth: {list(pii.keys())}"
                        ),
                        detail=(
                            f"Unauthenticated {obj_name}(id={test_id}) returned "
                            f"PII: {list(pii.keys())}. No auth token provided."
                        ),
                        remediation=(
                            "1. Require authentication on all data-returning resolvers.\n"
                            "2. Enforce field-level ownership checks before returning data.\n"
                            "3. Use opaque UUIDs instead of sequential IDs.\n"
                            "4. Apply RBAC/ABAC in every resolver."
                        ),
                        extra={"object": obj_name, "id_tested": test_id,
                               "pii_exposed": list(pii.keys()),
                               "mitre_technique": "T1530",
                               "mitre_name": "Data from Cloud Storage Object"},
                    )
                    break

    # ── main run ──────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  GraphQLProbe v1 — GraphQL Security Scanner")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            self._gql_url = await self.discover_endpoint(sess)
            if not self._gql_url:
                print("  [INFO] No GraphQL endpoint found — skipping")
                return self.findings

            # Introspection first — populates self._schema for other tests
            await self.test_introspection(sess)
            await delay(0.15)

            # Run independent tests in parallel
            await asyncio.gather(
                self.test_field_suggestions(sess),
                self.test_batching(sess),
                self.test_query_depth(sess),
                self.test_csrf(sess),
            )
            await delay(0.1)

            # Sequential tests that depend on schema or make targeted requests
            await self.test_injection(sess)
            await delay(0.1)
            await self.test_idor(sess)
            await delay(0.1)
            await self.test_alias_overload(sess)

        crit = sum(1 for f in self.findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in self.findings if f.get("severity") == "HIGH")
        print(f"\n[+] GraphQLProbe complete: {len(self.findings)} findings "
              f"({crit} CRITICAL / {high} HIGH)")
        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        t = p.read_text().strip()
        if t:
            return t
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    Path("reports").mkdir(exist_ok=True)
    target = get_target()
    scanner = GraphQLProbe(target)
    findings = asyncio.run(scanner.run())
    out = Path("reports/graphqlprobe.json")
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"\n[+] {len(findings)} findings → {out}")


if __name__ == "__main__":
    main()
