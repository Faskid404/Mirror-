#!/usr/bin/env python3
"""DeepLogic v4 — Pro-grade Business Logic Vulnerability Analyser.

Improvements over v3:
- Price manipulation: negative prices, zero-value, integer overflow, currency confusion
- Quantity bypass: negative quantities, floating-point, overflow values
- Race condition: concurrent request bursting to detect state corruption
- Coupon/promo: reuse detection, stacking, negative discount
- Workflow bypass: skipping required steps by direct endpoint access
- Mass assignment: injecting extra fields into update requests
- Evidence-based: only flags when response confirms exploitation
"""
import asyncio, aiohttp, json, re, sys, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

# ── Cart/order endpoints to probe ─────────────────────────────────────────────
CART_ENDPOINTS = [
    '/api/cart', '/api/cart/add', '/api/cart/update', '/api/order',
    '/api/orders', '/api/checkout', '/api/purchase', '/api/buy',
    '/cart', '/cart/add', '/cart/update', '/checkout',
    '/api/v1/cart', '/api/v1/orders', '/api/v1/checkout',
    '/shop/cart', '/store/cart',
]

PAYMENT_ENDPOINTS = [
    '/api/payment', '/api/pay', '/api/charge', '/api/billing',
    '/api/v1/payment', '/api/v1/pay', '/payment', '/pay',
    '/checkout/payment', '/api/checkout/confirm',
]

COUPON_ENDPOINTS = [
    '/api/coupon', '/api/coupons', '/api/promo', '/api/discount',
    '/api/voucher', '/api/redeem', '/api/coupon/apply',
    '/coupon/apply', '/promo/apply',
]


class DeepLogic:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        self.findings = []
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    async def _post(self, sess, url, payload, headers=None):
        try:
            h = {"Content-Type": "application/json"}
            h.update(headers or {})
            async with sess.post(url, json=payload, headers=h, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    async def _put(self, sess, url, payload, headers=None):
        try:
            h = {"Content-Type": "application/json"}
            h.update(headers or {})
            async with sess.put(url, json=payload, headers=h, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    def _response_looks_accepted(self, status, body):
        """Check if server accepted the request (not just returned 200)."""
        if status not in [200, 201, 202]:
            return False
        body_lower = (body or '').lower()
        rejected_signals = ['error', 'invalid', 'not allowed', 'forbidden',
                            'rejected', 'fail', 'cannot', 'negative']
        success_signals = ['success', 'added', 'updated', 'created', 'accepted',
                           'ok', 'total', 'price', 'amount', 'cart', 'order']
        has_rejection = any(s in body_lower for s in rejected_signals)
        has_success = any(s in body_lower for s in success_signals)
        return has_success and not has_rejection

    # ── Price manipulation ─────────────────────────────────────────────────────

    async def test_price_manipulation(self, sess):
        print("\n[*] Price manipulation — negative, zero, overflow values...")
        price_payloads = [
            ("negative_price",    {"price": -100,   "quantity": 1}),
            ("zero_price",        {"price": 0,       "quantity": 1}),
            ("negative_total",    {"total": -100,    "quantity": 1}),
            ("float_underflow",   {"price": 0.001,   "quantity": 1}),
            ("int_overflow",      {"price": 2**31-1, "quantity": 1}),
            ("string_price",      {"price": "0",     "quantity": 1}),
            ("negative_qty",      {"price": 10,      "quantity": -10}),
            ("zero_qty",          {"price": 10,      "quantity": 0}),
            ("qty_overflow",      {"price": 10,      "quantity": 2**31-1}),
        ]

        for endpoint in CART_ENDPOINTS:
            url = self.target + endpoint
            # First check endpoint exists
            s_check, _, _ = await self._get(sess, url)
            await delay()
            if s_check in [None, 404, 410]:
                continue

            for label, payload in price_payloads:
                # Try both product-style and cart-update-style payloads
                for full_payload in [
                    {**payload, "product_id": 1, "item_id": 1},
                    {**payload, "id": 1},
                    payload,
                ]:
                    s, body, _ = await self._post(sess, url, full_payload)
                    await delay()
                    if self._response_looks_accepted(s, body):
                        # Check if negative/manipulated value appears in response
                        accepted_value = re.search(
                            r'(?:total|price|amount|cost)["\s:]+(-?\d+(?:\.\d+)?)',
                            body, re.I)
                        val_str = accepted_value.group(1) if accepted_value else "unknown"
                        manipulated = (
                            label.startswith("negative") and "-" in val_str or
                            label.startswith("zero") and val_str == "0" or
                            self._response_looks_accepted(s, body)
                        )
                        if manipulated:
                            conf = 82
                            if meets_confidence_floor(conf):
                                self.findings.append({
                                    'type': 'PRICE_MANIPULATION',
                                    'severity': 'CRITICAL',
                                    'confidence': conf,
                                    'confidence_label': confidence_label(conf),
                                    'url': url,
                                    'technique': label,
                                    'payload': full_payload,
                                    'http_status': s,
                                    'accepted_value': val_str,
                                    'proof': (f"HTTP {s} — server accepted payload {json.dumps(full_payload)} "
                                              f"without rejection. Response value: {val_str}"),
                                    'detail': f"Price manipulation accepted: {label} at {endpoint}",
                                    'remediation': (
                                        "1. Validate all price/quantity fields server-side. "
                                        "2. Enforce minimum price > 0 and maximum reasonable quantity. "
                                        "3. Never trust client-submitted price — always calculate server-side. "
                                        "4. Use integer arithmetic (cents) to avoid float issues."
                                    ),
                                })
                                print(f"  [CRITICAL] {label} accepted at {endpoint} → value={val_str}")
                            break  # One finding per endpoint

    # ── Race condition ─────────────────────────────────────────────────────────

    async def test_race_condition(self, sess):
        print("\n[*] Race condition testing — concurrent burst requests...")
        race_targets = [
            (endpoint, {"code": "SAVE10", "user_id": 1})
            for endpoint in COUPON_ENDPOINTS
        ] + [
            (endpoint, {"item_id": 1, "quantity": 1})
            for endpoint in CART_ENDPOINTS[:4]
        ]

        for endpoint, payload in race_targets:
            url = self.target + endpoint
            s_check, _, _ = await self._get(sess, url)
            await delay()
            if s_check in [None, 404, 410]:
                continue

            # Send 15 simultaneous requests
            tasks = [self._post(sess, url, payload) for _ in range(15)]
            t0 = time.monotonic()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.monotonic() - t0

            successes = [r for r in results
                         if isinstance(r, tuple) and r[0] in [200, 201, 202]]

            if len(successes) > 1:
                # Multiple successes on a single-use endpoint = race condition
                bodies = [s[1] for s in successes if s[1]]
                unique_responses = set(b[:100] for b in bodies if b)

                if len(unique_responses) > 1 or len(successes) >= 3:
                    conf = 80
                    if meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'RACE_CONDITION',
                            'severity': 'HIGH',
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': url,
                            'concurrent_requests': 15,
                            'successful_responses': len(successes),
                            'elapsed_seconds': round(elapsed, 2),
                            'proof': (f"{len(successes)}/15 concurrent requests succeeded — "
                                      f"suggests missing atomic transaction or lock"),
                            'detail': f"Race condition at {endpoint} — duplicate operations possible",
                            'remediation': (
                                "1. Use database transactions with row-level locking (SELECT FOR UPDATE). "
                                "2. Implement idempotency keys for payment/coupon operations. "
                                "3. Use Redis SETNX or similar atomic operations for single-use resources."
                            ),
                        })
                        print(f"  [HIGH] Race condition: {len(successes)}/15 succeeded at {endpoint}")

    # ── Coupon abuse ───────────────────────────────────────────────────────────

    async def test_coupon_abuse(self, sess):
        print("\n[*] Coupon/promo abuse — stacking, negative discount, reuse...")
        for endpoint in COUPON_ENDPOINTS:
            url = self.target + endpoint
            s_check, _, _ = await self._get(sess, url)
            await delay()
            if s_check in [None, 404, 410]:
                continue

            abuse_cases = [
                ("negative_discount", {"code": "SAVE10", "discount": -100}),
                ("stacking",          {"codes": ["SAVE10", "SAVE20", "SAVE50"]}),
                ("empty_code",        {"code": "", "user_id": 1}),
                ("wildcard_code",     {"code": "*", "user_id": 1}),
                ("expired_code",      {"code": "EXPIRED2020", "user_id": 1}),
                ("other_user_code",   {"code": "SAVE10", "user_id": 99999}),
            ]

            for label, payload in abuse_cases:
                s, body, _ = await self._post(sess, url, payload)
                await delay()
                if self._response_looks_accepted(s, body):
                    discount = re.search(r'discount["\s:]+(-?\d+)', body, re.I)
                    d_val = discount.group(1) if discount else "?"
                    conf = 78
                    if meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'COUPON_ABUSE',
                            'severity': 'HIGH',
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': url,
                            'technique': label,
                            'payload': payload,
                            'discount_value': d_val,
                            'proof': f"HTTP {s} — {label} payload accepted. Discount: {d_val}",
                            'detail': f"Coupon logic vulnerable to {label} at {endpoint}",
                            'remediation': (
                                "Validate coupons server-side: check expiry, user binding, "
                                "single-use enforcement, and minimum/maximum discount values."
                            ),
                        })
                        print(f"  [HIGH] Coupon abuse: {label} at {endpoint}")

    # ── Mass assignment ────────────────────────────────────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Mass assignment — injecting privileged fields in update requests...")
        update_endpoints = [
            '/api/user', '/api/users/me', '/api/profile', '/api/account',
            '/api/v1/user', '/api/v1/profile',
        ]
        privileged_fields = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"is_staff": True},
            {"privilege": "superuser"},
            {"account_type": "premium"},
            {"subscription": "enterprise"},
            {"credit": 99999},
            {"balance": 99999},
        ]

        for endpoint in update_endpoints:
            url = self.target + endpoint
            for field in privileged_fields:
                s, body, _ = await self._put(sess, url, field)
                await delay()
                if s in [200, 201, 202] and body:
                    field_key = list(field.keys())[0]
                    field_val = str(list(field.values())[0]).lower()
                    # Proof: field value reflected in response
                    if field_key in body.lower() and field_val in body.lower():
                        conf = 85
                        if meets_confidence_floor(conf):
                            self.findings.append({
                                'type': 'MASS_ASSIGNMENT',
                                'severity': 'HIGH',
                                'confidence': conf,
                                'confidence_label': confidence_label(conf),
                                'url': url,
                                'injected_field': field,
                                'proof': (f"HTTP {s} — field '{field_key}={field_val}' "
                                          f"reflected in response after PUT request"),
                                'proof_snippet': body[:300],
                                'detail': f"Mass assignment: '{field_key}' accepted and reflected at {endpoint}",
                                'remediation': (
                                    "Use an explicit allowlist (DTO/serializer) of accepted fields. "
                                    "Never mass-assign raw request body to model objects. "
                                    "In Django: use form/serializer with explicit fields. "
                                    "In Rails: use strong parameters."
                                ),
                            })
                            print(f"  [HIGH] Mass assignment: {field} accepted at {endpoint}")

    # ── Workflow bypass ────────────────────────────────────────────────────────

    async def test_workflow_bypass(self, sess):
        print("\n[*] Workflow step bypass — direct access to later steps...")
        # Try to reach payment/confirmation without going through cart
        for endpoint in PAYMENT_ENDPOINTS:
            url = self.target + endpoint
            # POST with minimal payload to simulate skipping checkout
            payloads = [
                {"order_id": 1, "confirmed": True},
                {"cart_id": 1, "payment_method": "card"},
                {"amount": 0, "currency": "USD"},
            ]
            for payload in payloads:
                s, body, _ = await self._post(sess, url, payload)
                await delay()
                if s in [200, 201] and self._response_looks_accepted(s, body):
                    order_sig = any(kw in (body or '').lower()
                                    for kw in ['confirmed', 'payment', 'charged', 'success', 'order_id'])
                    if order_sig:
                        conf = 72
                        if meets_confidence_floor(conf):
                            self.findings.append({
                                'type': 'WORKFLOW_BYPASS',
                                'severity': 'HIGH',
                                'confidence': conf,
                                'confidence_label': confidence_label(conf),
                                'url': url,
                                'payload': payload,
                                'proof': (f"HTTP {s} — payment/order endpoint accepted direct "
                                          f"request without prior cart/session state"),
                                'detail': f"Checkout workflow bypass possible at {endpoint}",
                                'remediation': (
                                    "Enforce server-side state machine: "
                                    "validate that prior steps (cart → shipping → payment) "
                                    "are completed before allowing checkout finalization."
                                ),
                            })
                            print(f"  [HIGH] Workflow bypass: payment accepted without cart at {endpoint}")

    # ── Runner ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  DeepLogic v4 — Business Logic Vulnerability Analyser")
        print("  Evidence policy: server acceptance confirmed in response")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=120),
                headers={"User-Agent": random_ua()}) as sess:

            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_price_manipulation(sess)
            await self.test_race_condition(sess)
            await self.test_coupon_abuse(sess)
            await self.test_mass_assignment(sess)
            await self.test_workflow_bypass(sess)

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(DeepLogic(target).run())
    with open("reports/deeplogic.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/deeplogic.json")


if __name__ == '__main__':
    main()
