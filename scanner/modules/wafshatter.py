#!/usr/bin/env python3
"""WAFShatter v6 — Zero-False-Positive WAF/CDN Bypass & Auth Rate-Limit Tester.

Key rules:
- WAF bypass: only flag when payload reaches backend AND response differs structurally
- Rate limit: only flag when an ACTUAL auth endpoint responds to login attempts without 429
- Server disclosure: INFO level only (not exploitable alone)
- Every finding has verbatim HTTP evidence
"""
import asyncio, aiohttp, json, re, socket, sys, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, MITRE_MAP,
)

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "body":    ["cloudflare", "cf-ray", "Sorry, you have been blocked"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-akamai-request-id"],
        "body":    ["Reference #18.", "The page you are trying to access is blocked"],
    },
    "Imperva": {
        "headers": ["x-iinfo", "incap_ses", "visid_incap"],
        "body":    ["incapsula", "/_Incapsula_Resource"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-pop", "x-amz-cf-id"],
        "body":    ["aws waf"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body":    ["Access Denied - Sucuri Website Firewall"],
    },
    "ModSecurity": {
        "headers": ["x-modsecurity-action"],
        "body":    ["mod_security", "modsec", "406 Not Acceptable"],
    },
    "F5 BIG-IP": {
        "body":    ["The requested URL was rejected", "Your support ID is"],
    },
    "Cloudfront": {
        "headers": ["x-amz-cf-id", "via"],
        "body":    ["CloudFront"],
    },
    "Varnish": {
        "headers": ["x-varnish"],
        "body":    ["varnish"],
    },
}

BYPASS_PAYLOADS = [
    ("IP Spoofing: X-Forwarded-For: 127.0.0.1",        {"X-Forwarded-For": "127.0.0.1"}),
    ("IP Spoofing: CF-Connecting-IP: 127.0.0.1",       {"CF-Connecting-IP": "127.0.0.1"}),
    ("IP Spoofing: True-Client-IP: 127.0.0.1",         {"True-Client-IP": "127.0.0.1"}),
    ("IP Spoofing: X-Real-IP: 127.0.0.1",              {"X-Real-IP": "127.0.0.1"}),
    ("IP Spoofing: X-Remote-Addr: 127.0.0.1",          {"X-Remote-Addr": "127.0.0.1"}),
    ("Double XFF: 127.0.0.1, 127.0.0.1",               {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"}),
    ("RFC7239 Forwarded: for=127.0.0.1",                {"Forwarded": "for=127.0.0.1"}),
    ("Host override: localhost",                        {"X-Forwarded-Host": "localhost"}),
    ("Host override: 127.0.0.1",                        {"X-Host": "127.0.0.1"}),
    ("Path override: X-Original-URL: /admin",           {"X-Original-URL": "/admin"}),
    ("Path override: X-Rewrite-URL: /",                 {"X-Rewrite-URL": "/"}),
    ("Method override: X-HTTP-Method-Override: GET",    {"X-HTTP-Method-Override": "GET"}),
    ("Dev mode header: X-Dev-Mode: true",               {"X-Dev-Mode": "true"}),
    ("WAF disable: X-WAF-Bypass: 1",                    {"X-WAF-Bypass": "1"}),
    ("Null origin",                                     {"Origin": "null"}),
]

AUTH_CANDIDATES = [
    "/api/auth/login", "/api/login", "/login", "/auth/login",
    "/api/v1/auth/login", "/api/v1/login", "/api/users/login", "/api/session",
]


class WAFShatter:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.findings = []
        self.waf_type = None
        self.is_behind_waf = False

    async def _get(self, sess, url, headers=None, method="GET", data=None):
        merged = {"User-Agent": random_ua(), "Accept": "*/*"}
        if headers:
            merged.update(headers)
        try:
            kw = dict(headers=merged, ssl=False,
                      timeout=aiohttp.ClientTimeout(total=15),
                      allow_redirects=False)
            if data:
                kw["data"] = data
            async with sess.request(method, url, **kw) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    async def fingerprint_waf(self, sess):
        print("\n[*] Fingerprinting WAF/CDN...")
        s, body, hdrs = await self._get(sess, self.target)
        if s is None:
            return
        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}
        body_lower = (body or "").lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0
            signals = []
            for h in sigs.get("headers", []):
                if h.lower() in hdrs_lower:
                    score += 3; signals.append(f"header:{h}")
            for kw in sigs.get("body", []):
                if kw.lower() in body_lower:
                    score += 2; signals.append(f"body:{kw}")
            if score >= 3:
                self.waf_type = waf_name
                self.is_behind_waf = True
                self.findings.append({
                    "type": "WAF_CDN_DETECTED",
                    "severity": "INFO",
                    "confidence": min(98, score * 12),
                    "confidence_label": confidence_label(min(98, score * 12)),
                    "url": self.target,
                    "waf": waf_name,
                    "signals": signals,
                    "proof": f"Matched {len(signals)} signals: {', '.join(signals[:5])}",
                    "detail": f"{waf_name} WAF/CDN detected ({len(signals)} signals matched)",
                    "remediation": "Ensure WAF rules are up-to-date. Test bypass resilience regularly.",
                })
                print(f"  [INFO] WAF: {waf_name} (score={score})")
                break

        # Server disclosure — INFO only (not independently exploitable)
        for h in ["server", "x-powered-by", "x-aspnet-version"]:
            val = hdrs_lower.get(h)
            if val:
                self.findings.append({
                    "type": "SERVER_VERSION_DISCLOSURE",
                    "severity": "INFO",
                    "confidence": 97,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "header": h,
                    "value": val,
                    "proof": f"{h}: {val}",
                    "detail": f"Server version leaked via {h} — aids CVE lookup by attackers",
                    "remediation": f"Suppress: server_tokens off (Nginx) / ServerTokens Prod (Apache) / app.disable('x-powered-by') (Express)",
                })
                print(f"  [INFO] Server disclosure: {h}: {val}")

    async def test_bypasses(self, sess):
        print("\n[*] Testing WAF bypass techniques...")
        if not self.is_behind_waf:
            print("  [SKIP] No WAF detected")
            return

        # Use an XSS payload to trigger WAF, check what happens
        trigger = "/?x=%3Cscript%3Ealert(1)%3C/script%3E"
        s_blocked, body_blocked, _ = await self._get(sess, self.target + trigger)
        await delay()
        if s_blocked is None or s_blocked == 200:
            print("  [INFO] WAF did not block test XSS payload — rule coverage unclear")
            return

        print(f"  [*] WAF blocks at HTTP {s_blocked} — testing {len(BYPASS_PAYLOADS)} bypass headers")

        for name, extra_hdrs in BYPASS_PAYLOADS:
            s, body, hdrs = await self._get(sess, self.target + trigger, headers=extra_hdrs)
            await delay(0.15)
            if s is None:
                continue
            # Bypass = WAF no longer returns its block response AND we get a structural response
            if s not in (s_blocked, 429, 503) and s in (200, 201, 301, 302):
                # Verify body is different (not the same WAF block page)
                if (body or "")[:100] == (body_blocked or "")[:100]:
                    continue
                self.findings.append({
                    "type": "WAF_BYPASS_CONFIRMED",
                    "severity": "HIGH",
                    "confidence": 88,
                    "confidence_label": "High",
                    "url": self.target + trigger,
                    "technique": name,
                    "headers_used": extra_hdrs,
                    "blocked_status": s_blocked,
                    "bypass_status": s,
                    "proof": (
                        f"Baseline: {self.target}{trigger} → HTTP {s_blocked} (WAF block)\n"
                        f"With [{name}] headers: → HTTP {s} (bypass successful)\n"
                        f"Response body differs from WAF block page"
                    ),
                    "detail": f"WAF bypass: {name} caused WAF to pass XSS payload (HTTP {s_blocked}→{s})",
                    "remediation": (
                        "Update WAF rules to inspect these headers. "
                        "Never trust X-Forwarded-For or similar for access-control decisions. "
                        "Validate bypass-header rules at the WAF level, not application level."
                    ),
                    "mitre_technique": "T1562.001",
                    "mitre_name": "Impair Defenses: Disable or Modify Tools",
                })
                print(f"  [HIGH] BYPASS CONFIRMED: {name} → HTTP {s}")

    async def measure_rate_limit(self, sess):
        print("\n[*] Rate limit test on auth endpoints...")

        # Step 1: Find a real auth endpoint
        auth_url = None
        for candidate in AUTH_CANDIDATES:
            url = self.target + candidate
            s, body, hdrs = await self._get(
                sess, url, method="POST",
                data=json.dumps({"email": "probe@test.invalid", "password": "wrongprobe"}),
                headers={"Content-Type": "application/json"})
            await delay(0.3)
            # 404/405 = endpoint does not exist; anything else = found
            if s is not None and s not in (404, 405, 501):
                auth_url = url
                print(f"  [*] Auth endpoint confirmed: {candidate} (HTTP {s})")
                break

        if not auth_url:
            print("  [*] No auth endpoint discovered — rate limit test skipped")
            return

        # Step 2: Send 20 login attempts and watch for 429 or blocking
        responses = []
        for i in range(20):
            s, body, hdrs = await self._get(
                sess, auth_url, method="POST",
                data=json.dumps({"email": f"user{i}@probe.invalid",
                                 "password": f"wrongpass{i}_ratelimit"}),
                headers={"Content-Type": "application/json"})
            await delay(0.1)
            if s is None:
                break
            responses.append(s)
            rl = hdrs.get("x-ratelimit-remaining", hdrs.get("X-RateLimit-Remaining", ""))
            if s == 429 or (rl and str(rl).isdigit() and int(rl) < 5):
                self.findings.append({
                    "type": "RATE_LIMIT_ACTIVE",
                    "severity": "INFO",
                    "confidence": 98,
                    "confidence_label": "Confirmed",
                    "url": auth_url,
                    "triggered_at": i + 1,
                    "proof": f"HTTP {s} (rate limit) triggered after {i+1} POST requests to {auth_url}",
                    "detail": f"Rate limiting is active — triggered at request #{i+1}",
                    "remediation": "Rate limiting confirmed. Verify threshold ≤10 attempts/min.",
                })
                print(f"  [INFO] Rate limit triggered at request #{i+1}")
                return

        # Step 3: Only flag if auth logic responses prove brute-force is possible
        auth_responses = [s for s in responses if s in (200, 400, 401, 422)]
        if len(auth_responses) >= 10:
            self.findings.append({
                "type": "NO_RATE_LIMIT_ON_AUTH_ENDPOINT",
                "severity": "HIGH",
                "confidence": 90,
                "confidence_label": "High",
                "url": auth_url,
                "total_requests": len(responses),
                "auth_responses": len(auth_responses),
                "status_codes_seen": sorted(set(responses)),
                "proof": (
                    f"{len(auth_responses)}/{len(responses)} POST requests to {auth_url}\n"
                    f"received auth responses {sorted(set(auth_responses))}\n"
                    f"with ZERO 429 or rate-limit headers — automated credential attacks not blocked"
                ),
                "detail": (
                    f"No rate limiting on {auth_url}: {len(auth_responses)} consecutive "
                    f"login attempts processed without any blocking or throttling"
                ),
                "remediation": (
                    "1. Enforce ≤10 failed attempts per minute per IP and per account.\n"
                    "2. Return HTTP 429 with Retry-After header on threshold breach.\n"
                    "3. Implement CAPTCHA after 5 consecutive failures.\n"
                    "4. Alert on bursts of >20 failed logins from one IP within 60 seconds."
                ),
                "mitre_technique": "T1110",
                "mitre_name": "Brute Force",
            })
            print(f"  [HIGH] No rate limit: {len(auth_responses)}/20 auth responses, zero 429")
        else:
            print(f"  [INFO] Insufficient auth signals to confirm brute-force risk ({auth_responses})")

    async def discover_origin(self, sess):
        print("\n[*] Hunting for real origin IP in headers...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        for hdr in ["x-real-server","x-backend","x-origin-server","x-upstream","via","x-served-by"]:
            val = hdrs_lower.get(hdr, "")
            ip = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', val)
            if ip and not ip.group(1).startswith(("10.","172.","192.168.","127.","169.")):
                self.findings.append({
                    "type": "ORIGIN_IP_LEAKED",
                    "severity": "HIGH",
                    "confidence": 87,
                    "confidence_label": "High",
                    "url": self.target,
                    "header": hdr,
                    "origin_ip": ip.group(1),
                    "proof": f"Response header {hdr}: {val} — public IP visible, bypasses CDN protection",
                    "detail": f"Real origin IP {ip.group(1)} leaked via {hdr} — attacker can bypass WAF/CDN",
                    "remediation": "Strip backend IP headers in CDN/proxy config: proxy_hide_header (Nginx).",
                    "mitre_technique": "T1590",
                    "mitre_name": "Gather Victim Network Information",
                })
                print(f"  [HIGH] Origin IP leaked: {hdr}: {ip.group(1)}")

    async def audit_http_methods(self, sess):
        print("\n[*] Testing dangerous HTTP methods...")
        for method in ["TRACE", "PUT", "DELETE", "PROPFIND", "MKCOL"]:
            s, body, hdrs = await self._get(sess, self.target, method=method)
            await delay(0.15)
            if s is None:
                continue
            if method == "TRACE" and s == 200 and body and "TRACE" in body:
                self.findings.append({
                    "type": "HTTP_TRACE_ENABLED",
                    "severity": "MEDIUM",
                    "confidence": 97,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "method": "TRACE",
                    "proof": f"HTTP TRACE returned 200 — request headers reflected in response body:\n{body[:300]}",
                    "detail": "TRACE method enabled — XST (Cross-Site Tracing) possible, bypasses HttpOnly cookie protection",
                    "remediation": "Disable TRACE: TraceEnable Off (Apache) / if ($request_method = TRACE) return 405; (Nginx)",
                    "mitre_technique": "T1557",
                    "mitre_name": "Adversary-in-the-Middle",
                })
                print(f"  [MEDIUM] HTTP TRACE enabled!")
            elif method in ("PUT", "DELETE") and s not in (403, 405, 404, 501):
                self.findings.append({
                    "type": "DANGEROUS_HTTP_METHOD_ACCEPTED",
                    "severity": "HIGH",
                    "confidence": 82,
                    "confidence_label": "High",
                    "url": self.target,
                    "method": method,
                    "status": s,
                    "proof": f"HTTP {method} {self.target} → {s} (expected 403/405)",
                    "detail": f"Dangerous HTTP method {method} accepted — may allow file upload/deletion",
                    "remediation": f"Block {method} at the web server level unless intentionally used.",
                    "mitre_technique": "T1190",
                    "mitre_name": "Exploit Public-Facing Application",
                })
                print(f"  [HIGH] Dangerous method {method} accepted (HTTP {s})")

    async def run(self):
        print("=" * 60)
        print("  WAFShatter v6 — Zero-False-Positive WAF & Rate-Limit Tester")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=120)) as sess:
            await self.fingerprint_waf(sess)
            await self.test_bypasses(sess)
            await self.measure_rate_limit(sess)
            await self.discover_origin(sess)
            await self.audit_http_methods(sess)
        print(f"\n[+] WAFShatter: {len(self.findings)} findings")
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
    findings = asyncio.run(WAFShatter(target).run())
    with open("reports/wafshatter.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/wafshatter.json")


if __name__ == "__main__":
    main()
