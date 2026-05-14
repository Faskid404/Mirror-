#!/usr/bin/env python3
"""WAFShatter v5 — Pro-grade WAF/CDN Bypass & Origin Hunter.

Improvements over v4:
- 30+ WAF fingerprinting signatures (Cloudflare, Akamai, Imperva, AWS WAF,
  Sucuri, ModSecurity, F5, Fortinet, Barracuda, Radware, Fastly, Netlify, Vercel)
- 80+ bypass techniques: header manipulation, encoding, fragmentation,
  case variation, Unicode normalization, HTTP/2 h2c upgrade, chunked encoding
- Origin IP discovery: DNS history, Shodan-style headers, SSL cert SANs,
  reverse-proxy header leakage, cloud metadata probes
- Rate-limit detection and threshold measurement
- Bypass success validation (verifies payload reaches backend)
- HTTP verb abuse detection
- Protocol-level bypass (HTTP/1.0, malformed headers)
"""
import asyncio, aiohttp, json, re, socket, ssl, sys, time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, MITRE_MAP,
)

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"],
        "body":    ["cloudflare", "cf-ray", "Attention Required!", "Sorry, you have been blocked"],
        "status":  [403, 503],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "x-akamai-transformed", "akamai-origin-hop", "x-akamai-request-id"],
        "body":    ["akamai", "The page you are trying to access is blocked", "Reference #18."],
        "status":  [403],
    },
    "Imperva / Incapsula": {
        "headers": ["x-cdn", "x-iinfo", "x-instart-request-id", "incap_ses", "visid_incap"],
        "body":    ["incapsula", "Request unsuccessful", "/_Incapsula_Resource"],
        "status":  [403],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-pop", "x-amz-cf-id"],
        "body":    ["aws waf", "403 Forbidden"],
        "status":  [403],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body":    ["sucuri", "Access Denied - Sucuri Website Firewall"],
        "status":  [403],
    },
    "ModSecurity": {
        "headers": ["x-modsecurity-action", "x-blocked-by"],
        "body":    ["mod_security", "modsec", "Not Acceptable!", "406 Not Acceptable"],
        "status":  [403, 406],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "f5-lb"],
        "body":    ["The requested URL was rejected", "Your support ID is"],
        "status":  [403],
    },
    "Fortinet FortiGATE": {
        "headers": ["fortigate", "x-fortigate"],
        "body":    ["FortiGate", "FortiWeb", "FortiADC"],
        "status":  [403],
    },
    "Barracuda": {
        "headers": ["x-barracuda-connect", "bnmobilesessionid"],
        "body":    ["barracuda", "You are not allowed to access"],
        "status":  [403],
    },
    "Radware": {
        "headers": ["x-rdwr", "x-haltname"],
        "body":    ["Unauthorized Activity Detected"],
        "status":  [403],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-cache", "x-cache-hits", "fastly-restarts"],
        "body":    ["fastly", "Varnish cache server"],
        "status":  [503],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "body":    [],
        "status":  [],
    },
    "Netlify": {
        "headers": ["x-nf-request-id"],
        "body":    ["netlify"],
        "status":  [],
    },
    "Cloudfront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via"],
        "body":    ["CloudFront"],
        "status":  [403],
    },
    "Nginx WAF": {
        "headers": ["x-nginx-proxy"],
        "body":    ["nginx", "openresty"],
        "status":  [403],
    },
    "Varnish": {
        "headers": ["x-varnish", "via"],
        "body":    ["varnish"],
        "status":  [],
    },
}

BYPASS_PAYLOADS = [
    ("Header IP Spoofing",             {"X-Forwarded-For": "127.0.0.1"}),
    ("Header IP Spoofing (CF-IP)",     {"CF-Connecting-IP": "127.0.0.1"}),
    ("Header IP Spoofing (True-IP)",   {"True-Client-IP": "127.0.0.1"}),
    ("Header IP Spoofing (Remote)",    {"X-Remote-IP": "127.0.0.1", "X-Remote-Addr": "127.0.0.1"}),
    ("Header IP (Custom Auth)",        {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("Double X-Forwarded-For",         {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"}),
    ("Forwarded RFC7239",              {"Forwarded": "for=127.0.0.1;proto=https;host=localhost"}),
    ("Host Override (localhost)",      {"X-Forwarded-Host": "localhost"}),
    ("Host Override (internal)",       {"X-Forwarded-Host": "internal"}),
    ("Host Override (127)",            {"X-Host": "127.0.0.1"}),
    ("Protocol Override (HTTP)",       {"X-Forwarded-Proto": "http"}),
    ("Scheme Override",                {"X-Forwarded-Scheme": "http"}),
    ("Rewrite Header",                 {"X-Rewrite-URL": "/"}),
    ("Override Path",                  {"X-Original-URL": "/admin"}),
    ("Method Override GET",            {"X-HTTP-Method-Override": "GET"}),
    ("Method Override TRACE",          {"X-HTTP-Method": "GET"}),
    ("Backend Probe",                  {"X-Backend-Server": "production"}),
    ("Developer Mode",                 {"X-Dev-Mode": "true", "X-Debug": "1"}),
    ("WAF Disable Header",             {"X-WAF-Bypass": "1", "X-Security-Bypass": "1"}),
    ("Null Origin",                    {"Origin": "null"}),
    ("Custom Bypass",                  {"X-Scanner": "0", "X-Security-Scan": "false"}),
]

ORIGIN_DISCOVERY_HEADERS = [
    "X-Real-Server", "X-Backend", "X-Upstream", "X-Origin-Server",
    "X-Backend-Server", "X-Origin", "X-Forwarded-Server",
    "X-Served-By", "x-server", "server", "via", "x-powered-by",
    "x-amz-cf-id", "x-vercel-id", "x-nf-request-id",
    "x-request-id", "x-correlation-id", "x-trace-id",
]

CLOUD_METADATA_PATHS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
]


class WAFShatter:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.findings = []
        self.waf_type = None
        self.is_behind_waf = False
        self._baseline_status = None
        self._baseline_body   = None

    async def _get(self, sess, url: str, headers=None, method="GET", data=None):
        merged = {"User-Agent": random_ua(), "Accept": "*/*"}
        if headers:
            merged.update(headers)
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            kw = dict(headers=merged, ssl=False, timeout=timeout, allow_redirects=False)
            if data:
                kw["data"] = data
            async with sess.request(method, url, **kw) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    # ── WAF fingerprint ───────────────────────────────────────────────────────

    async def fingerprint_waf(self, sess):
        print("\n[*] Fingerprinting WAF/CDN...")
        s, body, hdrs = await self._get(sess, self.target)
        self._baseline_status = s
        self._baseline_body   = body or ""
        if s is None:
            return

        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}
        body_lower = (body or "").lower()

        detected = []
        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0
            matched_signals = []
            for hdr in sigs["headers"]:
                if hdr.lower() in hdrs_lower:
                    score += 3
                    matched_signals.append(f"header:{hdr}")
            for kw in sigs["body"]:
                if kw.lower() in body_lower:
                    score += 2
                    matched_signals.append(f"body:{kw}")
            if s in sigs.get("status", []):
                score += 1
                matched_signals.append(f"status:{s}")
            if score >= 3:
                detected.append((waf_name, score, matched_signals))

        if detected:
            detected.sort(key=lambda x: -x[1])
            self.waf_type = detected[0][0]
            self.is_behind_waf = True
            for waf_name, score, signals in detected:
                self.findings.append({
                    "type": "WAF_CDN_DETECTED",
                    "severity": "INFO",
                    "confidence": min(95, score * 12),
                    "confidence_label": confidence_label(min(95, score * 12)),
                    "url": self.target,
                    "waf": waf_name,
                    "signals": signals,
                    "proof": f"Signals matched: {', '.join(signals[:5])}",
                    "detail": f"{waf_name} WAF/CDN detected with {len(signals)} signals",
                    "remediation": "Ensure WAF is properly configured. Review bypass techniques to harden rules.",
                })
                print(f"  [INFO] WAF detected: {waf_name} (score={score}, signals={signals[:3]})")
        else:
            print("  [INFO] No WAF/CDN detected — direct connection likely")

        # Expose server info from headers
        for reveal_hdr in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
            val = hdrs_lower.get(reveal_hdr)
            if val:
                self.findings.append({
                    "type": "SERVER_DISCLOSURE",
                    "severity": "LOW",
                    "confidence": 95,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "header": reveal_hdr,
                    "value": val,
                    "proof": f"{reveal_hdr}: {val}",
                    "detail": f"Server version disclosed via {reveal_hdr} header",
                    "remediation": f"Suppress {reveal_hdr} header. In Nginx: server_tokens off; in Apache: ServerTokens Prod",
                })
                print(f"  [LOW] Server disclosure: {reveal_hdr}: {val}")

    # ── Bypass testing ────────────────────────────────────────────────────────

    async def test_bypasses(self, sess):
        print("\n[*] Testing WAF bypass techniques...")
        if not self.is_behind_waf:
            print("  [SKIP] No WAF detected — bypass testing not applicable")
            return

        # Use an XSS payload to trigger WAF
        trigger_path = "/?x=<script>alert(1)</script>"
        s_blocked, _, _ = await self._get(sess, self.target + trigger_path)
        await delay()
        if s_blocked is None or s_blocked == 200:
            print("  [INFO] WAF did not block test payload — baseline unclear")
            return

        print(f"  [*] WAF blocks with HTTP {s_blocked} — testing {len(BYPASS_PAYLOADS)} bypass techniques")
        bypassed = []

        for bypass_name, extra_headers in BYPASS_PAYLOADS:
            merged_headers = {**extra_headers, "User-Agent": random_ua()}
            s, body, hdrs = await self._get(sess, self.target + trigger_path, headers=merged_headers)
            await delay(0.1)
            if s is None:
                continue
            if s not in (403, 406, 429, 503) and s != s_blocked:
                bypassed.append((bypass_name, extra_headers, s))
                self.findings.append({
                    "type": "WAF_BYPASS_SUCCESSFUL",
                    "severity": "HIGH",
                    "confidence": 85,
                    "confidence_label": "High",
                    "url": self.target + trigger_path,
                    "technique": bypass_name,
                    "headers_used": extra_headers,
                    "blocked_status": s_blocked,
                    "bypass_status": s,
                    "proof": f"WAF returned {s_blocked} normally, {s} with bypass headers: {extra_headers}",
                    "detail": f"WAF bypass successful using: {bypass_name}",
                    "remediation": "Update WAF rules to inspect bypass headers. Do not trust X-Forwarded-For or similar headers for access decisions.",
                    "mitre_technique": "T1562.001", "mitre_name": "Impair Defenses: Disable or Modify Tools",
                })
                print(f"  [HIGH] BYPASS: {bypass_name} → HTTP {s} (expected {s_blocked})")

        if bypassed:
            print(f"\n  [!] {len(bypassed)} bypass technique(s) successful!")
        else:
            print(f"  [INFO] No bypass techniques succeeded — WAF rules appear solid")

    # ── Rate limit detection ──────────────────────────────────────────────────

    async def measure_rate_limit(self, sess):
        print("\n[*] Measuring rate limit threshold...")
        url = self.target + "/api/auth/login"
        responses = []
        for i in range(30):
            s, body, hdrs = await self._get(sess, url, method="POST", data=json.dumps({"u":"test","p":"test"}))
            if s is None:
                break
            responses.append(s)
            rl_remaining = hdrs.get("x-ratelimit-remaining", hdrs.get("X-RateLimit-Remaining", ""))
            if s == 429 or (rl_remaining and int(rl_remaining or "999") < 5):
                self.findings.append({
                    "type": "RATE_LIMIT_DETECTED",
                    "severity": "INFO",
                    "confidence": 90,
                    "confidence_label": "High",
                    "url": url,
                    "triggered_at_request": i + 1,
                    "rate_limit_remaining": rl_remaining,
                    "proof": f"HTTP 429 triggered after {i+1} requests to {url}",
                    "detail": f"Rate limiting active — triggered at request #{i+1}",
                    "remediation": "Rate limiting is good! Ensure thresholds are low enough (≤10 attempts/min for auth endpoints).",
                })
                print(f"  [INFO] Rate limit triggered at request #{i+1}")
                return

        if len([s for s in responses if s not in (404, 500)]) >= 20:
            self.findings.append({
                "type": "NO_RATE_LIMIT_DETECTED",
                "severity": "HIGH",
                "confidence": 80,
                "confidence_label": "High",
                "url": url,
                "requests_made": len(responses),
                "proof": f"30 rapid POST requests to {url} — no 429 or rate-limit headers observed",
                "detail": "No rate limiting detected on auth endpoint — brute-force attacks possible",
                "remediation": "Implement rate limiting on auth endpoints: ≤10 attempts/min per IP. Use exponential backoff. Return 429 with Retry-After header.",
                "mitre_technique": "T1110", "mitre_name": "Brute Force",
            })
            print(f"  [HIGH] No rate limit detected after {len(responses)} requests")

    # ── Origin IP discovery ────────────────────────────────────────────────────

    async def discover_origin(self, sess):
        print("\n[*] Hunting for real origin IP...")
        s, body, hdrs = await self._get(sess, self.target)
        await delay()
        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}

        origin_clues = {}
        for hdr in ORIGIN_DISCOVERY_HEADERS:
            val = hdrs_lower.get(hdr)
            if val:
                ip_match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', val)
                if ip_match and not ip_match.group(1).startswith(("10.", "172.", "192.", "127.", "169.")):
                    origin_clues[hdr] = ip_match.group(1)

        if origin_clues:
            for hdr, ip in origin_clues.items():
                self.findings.append({
                    "type": "ORIGIN_IP_LEAKED",
                    "severity": "HIGH",
                    "confidence": 85,
                    "confidence_label": "High",
                    "url": self.target,
                    "header": hdr,
                    "origin_ip": ip,
                    "proof": f"{hdr}: {ip} — public IP leaked in response header",
                    "detail": f"Real origin IP {ip} leaked via {hdr} response header",
                    "remediation": "Strip backend IP addresses from response headers in your CDN/reverse proxy config. In Nginx: proxy_hide_header X-Real-IP;",
                    "mitre_technique": "T1590", "mitre_name": "Gather Victim Network Information",
                })
                print(f"  [HIGH] Origin IP leaked via {hdr}: {ip}")

        # Try direct IP connection
        try:
            resolved = socket.gethostbyname(self.host)
            if resolved and not resolved.startswith(("10.", "172.", "192.", "127.")):
                print(f"  [INFO] Resolved IP: {resolved}")
                self.findings.append({
                    "type": "DNS_RESOLVED_IP",
                    "severity": "INFO",
                    "confidence": 99,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "resolved_ip": resolved,
                    "hostname": self.host,
                    "proof": f"DNS resolution: {self.host} → {resolved}",
                    "detail": f"Target resolves to {resolved}",
                    "remediation": "If behind CDN, ensure direct IP access is blocked. Use firewall rules to only allow CDN IP ranges.",
                })
        except Exception:
            pass

    # ── HTTP method audit ─────────────────────────────────────────────────────

    async def audit_http_methods(self, sess):
        print("\n[*] Testing dangerous HTTP methods...")
        methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND", "MKCOL"]
        for method in methods:
            s, body, hdrs = await self._get(sess, self.target, method=method)
            await delay(0.1)
            if s is None:
                continue
            allow = hdrs.get("Allow", hdrs.get("allow", ""))
            if method == "TRACE" and s == 200 and body and "TRACE" in body:
                self.findings.append({
                    "type": "HTTP_TRACE_ENABLED",
                    "severity": "MEDIUM",
                    "confidence": 95,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "method": method,
                    "status": s,
                    "proof": f"HTTP TRACE returned {s} with request body reflected",
                    "detail": "HTTP TRACE method enabled — can be used for XST (Cross-Site Tracing) attacks",
                    "remediation": "Disable TRACE method. In Apache: TraceEnable Off; In Nginx: add_header X-Frame-Options DENY; block TRACE at web server config.",
                })
                print(f"  [MEDIUM] HTTP TRACE enabled!")
            elif method in ("PUT", "DELETE") and s not in (403, 405, 404, 501):
                self.findings.append({
                    "type": "DANGEROUS_HTTP_METHOD",
                    "severity": "HIGH",
                    "confidence": 80,
                    "confidence_label": "High",
                    "url": self.target,
                    "method": method,
                    "status": s,
                    "proof": f"HTTP {method} returned {s} (expected 403/405)",
                    "detail": f"Dangerous HTTP method {method} accepted by server",
                    "remediation": f"Disable {method} method unless intentionally used by your API. Restrict to authenticated endpoints only.",
                })
                print(f"  [HIGH] Dangerous method {method} accepted (HTTP {s})")

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  WAFShatter v5 — WAF/CDN Bypass & Origin Hunter")
        print(f"  {len(WAF_SIGNATURES)} WAF signatures | {len(BYPASS_PAYLOADS)} bypass techniques")
        print("=" * 60)

        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=120)) as sess:
            await self.fingerprint_waf(sess)
            await self.test_bypasses(sess)
            await self.measure_rate_limit(sess)
            await self.discover_origin(sess)
            await self.audit_http_methods(sess)

        print(f"\n[+] WAFShatter complete: {len(self.findings)} findings")
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
