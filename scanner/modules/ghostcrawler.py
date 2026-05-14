#!/usr/bin/env python3
"""GhostCrawler v6 — Zero-False-Positive Attack Surface Discovery.

Rules:
- NEVER flag 401/403/302 — those prove protection exists
- Only flag HTTP 200/201/204 with ≥100 bytes of real content on sensitive paths
- Body-leak patterns require exact regex match in response body
- GraphQL introspection: only flag when __schema actually returned
- All findings carry a verbatim proof snippet from the response
"""
import asyncio, aiohttp, json, re, sys, time, hashlib
from pathlib import Path
from urllib.parse import urlparse, urljoin

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS, shannon_entropy, MITRE_MAP,
)

# ── Wordlist ────────────────────────────────────────────────────────────────────
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/internal", "/api/private",
    "/api/debug", "/api/dev", "/api/admin", "/api/graphql", "/graphql",
    "/graphiql", "/swagger", "/swagger-ui", "/swagger.json", "/openapi.json",
    "/api-docs", "/v1", "/v2", "/v3",
    "/api/auth", "/api/auth/login", "/api/login", "/api/me", "/api/users",
    "/admin", "/admin/", "/administration", "/admin/login", "/admin/dashboard",
    "/admin/users", "/admin/config", "/management", "/internal", "/backoffice",
    "/config", "/configuration", "/setup", "/debug", "/debug/vars",
    "/health", "/healthz", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/httptrace", "/actuator/loggers",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/backup", "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    "/config.json", "/config.yaml", "/appsettings.json", "/web.config",
    "/phpinfo.php", "/info.php", "/shell.php", "/test.php",
    "/phpmyadmin", "/pma", "/adminer.php", "/wp-admin", "/wp-login.php",
    "/wp-json/wp/v2/users", "/h2-console", "/jolokia", "/jolokia/list",
    "/console", "/terminal", "/exec", "/upload", "/uploads", "/files",
    "/export", "/reports", "/analytics", "/logs",
]

SENSITIVE_KEYWORDS = [
    "admin","debug","config","backup",".env","secret",".git",
    "swagger","openapi","graphql","actuator","phpinfo","shell",
    "dump","passwd","shadow","console","h2-console","jolokia",
    "adminer","phpmyadmin","terminal","exec","export","database",".sql",
]

# Patterns that constitute real data leaks
BODY_LEAK_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\'\']?([^\s"\'\']\{4,\})', "PASSWORD_IN_RESPONSE", "CRITICAL"),
    (r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\'\']?([A-Za-z0-9\-_]\{20,\})', "API_KEY_IN_RESPONSE", "CRITICAL"),
    (r'AKIA[0-9A-Z]\{16\}', "AWS_ACCESS_KEY_EXPOSED", "CRITICAL"),
    (r'(?:aws_secret|aws_access_key)[_-]?(?:id)?\s*[:=]\s*["\'\']?([A-Za-z0-9+/]\{40\})', "AWS_SECRET_KEY_EXPOSED", "CRITICAL"),
    (r'sk_live_[0-9A-Za-z]\{24,\}', "STRIPE_LIVE_KEY_EXPOSED", "CRITICAL"),
    (r'ghp_[A-Za-z0-9]\{36\}', "GITHUB_TOKEN_EXPOSED", "CRITICAL"),
    (r'eyJ[A-Za-z0-9_-]\{20,\}\.[A-Za-z0-9_-]\{10,\}\.[A-Za-z0-9_-]\{10,\}', "JWT_TOKEN_EXPOSED", "HIGH"),
    (r'"(?:email|username|user_name)"\s*:\s*"([^"@]\{2,\}@[^"]\{2,\})"', "PII_EMAIL_IN_RESPONSE", "HIGH"),
    (r'(?:mysql_connect|mysqli_|pg_connect|sqlite3_|ORA-\d\{4,\})', "DATABASE_ERROR_LEAK", "HIGH"),
    (r'(?:mongodb://|postgres://|mysql://|redis://|amqp://)[^\s"\'\']\{8,\}', "DB_CONNECTION_STRING", "CRITICAL"),
    (r'(?:stack\s+trace|traceback\s+\(most recent call\)|at com\.|at org\.|at java\.|NullPointerException)', "STACK_TRACE_LEAK", "MEDIUM"),
    (r'(?:private_key|private key|-----BEGIN (?:RSA|EC|PRIVATE))', "PRIVATE_KEY_EXPOSED", "CRITICAL"),
]


class GhostCrawler:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname
        self.findings = []
        self.seen_urls: set = set()
        self.found_endpoints: list = []
        self._sem = asyncio.Semaphore(10)

    async def _get(self, sess, url: str, headers=None):
        merged = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua()}
        if headers:
            merged.update(headers)
        try:
            async with self._sem:
                async with sess.get(
                    url, headers=merged, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=12),
                    allow_redirects=False,
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
        except Exception:
            return None, None, {}

    async def crawl_robots(self, sess):
        print("\n[*] Parsing robots.txt...")
        status, body, _ = await self._get(sess, self.target + "/robots.txt")
        if status != 200 or not body:
            return []
        paths = []
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                p = line.split(":", 1)[1].strip()
                if p and p not in ("/", ""):
                    paths.append(p)
        return paths

    async def parse_sitemap(self, sess, url: str, depth=0):
        if depth > 3:
            return
        status, body, _ = await self._get(sess, url)
        if status != 200 or not body:
            return
        locs = re.findall(r'<loc>\s*(.*?)\s*</loc>', body, re.I)
        for loc in locs[:200]:
            parsed = urlparse(loc)
            if parsed.hostname == self.host:
                self.found_endpoints.append(parsed.path)

    async def probe_endpoint(self, sess, path: str, baseline_hashes: set):
        url = self.target + path
        if url in self.seen_urls:
            return
        self.seen_urls.add(url)

        status, body, hdrs = await self._get(sess, url)
        await delay(0.05, 0.05)
        if status is None:
            return

        # Baseline dedup — generic 404 bodies
        if body:
            body_hash = hashlib.md5(body[:500].encode(errors="ignore")).hexdigest()
            if body_hash in baseline_hashes:
                return

        # ── CRITICAL FALSE-POSITIVE FILTER ──────────────────────────────────
        # 401 / 403 / 302 = server is ACTIVELY PROTECTING this path.
        # That is correct security behaviour and must NEVER be flagged.
        # Only report endpoints that are genuinely open (no auth required).
        if status not in (200, 201, 204):
            return

        content_type = hdrs.get("Content-Type", hdrs.get("content-type", "")).lower()
        body_size = len(body or "")
        body_lower = (body or "").lower()

        is_sensitive = any(kw in path.lower() for kw in SENSITIVE_KEYWORDS)

        # Sensitive paths with tiny/empty bodies are soft-404s returning 200 — skip
        if is_sensitive and body_size < 100:
            return

        # Generic 200 endpoints only reported if they look like real app content
        if not is_sensitive and body_size < 500:
            return

        severity   = "HIGH"   if is_sensitive else "INFO"
        confidence = 93       if is_sensitive else 65

        self.found_endpoints.append(path)
        self.findings.append({
            "type": "SENSITIVE_PATH_OPEN" if is_sensitive else "ENDPOINT_DISCOVERED",
            "severity": severity,
            "confidence": confidence,
            "confidence_label": confidence_label(confidence),
            "url": url,
            "path": path,
            "status": status,
            "content_type": content_type,
            "response_size": body_size,
            "proof": (
                f"HTTP {status} at {path} — {body_size} bytes returned "
                f"with no authentication required\n"
                f"Content-Type: {content_type}\n"
                f"Body preview: {(body or '')[:200].strip()}"
            ),
            "detail": (
                f"Sensitive path publicly accessible without auth: {path}"
                if is_sensitive else
                f"Open endpoint: {path} (HTTP {status})"
            ),
            "remediation": (
                "Require authentication before serving this endpoint. "
                "Verify no sensitive data is exposed."
            ),
            "mitre_technique": "T1590.001",
            "mitre_name": "Gather Victim Network Information: IP Addresses",
        })
        print(f"  [{severity}] {status} {path} ({body_size}b)")

        # Deep body leak scan
        if body and status == 200:
            await self._check_body_leaks(path, url, body)

    async def _check_body_leaks(self, path, url, body):
        for pattern, ftype, severity in BODY_LEAK_PATTERNS:
            m = re.search(pattern, body, re.I)
            if m:
                snippet = m.group(0)[:120]
                self.findings.append({
                    "type": ftype,
                    "severity": severity,
                    "confidence": 95,
                    "confidence_label": "Confirmed",
                    "url": url,
                    "path": path,
                    "proof": f"Pattern matched in HTTP 200 response body:\n  {snippet}",
                    "detail": f"{ftype.replace('_', ' ').title()} detected at {path}",
                    "remediation": "Remove sensitive data from responses immediately. Rotate any exposed credentials.",
                    "mitre_technique": "T1552.001",
                    "mitre_name": "Unsecured Credentials: Credentials In Files",
                })
                print(f"  [CRITICAL] {ftype} at {path}")
                break

    async def extract_js_endpoints(self, sess):
        print("\n[*] Scanning JavaScript bundles for hidden endpoints...")
        js_urls = set()
        status, body, _ = await self._get(sess, self.target + "/")
        if body:
            for m in re.finditer(r'src=["\'\']([^\'\'"<>]+\.js[^\'\'"<>]*)["\'\']', body, re.I):
                full = urljoin(self.target, m.group(1))
                if urlparse(full).hostname == self.host:
                    js_urls.add(full)

        for path in ["/static/js/main.js", "/assets/index.js", "/app.js", "/bundle.js"]:
            js_urls.add(self.target + path)

        extracted = set()
        for js_url in list(js_urls)[:15]:
            status, body, _ = await self._get(sess, js_url)
            if status != 200 or not body:
                continue
            for m in re.finditer(
                r'(?:fetch|axios\.(?:get|post|put|delete|patch)|url\s*[:=])\s*["\'\']'
                r'((?:/[\w\-./{}?=&%+]+)+)', body, re.I
            ):
                p = m.group(1).split("?")[0]
                if p.startswith("/") and len(p) > 2:
                    extracted.add(p)

        print(f"  [JS] Extracted {len(extracted)} endpoints from JavaScript bundles")
        return list(extracted)

    async def check_graphql(self, sess):
        print("\n[*] Probing GraphQL introspection...")
        query = json.dumps({"query": "{ __schema { types { name fields { name } } } }"})
        for path in ["/graphql", "/api/graphql", "/gql", "/graphiql"]:
            url = self.target + path
            try:
                async with sess.post(
                    url, data=query,
                    headers={**WAF_BYPASS_HEADERS, "Content-Type": "application/json"},
                    ssl=False, timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    body = await r.text(errors="ignore")
                    if r.status == 200 and "__schema" in body:
                        data = json.loads(body)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t["name"] for t in types if not t["name"].startswith("__")]
                        self.findings.append({
                            "type": "GRAPHQL_INTROSPECTION_ENABLED",
                            "severity": "HIGH",
                            "confidence": 98,
                            "confidence_label": "Confirmed",
                            "url": url,
                            "types_exposed": len(type_names),
                            "types_sample": type_names[:20],
                            "proof": (
                                f"POST {path} with introspection query → HTTP 200 "
                                f"with __schema in response\n"
                                f"{len(type_names)} types exposed: {', '.join(type_names[:10])}"
                            ),
                            "detail": (
                                f"GraphQL introspection enabled — full schema with {len(type_names)} types "
                                f"is publicly readable, revealing all queries, mutations, and data structures"
                            ),
                            "remediation": (
                                "Disable introspection in production. In Apollo: "
                                "ApolloServer(\{introspection: false\}). "
                                "In graphene-django: set GRAPHENE['INTROSPECTION'] = False."
                            ),
                            "mitre_technique": "T1590",
                            "mitre_name": "Gather Victim Network Information",
                        })
                        print(f"  [HIGH] GraphQL introspection open at {path} ({len(type_names)} types)")
            except Exception:
                pass
            await delay()

    async def check_swagger(self, sess):
        print("\n[*] Looking for exposed API specs...")
        for path in ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json"]:
            url = self.target + path
            status, body, _ = await self._get(sess, url)
            await delay()
            if status != 200 or not body:
                continue
            if not any(kw in body for kw in ["swagger", "openapi", "paths"]):
                continue
            try:
                data = json.loads(body)
            except Exception:
                continue
            paths_count = len(data.get("paths", {}))
            if paths_count == 0:
                continue
            sample_paths = list(data.get("paths", {}).keys())[:5]
            self.findings.append({
                "type": "API_SPEC_EXPOSED",
                "severity": "MEDIUM",
                "confidence": 97,
                "confidence_label": "Confirmed",
                "url": url,
                "paths_count": paths_count,
                "sample_paths": sample_paths,
                "proof": (
                    f"HTTP 200 at {path} — valid OpenAPI/Swagger spec with {paths_count} endpoint paths\n"
                    f"Sample routes: {', '.join(sample_paths)}"
                ),
                "detail": f"API documentation publicly exposed — {paths_count} routes readable by anyone",
                "remediation": "Restrict API docs to internal networks or authenticated users in production.",
                "mitre_technique": "T1590.001",
                "mitre_name": "Gather Victim Network Information",
            })
            print(f"  [MEDIUM] API spec exposed at {path} ({paths_count} paths)")
            for api_path in list(data.get("paths", {}).keys())[:100]:
                self.found_endpoints.append(api_path)
            break

    async def build_baselines(self, sess) -> set:
        hashes = set()
        for path in ["/mirror-ghost-404a-test", "/mirror-ghost-404b-test"]:
            _, body, _ = await self._get(sess, self.target + path)
            if body:
                hashes.add(hashlib.md5(body[:500].encode(errors="ignore")).hexdigest())
        return hashes

    async def run(self):
        print("=" * 60)
        print("  GhostCrawler v6 — Zero-False-Positive Endpoint Discovery")
        print(f"  {len(API_PATHS)} paths | JS analysis | GraphQL | Swagger")
        print("=" * 60)

        conn = aiohttp.TCPConnector(limit=12, ssl=False)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=90)) as sess:
            baselines = await self.build_baselines(sess)
            robot_paths = await self.crawl_robots(sess)
            js_paths    = await self.extract_js_endpoints(sess)
            await self.check_graphql(sess)
            await self.check_swagger(sess)

            all_paths = list(dict.fromkeys(API_PATHS + robot_paths + js_paths + self.found_endpoints))
            print(f"\n[*] Probing {len(all_paths)} paths (only 200/201/204 flagged)...")

            sem = asyncio.Semaphore(8)
            async def probe(path):
                async with sem:
                    await self.probe_endpoint(sess, path, baselines)

            await asyncio.gather(*[probe(p) for p in all_paths])

        print(f"\n[+] GhostCrawler: {len(self.findings)} findings (zero 403-flaps)")
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
    findings = asyncio.run(GhostCrawler(target).run())
    with open("reports/ghostcrawler.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/ghostcrawler.json")


if __name__ == "__main__":
    main()
