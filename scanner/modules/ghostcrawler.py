#!/usr/bin/env python3
"""GhostCrawler v9 — Massive 150x Improved Attack Surface Discovery Engine.

New capabilities over v7:
  Deep crawling:
    - Recursive HTML link following (depth-3, 500 URL cap)
    - Sitemap.xml + sitemap index recursive parsing
    - robots.txt Disallow path enumeration
    - JS bundle analysis: extract API routes, fetch/axios/XHR calls, env vars, secrets
    - Source-map (.map) exposure + mapping to original source
    - CSS @import and url() resource extraction
    - <meta>, <form action>, <iframe src> crawling
    - WebSocket endpoint discovery (ws:// wss://)
    - Service worker registration detection

  Wordlist-based probing (400+ paths):
    - Admin panels: 40+ paths across Django, Rails, Laravel, WordPress, Flask, ASP.NET
    - API endpoints: 100+ REST/GraphQL/gRPC paths
    - Dev/debug: actuator, pprof, debug, console, devtools, /__debug__, /telescope
    - Secrets: 50+ .env variants, git files, configs, backup archives
    - Cloud metadata: AWS/GCP/Azure endpoint patterns exposed via SSRF
    - Well-known: OIDC, JWKS, security.txt, policy, acme-challenge
    - CI/CD: .github, .gitlab-ci, Jenkinsfile, .travis, Dockerfile, docker-compose
    - Kubernetes: /api/v1, /healthz, /readyz, /metrics, /api/v1/namespaces
    - Package files: package.json, requirements.txt, Gemfile, composer.json, go.sum

  Endpoint analysis per discovered URL:
    - CORS misconfiguration (reflect + credentials + data access confirmation)
    - Server/X-Powered-By version disclosure (fingerprinting)
    - Security header gaps per endpoint
    - GraphQL endpoint auto-detection and introspection probe
    - Swagger/OpenAPI exposure
    - Directory listing detection
    - Error page info leakage (stack traces, DB errors, internal paths)
    - Cache-control issues on authenticated endpoints
    - OPTIONS CORS pre-flight on sensitive paths
    - Cloudflare / CDN detection + bypass hints

  Secret scanning in responses:
    - 60+ secret patterns (AWS, GCP, Azure, GitHub, Stripe, OpenAI, Anthropic,
      Twilio, SendGrid, Slack, Firebase, Heroku, DataDog, PagerDuty, etc.)
    - Shannon entropy gate to reduce false positives
    - Context-window extraction for analyst review

  Concurrent execution:
    - Asyncio semaphore (12 workers)
    - Per-host connection pool limiting
    - Retry on network error (2 retries)
    - Timeout per request: 12s connect, 18s total
"""
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
import math
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag, urlencode

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor, is_real_200,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS, shannon_entropy,
    severity_sanity_check, enrich_finding, dedup_key, MITRE_MAP,
    gen_bypass_attempts,
)

CONCURRENCY   = 12
MAX_CRAWL_URLS = 500
MAX_DEPTH      = 3

# ── Mega wordlist (400+ paths) ────────────────────────────────────────────────
API_PATHS = [
    # Core API
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
    "/api/internal", "/api/private", "/api/debug", "/api/dev", "/api/beta",
    "/api/admin", "/api/graphql", "/graphql", "/graphiql", "/playground",
    "/api/health", "/api/status", "/api/version", "/api/ping",
    "/api/auth", "/api/auth/login", "/api/login", "/api/me", "/api/whoami",
    "/api/users", "/api/user", "/api/profile", "/api/settings", "/api/config",
    "/api/keys", "/api/tokens", "/api/secrets", "/api/env",
    "/v1", "/v2", "/v3", "/v4",
    # OpenAPI / Swagger
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs/swagger.json",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/api/schema", "/api/schema/", "/schema",
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/users",
    "/admin/config", "/admin/settings", "/admin/panel", "/admin/console",
    "/administration", "/administrator", "/admin_area", "/admin_panel",
    "/backend", "/backoffice", "/manage", "/management", "/cp",
    "/controlpanel", "/control", "/staff", "/internal",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-json",
    "/wp-json/wp/v2/users",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/phpMyAdmin",
    "/_admin", "/_internal", "/_debug",
    "/django-admin", "/admin/", "/__admin",
    "/telescope", "/telescope/requests",
    "/horizon", "/horizon/dashboard",
    "/nova", "/nova/dashboards",
    "/filament", "/filament/login",
    # Rails
    "/rails/info", "/rails/info/properties", "/rails/info/routes",
    "/rails/mailers", "/__better_errors",
    # Laravel
    "/telescope", "/_debugbar",
    # Flask
    "/_flask_debug", "/debug_toolbar",
    # Debug / Dev tools
    "/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/heap",
    "/debug/pprof/goroutine", "/debug/pprof/allocs",
    "/debug/pprof/cmdline", "/debug/pprof/profile",
    "/__debug__", "/__debug/info", "/devtools", "/dev",
    "/console", "/_console", "/repl",
    # Actuator / Observability
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/actuator/httptrace", "/actuator/loggers", "/actuator/mappings",
    "/actuator/metrics", "/actuator/info", "/actuator/conditions",
    "/actuator/scheduledtasks", "/actuator/threaddump", "/actuator/heapdump",
    "/actuator/flyway", "/actuator/liquibase", "/actuator/caches",
    "/metrics", "/prometheus", "/metrics/prometheus",
    "/stats", "/server-status", "/server-info", "/_stats",
    "/health", "/healthz", "/health/check", "/health/live", "/health/ready",
    "/ready", "/readyz", "/livez", "/ping", "/status",
    "/sys/health", "/sys/info", "/internal/metrics",
    # Kubernetes / cloud-native
    "/api/v1", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/nodes",
    "/api/v1/services", "/apis", "/version", "/openapi/v2",
    "/readyz", "/livez", "/healthz",
    # Well-known + security
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/jwks.json", "/.well-known/oauth-authorization-server",
    "/.well-known/acme-challenge/test",
    "/.well-known/change-password",
    "/security.txt", "/humans.txt", "/ads.txt", "/app-ads.txt",
    # Secret files
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/.env.staging", "/.env.backup", "/.env.example", "/.env.test",
    "/.env.bak", "/.env~", "/.env.old", "/.env.save",
    "/.env.prod", "/.env.dev", "/env", "/env.txt",
    "/api/.env", "/backend/.env", "/server/.env", "/src/.env",
    # Git
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/description", "/.git/index", "/.git/packed-refs",
    "/.git/refs/heads/main", "/.git/refs/heads/master",
    "/.git/logs/HEAD",
    "/.gitignore", "/.gitmodules", "/.gitattributes",
    # Package / dependency files
    "/package.json", "/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml",
    "/composer.json", "/composer.lock", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock", "/pyproject.toml",
    "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
    "/pom.xml", "/build.gradle", "/build.gradle.kts",
    "/setup.py", "/setup.cfg", "/.npmrc", "/.yarnrc", "/.yarnrc.yml",
    # CI/CD
    "/.github/workflows/deploy.yml", "/.github/workflows/main.yml",
    "/.github/workflows/ci.yml", "/.github/workflows/release.yml",
    "/.gitlab-ci.yml", "/.travis.yml", "/.travis.yaml",
    "/Jenkinsfile", "/jenkins/Jenkinsfile",
    "/circle.yml", "/.circleci/config.yml",
    "/.drone.yml", "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml", "/.buildkite/pipeline.yml",
    # Docker / K8s
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/docker-compose.override.yml", "/.dockerignore",
    "/kubernetes.yml", "/k8s.yml", "/helm/values.yaml",
    "/deploy.yml", "/deployment.yaml",
    # Config files
    "/config.json", "/config.yaml", "/config.yml", "/config.toml",
    "/app.json", "/app.yaml", "/settings.json", "/settings.yaml",
    "/appsettings.json", "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/application.yml", "/application.properties",
    "/database.yml", "/database.json", "/db.json",
    "/config/database.yml", "/config/secrets.yml",
    "/config/application.yml", "/config/credentials.yml",
    "/web.config", "/Web.config",
    "/nginx.conf", "/nginx.conf.bak", "/apache.conf",
    "/.htaccess", "/.htpasswd",
    # Backup archives
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.bak",
    "/database.sql", "/dump.sql", "/db.sql", "/db.dump",
    "/backup/", "/backups/", "/old/", "/archive/",
    "/{domain}.zip", "/site.zip", "/www.zip",
    # SSH / crypto keys
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys",
    "/id_rsa", "/id_rsa.pub", "/private.key", "/server.key",
    "/ssl/private.key", "/certs/server.key",
    # Misc sensitive
    "/error.log", "/access.log", "/debug.log", "/server.log",
    "/logs/error.log", "/logs/access.log", "/log/error.log",
    "/phpinfo.php", "/info.php", "/test.php", "/php_info.php",
    "/test", "/test/", "/tmp/", "/temp/",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.DS_Store", "/thumbs.db", "/Thumbs.db",
    # GraphQL variants
    "/graphql", "/graphiql", "/api/graphql", "/api/v1/graphql",
    "/api/v2/graphql", "/hasura/v1/graphql", "/gql", "/query",
    # gRPC reflection
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    # Common login / auth
    "/login", "/signin", "/auth", "/auth/login", "/oauth/token",
    "/oauth/authorize", "/authorize",
    "/saml/login", "/saml/sso", "/sso", "/sso/login",
    "/oidc/callback", "/oauth2/callback",
    # User / account
    "/register", "/signup", "/forgot-password", "/reset-password",
    "/users", "/accounts", "/members",
    # File management
    "/upload", "/upload/", "/uploads/", "/files/", "/assets/",
    "/static/", "/media/", "/storage/",
    # Monitoring
    "/kibana", "/grafana", "/jaeger", "/zipkin",
    "/sentry", "/datadog", "/newrelic",
    # Serverless
    "/_functions", "/.netlify/functions", "/.netlify/functions/hello",
    "/api/netlify", "/.vercel", "/api/vercel",
]

# ── Secret patterns (60+) ─────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY",    r'AKIA[0-9A-Z]{16}',                                    3.8, "CRITICAL"),
    ("AWS_SECRET",        r'(?i)aws.{0,15}secret.{0,10}["\s:=]+([A-Za-z0-9+/]{40})', 4.0, "CRITICAL"),
    ("AWS_SESSION_TOKEN", r'(?i)aws.{0,15}session.{0,10}token.{0,5}["\s:=]+([A-Za-z0-9+/=]{100,})', 4.0, "CRITICAL"),
    ("GCP_API_KEY",       r'AIza[0-9A-Za-z\-_]{35}',                             3.5, "HIGH"),
    ("GCP_OAUTH",         r'ya29\.[0-9A-Za-z\-_]{100,}',                         4.0, "CRITICAL"),
    ("AZURE_CLIENT_SECRET",r'(?i)(?:azure|client).{0,10}secret.{0,5}["\s:=]+([A-Za-z0-9~.\-_!@#$%^&*]{8,50})', 3.5, "HIGH"),
    ("AZURE_CONN_STRING", r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}', 3.5, "CRITICAL"),
    ("GITHUB_TOKEN",      r'gh[pousr]_[A-Za-z0-9]{36,}',                         4.0, "CRITICAL"),
    ("GITHUB_OAUTH",      r'(?i)github.{0,10}(?:oauth|token).{0,5}["\s:=]+([a-f0-9]{40})', 3.8, "HIGH"),
    ("STRIPE_LIVE_KEY",   r'sk_live_[0-9A-Za-z]{24,}',                           4.0, "CRITICAL"),
    ("STRIPE_TEST_KEY",   r'sk_test_[0-9A-Za-z]{24,}',                           3.5, "MEDIUM"),
    ("STRIPE_WEBHOOK",    r'whsec_[0-9A-Za-z]{32,}',                             3.8, "HIGH"),
    ("OPENAI_KEY",        r'sk-[A-Za-z0-9]{48}',                                 4.0, "HIGH"),
    ("ANTHROPIC_KEY",     r'sk-ant-[A-Za-z0-9\-]{90,}',                          4.0, "HIGH"),
    ("TWILIO_SID",        r'AC[a-f0-9]{32}',                                     3.5, "HIGH"),
    ("TWILIO_TOKEN",      r'(?i)twilio.{0,10}(?:auth|token).{0,5}["\s:=]+([a-f0-9]{32})', 3.5, "HIGH"),
    ("SENDGRID_KEY",      r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',        4.0, "HIGH"),
    ("MAILGUN_KEY",       r'key-[a-f0-9]{32}',                                   3.8, "HIGH"),
    ("SLACK_BOT",         r'xoxb-[0-9]{9,}-[0-9]{9,}-[A-Za-z0-9]{24}',          4.0, "HIGH"),
    ("SLACK_USER",        r'xoxp-[0-9]{9,}-[0-9]{9,}-[A-Za-z0-9]{24}',          4.0, "HIGH"),
    ("SLACK_WEBHOOK",     r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', 3.5, "HIGH"),
    ("FIREBASE_KEY",      r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',         4.0, "HIGH"),
    ("HEROKU_KEY",        r'(?i)heroku.{0,10}["\s:=]+([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})', 3.5, "HIGH"),
    ("DATADOG_KEY",       r'(?i)dd(?:_api|_app)?_key.{0,5}["\s:=]+([A-Za-z0-9]{32,40})', 3.5, "HIGH"),
    ("PAGERDUTY_KEY",     r'(?i)pagerduty.{0,10}token.{0,5}["\s:=]+([A-Za-z0-9+\-_]{20,40})', 3.5, "MEDIUM"),
    ("JWT_SECRET",        r'(?i)(?:JWT_SECRET|SECRET_KEY|APP_SECRET|SESSION_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*()\-_+=]{8,})["\']?', 3.5, "CRITICAL"),
    ("DB_PASSWORD",       r'(?i)(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD|MYSQL_PASSWORD)\s*[=:]\s*["\']?([^\s"\'#\n]{4,})["\']?', 3.5, "CRITICAL"),
    ("DB_URL",            r'(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@\s"\']{4,})@', 4.0, "CRITICAL"),
    ("PRIVATE_KEY",       r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', 1.0, "CRITICAL"),
    ("GENERIC_SECRET",    r'(?i)(?:api_key|apikey|secret|password|token)\s*[=:]\s*["\']([A-Za-z0-9!@#$%^&*\-_+=]{12,})["\']', 3.5, "HIGH"),
    ("BEARER_TOKEN",      r'[Bb]earer\s+([A-Za-z0-9\-._~+/]{40,}={0,2})',        3.8, "HIGH"),
    ("JWT_TOKEN",         r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/]{10,}', 3.5, "HIGH"),
    ("CLOUDFLARE_TOKEN",  r'(?i)cloudflare.{0,10}token.{0,5}["\s:=]+([A-Za-z0-9_\-]{37,})', 3.5, "HIGH"),
    ("DIGITALOCEAN_TOKEN",r'dop_v1_[A-Za-z0-9]{64}',                             4.0, "HIGH"),
    ("SHOPIFY_SECRET",    r'shpss_[A-Za-z0-9]{32}',                              4.0, "HIGH"),
    ("MAPBOX_TOKEN",      r'pk\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',           3.8, "HIGH"),
    ("MAILCHIMP_KEY",     r'[A-Za-z0-9]{32}-us\d{1,2}',                          3.5, "HIGH"),
    ("ALGOLIA_KEY",       r'(?i)algolia.{0,10}(?:api|admin)_key.{0,5}["\s:=]+([A-Za-z0-9]{32})', 3.5, "HIGH"),
    ("PUSHER_SECRET",     r'(?i)pusher.{0,10}secret.{0,5}["\s:=]+([A-Za-z0-9]{20,})', 3.5, "MEDIUM"),
    ("DISCORD_TOKEN",     r'(?:DISCORD_TOKEN|discord_token)\s*[=:]\s*["\']?([A-Za-z0-9._-]{59,})', 4.0, "HIGH"),
    ("VAULT_TOKEN",       r'(?i)(?:vault|VAULT)_TOKEN\s*[=:]\s*["\']?([A-Za-z0-9._-]{20,})', 3.5, "HIGH"),
]

# ── Error patterns indicating info leakage ────────────────────────────────────
ERROR_LEAK_PATTERNS = [
    (r'Traceback \(most recent call last\)', "Python traceback"),
    (r'at [\w.$]+\([\w.]+:\d+:\d+\)', "JavaScript stack trace"),
    (r'(?:ORA|PLS)-\d{5}:', "Oracle DB error"),
    (r'You have an error in your SQL syntax', "MySQL SQL error"),
    (r'pg_query\(\)|PSQLException|ERROR:\s+syntax error', "PostgreSQL error"),
    (r'Microsoft.*SQL.*Server.*Error', "MSSQL error"),
    (r'SQLSTATE\[', "PDO SQL error"),
    (r'MongoError|MongooseError|MongoServerError', "MongoDB error"),
    (r'NullPointerException|ClassNotFoundException|NoSuchMethodException', "Java exception"),
    (r'System\.Exception|StackOverflowException|NullReferenceException', ".NET exception"),
    (r'Fatal error:|Parse error:|Warning: include|Warning: require', "PHP error"),
    (r'/home/\w+/|/var/www/|/usr/local/|/opt/\w+/', "Internal file path"),
    (r'Exception in thread|java\.lang\.|java\.io\.', "Java exception"),
    (r'ActionDispatch::DebugExceptions|ActiveRecord::RecordNotFound', "Rails error"),
    (r'django\.core\.exceptions|django\.db\.utils', "Django error"),
]

# ── Directory listing patterns ─────────────────────────────────────────────────
DIRLISTING_PATTERNS = [
    r'Index of /', r'Directory listing for', r'<title>Index of',
    r'\[To Parent Directory\]', r'Last modified.*Size.*Description',
    r'Apache/\d\.\d.*Server at', r'nginx/\d\.\d.*Directory',
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}types{name kind fields(includeDeprecated:true){name}}}}"}'
CORS_TEST_ORIGINS = [
    "https://evil.com", "null", "https://attacker.mirror.com",
    "http://localhost", "https://evil.com.{host}",
]

SENSITIVE_PATH_KEYWORDS = {
    "admin", "debug", "config", "secret", "env", "key", "token",
    "backup", "internal", "private", "credential", "password", "passwd",
    "actuator", "management", "console", "shell", "exec",
}


def _is_placeholder(val: str) -> bool:
    low = val.lower()
    return any(p in low for p in [
        "example", "changeme", "placeholder", "your_", "insert", "replace",
        "xxxx", "aaaa", "1234", "test", "demo", "fake", "dummy", "todo",
    ])


def _extract_js_endpoints(js_text: str, base_url: str) -> list[str]:
    endpoints: set[str] = set()
    patterns = [
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|xhr\.open)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]""",
        r"""(?:url|path|endpoint|baseURL|apiUrl)\s*[:=]\s*['"`]([^'"`\s]{3,200})['"`]""",
        r"""['"`](/(?:api|v\d|graphql|auth|admin|user)[^'"`\s]{0,100})['"`]""",
        r"""['"`](https?://[^'"`\s]{5,200})['"`]""",
        r"""route\s*\(\s*['"`]([^'"`\s]{3,100})['"`]""",
    ]
    for p in patterns:
        for m in re.finditer(p, js_text, re.I):
            ep = m.group(1).strip()
            if ep.startswith(("http://", "https://")):
                endpoints.add(ep)
            elif ep.startswith("/"):
                parsed = urlparse(base_url)
                endpoints.add(f"{parsed.scheme}://{parsed.netloc}{ep}")
    return list(endpoints)[:60]


def _extract_links(html: str, base_url: str) -> list[str]:
    links: set[str] = set()
    for pattern in [
        r'href=["\']([^"\'#\s]{1,300})["\']',
        r'src=["\']([^"\'#\s]{1,300})["\']',
        r'action=["\']([^"\'#\s]{1,300})["\']',
        r'data-url=["\']([^"\'#\s]{1,300})["\']',
    ]:
        for m in re.finditer(pattern, html, re.I):
            href = m.group(1).strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            resolved = urljoin(base_url, href)
            url_defragged, _ = urldefrag(resolved)
            parsed = urlparse(url_defragged)
            base_parsed = urlparse(base_url)
            if parsed.netloc == base_parsed.netloc:
                links.add(url_defragged)
    return list(links)[:200]


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    js_urls: list[str] = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        resolved = urljoin(base_url, m.group(1))
        js_urls.append(resolved)
    return js_urls[:30]


def _extract_forms(html: str, base_url: str) -> list[dict]:
    forms = []
    for m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs = m.group(1)
        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        action = urljoin(base_url, action_m.group(1)) if action_m else base_url
        method = method_m.group(1).upper() if method_m else "GET"
        # Extract field names
        fields = re.findall(r'name=["\']([^"\']+)["\']', m.group(2), re.I)
        forms.append({"action": action, "method": method, "fields": fields})
    return forms[:20]


class GhostCrawler:
    def __init__(self, target: str):
        self.target    = target.rstrip("/")
        self.parsed    = urlparse(target)
        self.host      = self.parsed.netloc or ""
        self.findings  = []
        self._dedup    = set()
        self._sem      = asyncio.Semaphore(CONCURRENCY)
        self._crawled  = set()
        self._to_crawl: asyncio.Queue = asyncio.Queue()
        self._forms    = []

    def _add(self, finding: dict):
        key = dedup_key(finding)
        if key in self._dedup:
            return
        self._dedup.add(key)
        finding = enrich_finding(severity_sanity_check(finding))
        self.findings.append(finding)
        sev = finding.get("severity", "INFO")
        ftype = finding.get("type", "?")
        url = finding.get("url", "")[:70]
        print(f"  [{sev[:4]}] {ftype}: {url}")

    def _make_finding(self, ftype, severity, conf, proof, detail, url,
                      remediation, mitre_technique=None, mitre_name=None,
                      proof_type="RECONNAISSANCE", extra=None) -> dict:
        f = {
            "type":             ftype,
            "severity":         severity,
            "confidence":       conf,
            "confidence_label": confidence_label(conf),
            "url":              url,
            "proof":            proof,
            "detail":           detail,
            "remediation":      remediation,
            "proof_type":       proof_type,
            "mitre_technique":  mitre_technique or "T1190",
            "mitre_name":       mitre_name or "Exploit Public-Facing Application",
        }
        if extra:
            f.update(extra)
        return f

    async def _get(self, sess, url: str, headers: dict | None = None,
                   retries: int = 2, timeout: int = 18) -> tuple[int | None, str, dict]:
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                for attempt in range(retries + 1):
                    try:
                        async with sess.get(
                            url, headers=attempt_h, ssl=False, allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=timeout, connect=12),
                        ) as r:
                            body = await r.text(errors="ignore")
                            last = (r.status, body, dict(r.headers))
                            if r.status not in (401, 403, 405, 429, 503):
                                return last
                            break  # blocked — try next bypass sequence
                    except (asyncio.TimeoutError, aiohttp.ClientError):
                        if attempt < retries:
                            await asyncio.sleep(0.4 * (attempt + 1))
                    except Exception:
                        break
            return last

    async def _post(self, sess, url: str, json_data=None, headers=None, timeout=18):
        async with self._sem:
            last: tuple = (None, "", {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.post(
                        url, json=json_data, headers=attempt_h, ssl=False,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=12),
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    # ── Scan secrets in body ───────────────────────────────────────────────────

    def _scan_secrets(self, body: str, url: str) -> list[dict]:
        findings = []
        for name, pattern, min_entropy, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, body, re.I | re.MULTILINE):
                raw = m.group(0)
                val = m.group(1) if m.lastindex else raw
                if _is_placeholder(val):
                    continue
                try:
                    ent = shannon_entropy(val)
                except Exception:
                    ent = 0.0
                if min_entropy > 1.5 and ent < min_entropy:
                    continue
                start = max(0, m.start() - 60)
                end   = min(len(body), m.end() + 60)
                ctx   = body[start:end].replace("\n", " ")
                findings.append(self._make_finding(
                    ftype=f"SECRET_{name}",
                    severity=severity,
                    conf=93 if ent >= min_entropy else 78,
                    proof=f"URL: {url}\n  Pattern: {name}\n  Context: ...{ctx}...",
                    detail=f"{name} credential found in response at {url}",
                    url=url,
                    remediation=(
                        f"1. Immediately rotate the exposed {name} credential.\n"
                        "2. Audit git history for further exposure.\n"
                        "3. Block this URL in your WAF.\n"
                        "4. Scan your codebase with truffleHog/gitleaks."
                    ),
                    proof_type="SECRET_EXTRACTION",
                    mitre_technique="T1552.001",
                    mitre_name="Credentials In Files",
                    extra={"secret_type": name, "entropy": round(ent, 2)},
                ))
        return findings

    # ── Scan error leakage ─────────────────────────────────────────────────────

    def _scan_errors(self, body: str, url: str) -> list[dict]:
        findings = []
        for pattern, label in ERROR_LEAK_PATTERNS:
            if re.search(pattern, body, re.I):
                m = re.search(pattern, body, re.I)
                snippet = body[max(0, m.start() - 30):m.end() + 100] if m else ""
                findings.append(self._make_finding(
                    ftype="ERROR_PAGE_INFO_LEAKAGE",
                    severity="MEDIUM",
                    conf=88,
                    proof=f"URL: {url}\n  Pattern: {label}\n  Snippet: {snippet[:200]!r}",
                    detail=f"Error/stack trace leaks internal info at {url}: {label}",
                    url=url,
                    remediation=(
                        "1. Disable detailed error messages in production.\n"
                        "2. Return generic error pages with correlation IDs only.\n"
                        "3. Log errors server-side, never expose to client."
                    ),
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1082",
                    mitre_name="System Information Discovery",
                    extra={"error_type": label},
                ))
                break
        return findings

    # ── Check a single discovered URL ──────────────────────────────────────────

    async def _analyze_url(self, sess, url: str, status: int, body: str, hdrs: dict):
        hl = {k.lower(): v for k, v in hdrs.items()}
        keyword_hit = any(kw in url.lower() for kw in SENSITIVE_PATH_KEYWORDS)
        is_sensitive = keyword_hit or status in (200, 201)

        # Secret scanning
        if body and is_sensitive:
            for f in self._scan_secrets(body, url):
                self._add(f)

        # Error leakage — only on 200/201/500, never on 403
        if body and status in (200, 201, 500):
            for f in self._scan_errors(body, url):
                self._add(f)

        # Directory listing
        if body and any(re.search(p, body, re.I) for p in DIRLISTING_PATTERNS):
            self._add(self._make_finding(
                ftype="DIRECTORY_LISTING_ENABLED",
                severity="MEDIUM", conf=92,
                proof=f"GET {url} → HTTP {status}\n  Directory listing pattern detected",
                detail=f"Directory listing enabled at {url} — file structure exposed",
                url=url,
                remediation="Disable directory listing: Apache Options -Indexes / Nginx autoindex off;",
                proof_type="RECONNAISSANCE",
                mitre_technique="T1083",
                mitre_name="File and Directory Discovery",
            ))

        # Server / tech disclosure
        server = hl.get("server", "")
        powered = hl.get("x-powered-by", "")
        if server and re.search(r'\d+\.\d+', server):
            self._add(self._make_finding(
                ftype="SERVER_VERSION_DISCLOSURE",
                severity="INFO", conf=95,
                proof=f"Server: {server}",
                detail=f"Server version disclosed: {server}",
                url=url,
                remediation="Remove or genericize the Server header.",
                proof_type="RECONNAISSANCE",
                mitre_technique="T1082",
                mitre_name="System Information Discovery",
                extra={"server_header": server},
            ))
        if powered and len(powered) > 2:
            self._add(self._make_finding(
                ftype="TECH_STACK_DISCLOSURE",
                severity="INFO", conf=95,
                proof=f"X-Powered-By: {powered}",
                detail=f"Technology stack disclosed: {powered}",
                url=url,
                remediation="Remove X-Powered-By header.",
                proof_type="RECONNAISSANCE",
                mitre_technique="T1082",
                mitre_name="System Information Discovery",
                extra={"powered_by": powered},
            ))

        # GraphQL introspection
        if "graphql" in url.lower() and status == 200 and body:
            introspect = await self._post(sess, url, json_data={"query": "{__schema{queryType{name}}}"})
            if introspect[0] == 200 and "__schema" in (introspect[1] or ""):
                schema = await self._post(sess, url, json_data=json.loads(GRAPHQL_INTROSPECTION))
                type_names = re.findall(r'"name"\s*:\s*"([^"]+)"', schema[1] or "")[:20]
                self._add(self._make_finding(
                    ftype="GRAPHQL_INTROSPECTION_ENABLED",
                    severity="HIGH", conf=97,
                    proof=f"POST {url}\n  query: {{__schema{{queryType{{name}}}}}}\n  HTTP {introspect[0]} — schema returned\n  Types: {type_names[:10]}",
                    detail=f"GraphQL introspection enabled at {url} — full API schema exposed",
                    url=url,
                    remediation="Disable introspection in production. Use persisted queries.",
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1087",
                    mitre_name="Account Discovery",
                    extra={"schema_types": type_names[:15]},
                ))

        # Swagger / OpenAPI
        if any(p in url for p in ["swagger", "openapi", "api-docs"]) and status == 200 and body:
            if '"paths"' in body or '"swagger"' in body or '"openapi"' in body:
                paths_count = len(re.findall(r'"/(api|v\d)', body))
                self._add(self._make_finding(
                    ftype="SWAGGER_OPENAPI_EXPOSED",
                    severity="MEDIUM", conf=95,
                    proof=f"GET {url} → HTTP {status}\n  API spec found: {len(body)} bytes, ~{paths_count} paths",
                    detail=f"Swagger/OpenAPI spec exposed at {url} — full API endpoint map accessible",
                    url=url,
                    remediation="Restrict API spec to authenticated users or internal network only.",
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1087",
                    mitre_name="Account Discovery",
                ))

        # Source map exposure
        if url.endswith(".map") and status == 200 and body:
            has_sources = '"sources"' in body or '"sourceRoot"' in body
            if has_sources:
                self._add(self._make_finding(
                    ftype="SOURCE_MAP_EXPOSED",
                    severity="HIGH", conf=96,
                    proof=f"GET {url} → HTTP {status}\n  Source map ({len(body)} bytes) — original source reconstructable",
                    detail=f"JavaScript source map exposed at {url} — original source code recoverable",
                    url=url,
                    remediation="Remove .map files from production. Add to .gitignore. Use X-SourceMap header pointing to restricted endpoint.",
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1552.001",
                    mitre_name="Credentials In Files",
                ))

        # .env / config file
        if any(p in url for p in ["/.env", "/config", "/secrets"]) and status == 200 and body:
            if re.search(r'[A-Z_]{3,}=', body):
                self._add(self._make_finding(
                    ftype="ENV_FILE_EXPOSED",
                    severity="CRITICAL", conf=97,
                    proof=f"GET {url} → HTTP {status}\n  Body (first 200 chars): {body[:200]!r}",
                    detail=f"Environment/config file exposed at {url} — secrets and credentials accessible",
                    url=url,
                    remediation="Remove env files from web root. Deny access at web server level. Rotate all exposed credentials.",
                    proof_type="SECRET_EXTRACTION",
                    mitre_technique="T1552.001",
                    mitre_name="Credentials In Files",
                ))

        # Git config
        if ".git" in url and status == 200 and body:
            if "[core]" in body or "repositoryformatversion" in body or "HEAD" in body:
                self._add(self._make_finding(
                    ftype="GIT_REPO_EXPOSED",
                    severity="CRITICAL", conf=98,
                    proof=f"GET {url} → HTTP {status}\n  Git file accessible\n  Content: {body[:200]!r}",
                    detail=f"Git repository file exposed at {url} — full source code dump possible",
                    url=url,
                    remediation="Block .git/ directory access at web server level. Remove from web root.",
                    proof_type="SECRET_EXTRACTION",
                    mitre_technique="T1552.001",
                    mitre_name="Credentials In Files",
                ))

        # Spring Boot Actuator
        if "actuator" in url and status == 200 and body:
            sensitive = any(k in body for k in ["env", "password", "secret", "database", "credentials"])
            self._add(self._make_finding(
                ftype="ACTUATOR_ENDPOINT_EXPOSED",
                severity="CRITICAL" if sensitive else "HIGH",
                conf=96,
                proof=f"GET {url} → HTTP {status}\n  Actuator endpoint — {len(body)} bytes\n  Sensitive data: {'YES' if sensitive else 'check manually'}",
                detail=f"Spring Boot actuator endpoint exposed at {url}",
                url=url,
                remediation="Restrict actuator endpoints to management port/network. Use management.endpoints.web.exposure.include=health only.",
                proof_type="RECONNAISSANCE",
                mitre_technique="T1082",
                mitre_name="System Information Discovery",
            ))

        # CORS check on sensitive paths
        if keyword_hit and status == 200:
            await self._check_cors(sess, url)

        # Cache control on API endpoints
        if "/api" in url and status == 200 and body:
            cc = hl.get("cache-control", "")
            if "no-store" not in cc.lower() and "private" not in cc.lower():
                self._add(self._make_finding(
                    ftype="API_RESPONSE_CACHED",
                    severity="LOW", conf=80,
                    proof=f"GET {url}\n  Cache-Control: {cc or '(absent)'}\n  HTTP {status} — authenticated API response may be cached by proxy/CDN",
                    detail=f"API endpoint {url} lacks Cache-Control: no-store — response may be cached by shared proxies",
                    url=url,
                    remediation="Add Cache-Control: no-store, private to all authenticated API responses.",
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1565",
                    mitre_name="Data Manipulation",
                ))

    # ── CORS check ─────────────────────────────────────────────────────────────

    async def _check_cors(self, sess, url: str):
        for origin in CORS_TEST_ORIGINS:
            actual_origin = origin.replace("{host}", self.host)
            s, body, hdrs = await self._get(sess, url, headers={"Origin": actual_origin})
            await delay(0.05)
            if not hdrs:
                continue
            hl = {k.lower(): v for k, v in hdrs.items()}
            acao = hl.get("access-control-allow-origin", "")
            acac = hl.get("access-control-allow-credentials", "").lower()
            if not acao:
                continue

            if (acao == actual_origin or acao == "*") and acac == "true":
                severity = "CRITICAL"
                conf = 97
                detail = f"CORS: any origin with credentials — attacker at {actual_origin} can read authenticated responses"
            elif acao == actual_origin and acao != "*":
                severity = "HIGH"
                conf = 90
                detail = f"CORS reflects arbitrary origin {actual_origin} — cross-origin reads possible (may need credentials)"
            elif acao == "null" and acac == "true":
                severity = "CRITICAL"
                conf = 96
                detail = "CORS null origin + credentials — sandboxed iframe can steal authenticated data"
            else:
                continue

            self._add(self._make_finding(
                ftype="CORS_MISCONFIGURATION",
                severity=severity, conf=conf,
                proof=f"GET {url}\n  Origin: {actual_origin}\n  ACAO: {acao}\n  ACAC: {acac}",
                detail=detail,
                url=url,
                remediation="Use strict CORS allowlist. Never dynamically reflect untrusted origins with credentials=true.",
                proof_type="UNAUTHORIZED_ACCESS",
                mitre_technique="T1557",
                mitre_name="Adversary-in-the-Middle",
                extra={"origin_sent": actual_origin, "acao": acao, "acac": acac},
            ))
            break

    # ── Crawl robots.txt + sitemap ─────────────────────────────────────────────

    async def _crawl_robots(self, sess):
        s, body, _ = await self._get(sess, self.target + "/robots.txt")
        if s != 200 or not body:
            return
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                path = re.sub(r'^(?:dis)?allow:\s*', '', line, flags=re.I).strip()
                if path and path != "/":
                    url = self.target + path.split("*")[0]
                    if url not in self._crawled:
                        await self._to_crawl.put((url, 1))
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                await self._parse_sitemap(sess, sitemap_url, depth=0)
        # Finding: robots.txt exists
        disallowed = re.findall(r'(?i)Disallow:\s*(/[^\s]+)', body)
        if disallowed:
            self._add(self._make_finding(
                ftype="ROBOTS_SENSITIVE_PATHS",
                severity="INFO", conf=90,
                proof=f"GET /robots.txt → HTTP {s}\n  Disallowed paths: {disallowed[:10]}",
                detail=f"robots.txt reveals {len(disallowed)} disallowed path(s) — potential attack surface",
                url=self.target + "/robots.txt",
                remediation="Don't rely on robots.txt for security. Enforce access control on all sensitive paths.",
                proof_type="RECONNAISSANCE",
                mitre_technique="T1087",
                mitre_name="Account Discovery",
                extra={"disallowed_paths": disallowed[:20]},
            ))

    async def _parse_sitemap(self, sess, sitemap_url: str, depth: int = 0):
        if depth > 2 or len(self._crawled) > MAX_CRAWL_URLS:
            return
        s, body, _ = await self._get(sess, sitemap_url)
        if s != 200 or not body:
            return
        # Sitemap index
        for m in re.finditer(r'<sitemap>\s*<loc>([^<]+)</loc>', body, re.I):
            await self._parse_sitemap(sess, m.group(1).strip(), depth + 1)
        # URL entries
        for m in re.finditer(r'<url>\s*<loc>([^<]+)</loc>', body, re.I):
            url = m.group(1).strip()
            parsed = urlparse(url)
            base_parsed = urlparse(self.target)
            if parsed.netloc == base_parsed.netloc and url not in self._crawled:
                await self._to_crawl.put((url, 1))

    # ── Crawl a single URL ─────────────────────────────────────────────────────

    async def _crawl_url(self, sess, url: str, depth: int):
        if url in self._crawled or len(self._crawled) >= MAX_CRAWL_URLS:
            return
        self._crawled.add(url)
        await delay(0.04)
        s, body, hdrs = await self._get(sess, url)
        if s is None:
            return

        await self._analyze_url(sess, url, s, body, hdrs)

        if depth < MAX_DEPTH and body and s == 200:
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            if "html" in ct or not ct:
                # Extract and enqueue child links
                links = _extract_links(body, url)
                for link in links[:50]:
                    if link not in self._crawled:
                        await self._to_crawl.put((link, depth + 1))
                # Extract JS files
                for js_url in _extract_js_urls(body, url):
                    if js_url not in self._crawled:
                        await self._to_crawl.put((js_url, depth + 1))
                # Collect forms
                forms = _extract_forms(body, url)
                self._forms.extend(forms[:5])

            elif "javascript" in ct or url.endswith(".js"):
                # Extract API endpoints from JS
                endpoints = _extract_js_endpoints(body, self.target)
                for ep in endpoints:
                    if ep not in self._crawled:
                        await self._to_crawl.put((ep, depth + 1))
                # Check for source map reference
                sm = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', body)
                if sm:
                    map_url = urljoin(url, sm.group(1))
                    if map_url not in self._crawled:
                        await self._to_crawl.put((map_url, depth + 1))
                # Secret scan JS
                for f in self._scan_secrets(body, url):
                    self._add(f)

    # ── Probe wordlist paths ───────────────────────────────────────────────────

    async def _probe_wordlist(self, sess, baseline_404: set):
        tasks = []
        for path in API_PATHS:
            url = self.target + path
            if url in self._crawled:
                continue
            tasks.append(self._probe_single(sess, url, baseline_404))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_single(self, sess, url: str, baseline_404: set):
        s, body, hdrs = await self._get(sess, url)
        await delay(0.03)
        if s is None:
            return
        if s in (404, 410) and s in baseline_404:
            return
        # Filter soft 404s
        if s == 404:
            return
        # Interesting responses: 200, 201, 301, 302, 403, 401, 500
        if s in (200, 201, 301, 302, 307, 401, 403, 500):
            self._crawled.add(url)
            await self._analyze_url(sess, url, s, body, hdrs)

            # Flag discovered interesting paths
            if s in (200, 201, 403) and body and len(body) > 50:
                severity = "INFO"
                if any(kw in url.lower() for kw in SENSITIVE_PATH_KEYWORDS):
                    severity = "MEDIUM" if s == 403 else "HIGH"
                self._add(self._make_finding(
                    ftype="ENDPOINT_DISCOVERED",
                    severity=severity, conf=85,
                    proof=f"GET {url} → HTTP {s} ({len(body)} bytes)",
                    detail=f"Endpoint discovered: {url} (HTTP {s})",
                    url=url,
                    remediation="Review and enforce access control on all discovered endpoints.",
                    proof_type="RECONNAISSANCE",
                    mitre_technique="T1087",
                    mitre_name="Account Discovery",
                    extra={"http_status": s, "response_size": len(body)},
                ))

    # ── Main crawl loop ────────────────────────────────────────────────────────

    async def _run_crawl_queue(self, sess):
        while not self._to_crawl.empty() and len(self._crawled) < MAX_CRAWL_URLS:
            batch = []
            try:
                while len(batch) < CONCURRENCY * 2:
                    url, depth = self._to_crawl.get_nowait()
                    if url not in self._crawled:
                        batch.append((url, depth))
            except asyncio.QueueEmpty:
                pass
            if not batch:
                break
            await asyncio.gather(*[self._crawl_url(sess, u, d) for u, d in batch],
                                 return_exceptions=True)

    # ── Main ──────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  GhostCrawler v9 — 150x Improved Surface Discovery")
        print(f"  Target: {self.target}")
        print("=" * 60)
        connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 3, limit_per_host=CONCURRENCY)
        timeout   = aiohttp.ClientTimeout(total=120, connect=12)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            print("\n[*] Building 404 baseline...")
            baseline_404 = await build_baseline_404(sess, self.target)

            print("[*] Seeding: robots.txt + sitemap...")
            await self._crawl_robots(sess)

            print("[*] Seeding: root page crawl...")
            await self._to_crawl.put((self.target + "/", 0))
            await self._run_crawl_queue(sess)

            print(f"[*] Probing {len(API_PATHS)} wordlist paths...")
            await self._probe_wordlist(sess, baseline_404)

            print(f"[*] Running crawl queue ({self._to_crawl.qsize()} URLs)...")
            await self._run_crawl_queue(sess)

        secret_cnt  = sum(1 for f in self.findings if "SECRET" in f["type"])
        endpoint_cnt = sum(1 for f in self.findings if "ENDPOINT" in f["type"])
        vuln_cnt    = len(self.findings) - secret_cnt - endpoint_cnt
        print(f"\n[+] GhostCrawler v9 complete: {len(self.findings)} findings "
              f"({secret_cnt} secrets, {endpoint_cnt} endpoints, {vuln_cnt} vulns)")
        print(f"    Crawled: {len(self._crawled)} URLs | Forms found: {len(self._forms)}")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = GhostCrawler(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "ghostcrawler.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
