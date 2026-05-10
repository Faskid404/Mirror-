#!/usr/bin/env python3
"""
GhostCrawler v2 — Intelligent web crawler and attack surface mapper.

Improvements:
  - Respects scope (stays on target domain)
  - JS file parsing for API routes, fetch() calls, axios calls, GraphQL
  - Form extraction with field names and method detection
  - Robots.txt and sitemap.xml parsing
  - Hidden parameter mining (discovers params from JS/HTML)
  - Technology stack detection
  - Admin panel discovery (200+ paths)
  - Cloud metadata / debug endpoint detection
  - Generates structured attack surface report
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_likely_real_vuln, delay,
    confidence_score, confidence_label, severity_from_confidence,
    detect_waf, detect_tech, REQUEST_DELAY
)

MAX_PAGES    = 80
MAX_JS_FILES = 30

class GhostCrawler:
    def __init__(self, target):
        self.target       = target.rstrip('/')
        self.host         = urlparse(target).hostname
        self.scheme       = urlparse(target).scheme
        self.visited      = set()
        self.js_visited   = set()
        self.queue        = []
        self.findings     = []
        self.endpoints    = []   # discovered endpoints
        self.params       = set()
        self.forms        = []
        self.tech         = []
        self.waf          = []
        self.baseline_404 = ""

    async def _get(self, sess, url, timeout=10):
        try:
            async with sess.get(url, ssl=False, allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _in_scope(self, url):
        try:
            return urlparse(url).hostname == self.host
        except Exception:
            return False

    def _normalize(self, url, base=None):
        try:
            full = urljoin(base or self.target, url)
            clean, _ = urldefrag(full)
            clean = clean.rstrip('/')
            parsed = urlparse(clean)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return None

    # ── Robots.txt & Sitemap ─────────────────────────────────────────────────

    async def crawl_robots(self, sess):
        status, body, _ = await self._get(sess, self.target + '/robots.txt')
        await delay()
        if not body or status != 200:
            return
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith(('disallow:', 'allow:')):
                path = re.sub(r'^(?:dis)?allow:\s*', '', line, flags=re.I).strip()
                if path and path != '/':
                    url = self._normalize(path)
                    if url and url not in self.visited:
                        self.queue.append(url)
                        self.endpoints.append({'url': url, 'source': 'robots.txt'})
        # Find sitemap
        for line in body.splitlines():
            if line.lower().startswith('sitemap:'):
                sitemap_url = line.split(':', 1)[1].strip()
                await self.crawl_sitemap(sess, sitemap_url)

    async def crawl_sitemap(self, sess, sitemap_url):
        status, body, _ = await self._get(sess, sitemap_url)
        await delay()
        if not body or status != 200:
            return
        urls = re.findall(r'<loc>([^<]+)</loc>', body)
        for u in urls[:50]:
            norm = self._normalize(u)
            if norm and self._in_scope(norm) and norm not in self.visited:
                self.queue.append(norm)
                self.endpoints.append({'url': norm, 'source': 'sitemap'})

    # ── Admin panel discovery ─────────────────────────────────────────────────

    async def discover_admin_panels(self, sess):
        print("\n[*] Discovering admin panels and sensitive paths...")
        ADMIN_PATHS = [
            '/admin', '/admin/', '/administrator', '/admin/login',
            '/wp-admin', '/wp-admin/admin-ajax.php', '/wp-login.php',
            '/login', '/signin', '/auth', '/auth/login',
            '/dashboard', '/panel', '/cpanel', '/controlpanel',
            '/manager', '/management', '/console', '/webconsole',
            '/phpmyadmin', '/pma', '/mysqladmin', '/dbadmin',
            '/jenkins', '/jira', '/confluence', '/gitlab', '/grafana',
            '/kibana', '/elastic', '/solr', '/redis',
            '/api', '/api/v1', '/api/v2', '/api/swagger', '/swagger-ui.html',
            '/swagger', '/openapi.json', '/swagger.json', '/api-docs',
            '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/config', '/config.json', '/config.yaml', '/config.yml',
            '/settings', '/setup', '/install',
            '/server-status', '/server-info', '/status', '/health',
            '/healthz', '/readyz', '/livez', '/ping', '/info',
            '/metrics', '/actuator', '/actuator/health', '/actuator/env',
            '/debug', '/debug/vars', '/debug/pprof',
            '/trace', '/tracing', '/_debug', '/__debug__',
            '/shell', '/terminal', '/cmd', '/exec',
            '/backup', '/backups', '/dump', '/exports', '/downloads',
            '/upload', '/uploads', '/files', '/static', '/assets',
            '/graphql', '/graphiql', '/playground',
            '/telescope', '/horizon', '/_ignition',
            '/nagios', '/zabbix', '/prometheus',
            '/.git', '/.git/HEAD', '/.svn', '/.svn/entries',
            '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
        ]
        found = 0
        for path in ADMIN_PATHS:
            url = self.target + path
            if url in self.visited:
                continue
            status, body, hdrs = await self._get(sess, url)
            await delay()
            if status is None:
                continue
            if is_likely_real_vuln(body or '', status, self.baseline_404, 200, 403):
                found += 1
                is_sensitive = any(x in path for x in [
                    '.env', '.git', 'admin', 'config', 'debug', 'shell',
                    'backup', 'phpmyadmin', 'actuator', 'terminal', 'cmd'
                ])
                sev = 'HIGH' if is_sensitive else 'MEDIUM'
                conf = confidence_score({
                    'status_200':  (status == 200, 50),
                    'body_size':   (len(body or '') > 500, 30),
                    'not_generic': (is_sensitive, 20),
                })
                self.findings.append({
                    'type':             'ADMIN_PANEL_FOUND',
                    'severity':         severity_from_confidence(sev, conf),
                    'confidence':       conf,
                    'confidence_label': confidence_label(conf),
                    'url':              url,
                    'status':           status,
                    'size':             len(body or ''),
                    'detail':           f"Sensitive path accessible: {path} ({status})",
                    'remediation':      "Restrict access to administrative interfaces with IP allowlisting and authentication.",
                })
                self.endpoints.append({'url': url, 'source': 'admin_discovery', 'status': status})
                print(f"  [{sev}] {url} ({status}) [conf:{conf}%]")
        print(f"  [+] Admin discovery: {found} sensitive paths found")

    # ── Cloud metadata endpoints ──────────────────────────────────────────────

    async def discover_cloud_metadata(self, sess):
        print("\n[*] Probing for cloud metadata and SSRF surfaces...")
        METADATA_PATHS = [
            '/latest/meta-data/',             # AWS EC2
            '/metadata/instance',              # Azure
            '/computeMetadata/v1/',            # GCP
            '/opc/v1/instance/',               # Oracle Cloud
            '/metadata/v1',                    # DigitalOcean
            '/v1.0/metadata',                  # Alibaba Cloud
            '/.well-known/security.txt',
            '/security.txt',
            '/humans.txt',
        ]
        for path in METADATA_PATHS:
            url = self.target + path
            status, body, _ = await self._get(sess, url)
            await delay()
            if status == 200 and body and len(body.strip()) > 20:
                is_cloud = any(x in (body or '').lower() for x in [
                    'ami-id', 'instance-id', 'compute.googleapis', 'azure',
                    'digitalocean', 'alibaba'
                ])
                sev = 'CRITICAL' if is_cloud else 'LOW'
                self.findings.append({
                    'type':             'CLOUD_METADATA' if is_cloud else 'INFO_FILE',
                    'severity':         sev,
                    'confidence':       90 if is_cloud else 60,
                    'confidence_label': 'High' if is_cloud else 'Medium',
                    'url':              url,
                    'detail':           f"{'Cloud metadata endpoint' if is_cloud else 'Info file'} accessible: {path}",
                    'remediation':      "Block access to cloud metadata endpoints at the network level.",
                })
                print(f"  [{sev}] {url}")

    # ── JavaScript parsing ────────────────────────────────────────────────────

    async def parse_javascript(self, sess, js_url):
        if js_url in self.js_visited or len(self.js_visited) >= MAX_JS_FILES:
            return
        self.js_visited.add(js_url)
        status, body, _ = await self._get(sess, js_url, timeout=12)
        await delay()
        if not body or status != 200:
            return

        # API route extraction patterns
        patterns = [
            r'["\'`](/api/[^\s"\'`?#]{3,80})',
            r'["\'`](/v\d+/[^\s"\'`?#]{3,80})',
            r'["\'`]/(graphql|gql)[^\s"\'`]{0,20}',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
            r'(?:url|endpoint|baseUrl|apiUrl)\s*[:=]\s*["\']([^"\']{5,100})["\']',
        ]
        found_routes = set()
        for pattern in patterns:
            for match in re.findall(pattern, body):
                if isinstance(match, str) and match.startswith('/'):
                    found_routes.add(match)
                elif isinstance(match, str) and match.startswith('http'):
                    parsed = urlparse(match)
                    if parsed.hostname == self.host:
                        found_routes.add(parsed.path)

        # Parameter mining
        param_patterns = [
            r'\?([a-zA-Z_][a-zA-Z0-9_]{1,40})=',
            r'params\[["\']([\w]{2,40})["\']\]',
            r'body\[["\']([\w]{2,40})["\']\]',
        ]
        for pattern in param_patterns:
            self.params.update(re.findall(pattern, body))

        for route in found_routes:
            url = self._normalize(route)
            if url and url not in self.visited:
                self.endpoints.append({'url': url, 'source': 'js_parse', 'js_file': js_url})
                self.queue.append(url)

        # Secret leak detection in JS
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', 'API_KEY'),
            (r'(?:secret|token|password|passwd)\s*[:=]\s*["\']([A-Za-z0-9_\-./]{12,})["\']', 'SECRET'),
            (r'AKIA[0-9A-Z]{16}', 'AWS_KEY'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'GOOGLE_API_KEY'),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'GITHUB_TOKEN'),
            (r'sk-[A-Za-z0-9]{32,}', 'OPENAI_KEY'),
            (r'xox[baprs]-[0-9A-Za-z]{10,}', 'SLACK_TOKEN'),
        ]
        blacklist = {'example', 'test', 'demo', 'placeholder', 'your_', 'insert_'}
        for pattern, dtype in secret_patterns:
            for match in re.findall(pattern, body, re.IGNORECASE):
                val = match if isinstance(match, str) else (match[0] if match else '')
                if not val or len(val) < 12:
                    continue
                if any(b in val.lower() for b in blacklist):
                    continue
                self.findings.append({
                    'type':             'SECRET_IN_JS',
                    'severity':         'CRITICAL',
                    'confidence':       85,
                    'confidence_label': 'High',
                    'url':              js_url,
                    'data_type':        dtype,
                    'preview':          val[:30] + '...',
                    'detail':           f"{dtype} hardcoded in JavaScript: {js_url}",
                    'remediation':      "Move secrets to server-side environment variables. Rotate the exposed credential immediately.",
                })
                print(f"  [CRITICAL] {dtype} in JS: {js_url}")

    # ── HTML page crawler ─────────────────────────────────────────────────────

    async def crawl_page(self, sess, url):
        if url in self.visited or len(self.visited) >= MAX_PAGES:
            return
        self.visited.add(url)

        status, body, hdrs = await self._get(sess, url)
        await delay()
        if not body or status is None:
            return

        # Tech/WAF detection on first page
        if len(self.visited) == 1:
            self.tech = detect_tech(hdrs, body)
            self.waf  = detect_waf(hdrs)
            if self.tech:
                print(f"  [TECH] Detected: {', '.join(self.tech)}")
            if self.waf:
                print(f"  [WAF]  Detected: {', '.join(self.waf)}")

        ct = hdrs.get('Content-Type', '').lower()
        if 'html' not in ct:
            return

        # Extract links
        href_re   = re.compile(r'href=["\']([^"\'#?]+)', re.I)
        action_re = re.compile(r'action=["\']([^"\']+)', re.I)
        src_re    = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)

        for href in href_re.findall(body):
            norm = self._normalize(href, url)
            if norm and self._in_scope(norm) and norm not in self.visited:
                self.queue.append(norm)
                self.endpoints.append({'url': norm, 'source': 'html_crawl'})

        for action in action_re.findall(body):
            norm = self._normalize(action, url)
            if norm and self._in_scope(norm):
                self.endpoints.append({'url': norm, 'source': 'form_action'})

        for js_src in src_re.findall(body):
            js_url = self._normalize(js_src, url)
            if js_url and self._in_scope(js_url):
                await self.parse_javascript(sess, js_url)

        # Extract forms
        form_re   = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
        input_re  = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
        for form_match in form_re.findall(body):
            fields = input_re.findall(form_match)
            self.forms.append({'page': url, 'fields': fields})
            self.params.update(fields)

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  GhostCrawler v2 — Attack Surface Mapper")
        print("=" * 60)

        conn    = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=60)

        async with aiohttp.ClientSession(connector=conn, timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/2.0)'}) as sess:

            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)

            await self.crawl_robots(sess)
            self.queue.append(self.target)

            print(f"\n[*] Crawling (max {MAX_PAGES} pages)...")
            while self.queue and len(self.visited) < MAX_PAGES:
                url = self.queue.pop(0)
                if url not in self.visited and self._in_scope(url):
                    await self.crawl_page(sess, url)

            print(f"  [+] Crawled {len(self.visited)} pages, found {len(self.endpoints)} endpoints")

            await self.discover_admin_panels(sess)
            await self.discover_cloud_metadata(sess)

        # Summary finding
        unique_endpoints = list({e['url'] for e in self.endpoints})
        self.findings.insert(0, {
            'type':          'ATTACK_SURFACE_SUMMARY',
            'severity':      'INFO',
            'confidence':    100,
            'confidence_label': 'High',
            'pages_crawled': len(self.visited),
            'endpoints':     len(unique_endpoints),
            'js_files':      len(self.js_visited),
            'forms':         len(self.forms),
            'params':        sorted(self.params),
            'tech':          self.tech,
            'waf':           self.waf,
            'detail':        f"Attack surface: {len(unique_endpoints)} endpoints, {len(self.forms)} forms, {len(self.params)} params",
        })
        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u


def main():
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    scanner  = GhostCrawler(target)
    findings = asyncio.run(scanner.run())
    with open("reports/ghostcrawler.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/ghostcrawler.json")


if __name__ == '__main__':
    main()
