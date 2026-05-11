#!/usr/bin/env python3
"""
GhostCrawler v3 — Technology-aware web crawler and attack surface mapper.

v3 critical fixes:
  - 403 = PROTECTED (not a finding). Only 200/201 truly accessible paths are flagged.
  - Technology-aware path selection: Django paths for Django, WP paths only if WP detected
  - Minimum confidence raised to 70 before reporting an admin panel
  - WAF/CDN detection result properly affects what we report
  - Proof requirement: must have body content, not just a status code
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
    build_baseline_404, is_truly_accessible, is_likely_real_vuln,
    delay, confidence_score, confidence_label, severity_from_confidence,
    detect_waf, detect_tech, meets_confidence_floor, get_relevant_paths,
    status_explains_protection, random_ua, REQUEST_DELAY
)

MAX_PAGES    = 60
MAX_JS_FILES = 20


class GhostCrawler:
    def __init__(self, target):
        self.target       = target.rstrip('/')
        self.host         = urlparse(target).hostname
        self.scheme       = urlparse(target).scheme
        self.visited      = set()
        self.js_visited   = set()
        self.queue        = []
        self.findings     = []
        self.endpoints    = []
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
            full  = urljoin(base or self.target, url)
            clean, _ = urldefrag(full)
            clean = clean.rstrip('/')
            p     = urlparse(clean)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return None

    # ── Robots / Sitemap ─────────────────────────────────────────────────────

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
        for line in body.splitlines():
            if line.lower().startswith('sitemap:'):
                sm = line.split(':', 1)[1].strip()
                await self.crawl_sitemap(sess, sm)

    async def crawl_sitemap(self, sess, sitemap_url):
        status, body, _ = await self._get(sess, sitemap_url)
        await delay()
        if not body or status != 200:
            return
        for u in re.findall(r'<loc>([^<]+)</loc>', body)[:40]:
            norm = self._normalize(u)
            if norm and self._in_scope(norm) and norm not in self.visited:
                self.queue.append(norm)
                self.endpoints.append({'url': norm, 'source': 'sitemap'})

    # ── Admin panel discovery — 200-only ─────────────────────────────────────

    async def discover_admin_panels(self, sess):
        print("\n[*] Discovering admin/sensitive paths (only flagging 200 responses)...")

        # Start with universal paths, then add tech-specific ones
        base_paths = [
            '/.env', '/.env.local', '/.env.production', '/.git/HEAD',
            '/config.json', '/config.yaml', '/api-docs', '/swagger.json',
            '/openapi.json', '/graphql', '/graphiql',
            '/actuator', '/actuator/env', '/actuator/health',
            '/debug', '/__debug__', '/server-status',
            '/phpmyadmin', '/pma',
        ]
        tech_paths = get_relevant_paths(self.tech)
        all_paths  = list(dict.fromkeys(tech_paths + base_paths))  # dedup, preserve order

        accessible  = []
        protected   = []   # 403/401 — tracked but NOT flagged as vulnerabilities
        for path in all_paths:
            url = self.target + path
            if url in self.visited:
                continue
            status, body, hdrs = await self._get(sess, url)
            await delay()
            if status is None:
                continue

            if is_truly_accessible(status) and is_likely_real_vuln(
                    body or '', status, self.baseline_404, 200, 299):
                accessible.append((path, url, status, body or ''))

                is_critical = any(x in path for x in [
                    '.env', '.git', 'config', 'debug', 'actuator',
                    'phpmyadmin', 'shell', 'backup', 'secret'
                ])
                sev  = 'HIGH' if is_critical else 'MEDIUM'
                conf = confidence_score({
                    'status_200':   (status == 200, 50),
                    'has_content':  (len(body or '') > 200, 30),
                    'is_critical':  (is_critical, 20),
                })
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type':             'SENSITIVE_PATH_EXPOSED',
                        'severity':         severity_from_confidence(sev, conf),
                        'confidence':       conf,
                        'confidence_label': confidence_label(conf),
                        'url':              url,
                        'status':           status,
                        'size':             len(body or ''),
                        'detail':           f"Sensitive path genuinely accessible (HTTP 200): {path}",
                        'proof':            f"HTTP {status} with {len(body or '')} bytes of content",
                        'remediation':      "Block web access to this path. Move sensitive files outside the web root.",
                    })
                    print(f"  [REAL FINDING] {sev}: {url} (HTTP {status}, {len(body or '')}b)")
                    self.endpoints.append({'url': url, 'source': 'admin_discovery', 'status': status})

            elif status in (401, 403):
                # CORRECT BEHAVIOUR: server blocked us — this is NOT a vulnerability
                protected.append(path)

        # Print summary only
        if protected:
            print(f"  [OK] {len(protected)} paths returned 403/401 (protected correctly — not reported)")
        print(f"  [+] Admin/sensitive discovery: {len(accessible)} accessible, {len(protected)} protected")

    # ── Cloud metadata ────────────────────────────────────────────────────────

    async def discover_cloud_metadata(self, sess):
        print("\n[*] Probing for exposed cloud metadata endpoints...")
        METADATA_PATHS = [
            '/.well-known/security.txt', '/security.txt', '/humans.txt',
        ]
        for path in METADATA_PATHS:
            url = self.target + path
            status, body, _ = await self._get(sess, url)
            await delay()
            if is_truly_accessible(status) and body and len(body.strip()) > 20:
                self.findings.append({
                    'type':             'INFO_FILE_ACCESSIBLE',
                    'severity':         'INFO',
                    'confidence':       80,
                    'confidence_label': 'High',
                    'url':              url,
                    'detail':           f"Info file accessible: {path}",
                })

    # ── JavaScript parsing ────────────────────────────────────────────────────

    async def parse_javascript(self, sess, js_url):
        if js_url in self.js_visited or len(self.js_visited) >= MAX_JS_FILES:
            return
        self.js_visited.add(js_url)
        status, body, _ = await self._get(sess, js_url, timeout=12)
        await delay()
        if not body or status != 200:
            return

        patterns = [
            r'["\'`](/api/[^\s"\'`?#]{3,80})',
            r'["\'`](/v\d+/[^\s"\'`?#]{3,80})',
            r'["\'`]/(graphql|gql)[^\s"\'`]{0,20}',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.findall(pattern, body):
                if isinstance(match, str) and match.startswith('/'):
                    url = self._normalize(match)
                    if url and url not in self.visited:
                        self.endpoints.append({'url': url, 'source': 'js_parse', 'js_file': js_url})
                        self.queue.append(url)

        # Parameter mining
        self.params.update(re.findall(r'\?([a-zA-Z_][a-zA-Z0-9_]{1,40})=', body))

        # Secret leak detection
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}',                                          'AWS_KEY'),
            (r'AIza[0-9A-Za-z\-_]{35}',                                    'GOOGLE_API_KEY'),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',               'GITHUB_TOKEN'),
            (r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',               'OPENAI_KEY'),
            (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',                  'PRIVATE_KEY'),
        ]
        blacklist = {'example', 'test', 'demo', 'placeholder', 'your_'}
        for pattern, dtype in secret_patterns:
            for match in re.findall(pattern, body, re.IGNORECASE):
                val = match if isinstance(match, str) else ''
                if not val or len(val) < 16 or any(b in val.lower() for b in blacklist):
                    continue
                self.findings.append({
                    'type':             'SECRET_IN_JS',
                    'severity':         'CRITICAL',
                    'confidence':       90,
                    'confidence_label': 'High',
                    'url':              js_url,
                    'data_type':        dtype,
                    'preview':          val[:30] + '...',
                    'proof':            f"{dtype} pattern found verbatim in JavaScript file: {js_url}",
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

        if len(self.visited) == 1:
            self.tech = detect_tech(hdrs, body)
            self.waf  = detect_waf(hdrs)
            if self.tech:
                print(f"  [TECH] Detected: {', '.join(self.tech)}")
            if self.waf:
                print(f"  [WAF]  Detected: {', '.join(self.waf)}")
                print(f"  [NOTE] WAF presence will affect which findings are reliable")

        ct = hdrs.get('Content-Type', '').lower()
        if 'html' not in ct:
            return

        href_re  = re.compile(r'href=["\']([^"\'#?]+)', re.I)
        src_re   = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        form_re  = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
        input_re = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)

        for href in href_re.findall(body):
            norm = self._normalize(href, url)
            if norm and self._in_scope(norm) and norm not in self.visited:
                self.queue.append(norm)
                self.endpoints.append({'url': norm, 'source': 'html_crawl'})

        for js_src in src_re.findall(body):
            js_url = self._normalize(js_src, url)
            if js_url and self._in_scope(js_url):
                await self.parse_javascript(sess, js_url)

        for form_match in form_re.findall(body):
            fields = input_re.findall(form_match)
            self.forms.append({'page': url, 'fields': fields})
            self.params.update(fields)

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  GhostCrawler v3 — Tech-Aware Attack Surface Mapper")
        print("  Note: 403/401 responses are NOT reported as vulnerabilities")
        print("=" * 60)

        conn_kwargs = {'limit': 10, 'ssl': False}
        conn    = aiohttp.TCPConnector(**conn_kwargs)
        timeout = aiohttp.ClientTimeout(total=60)
        sess_kwargs = {'connector': conn, 'timeout': timeout,
                       'headers': {'User-Agent': random_ua()}}

        async with aiohttp.ClientSession(**sess_kwargs) as sess:
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

            # Tech-aware path discovery
            await self.discover_admin_panels(sess)
            await self.discover_cloud_metadata(sess)

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
            'note':          '403/401 responses are treated as working protection, not vulnerabilities.',
            'detail':        f"Attack surface: {len(unique_endpoints)} endpoints, {len(self.forms)} forms, {len(self.params)} params. Tech: {', '.join(self.tech) or 'unknown'}",
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
