#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
import math
import statistics
import string
import random
import time
import json
import re
from collections import Counter
from urllib.parse import urljoin
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import REQUEST_DELAY

WORDLIST = [
    "admin", "admin/login", "administrator", "api", "api/v1", "api/v2",
    "api/internal", "backup", "config", "config.json", "debug", "dev",
    "staging", "test", ".git/config", ".git/HEAD", ".env", ".env.local",
    ".env.production", ".svn/entries", "wp-admin", "phpmyadmin", "console",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "server-status", "swagger", "swagger-ui", "api-docs", "graphql",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "login",
    "upload", "internal", "private", "dashboard", "panel",
    "api/v1/users", "api/v2/users", "api/v1/admin", "api/v2/admin",
    "api/internal/config", "api/keys", "api/tokens",
    "settings.py", "docker-compose.yml", "package.json",
    "secrets.json", "credentials.json", "application.yml",
]

TOKEN_PATTERNS = [
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT'),
    (r'AKIA[0-9A-Z]{16}', 'AWS_KEY'),
    (r'AIza[0-9A-Za-z_-]{35}', 'GOOGLE_KEY'),
    (r'"api[_-]?key"\s*:\s*"([^"]{20,})"', 'API_KEY'),
    (r'"access[_-]?token"\s*:\s*"([^"]{20,})"', 'ACCESS_TOKEN'),
    (r'"secret"\s*:\s*"([^"]{10,})"', 'SECRET'),
    (r'"password"\s*:\s*"([^"]{8,})"', 'PASSWORD_LEAK'),
    (r'bearer\s+([A-Za-z0-9_-]{20,})', 'BEARER'),
    (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'PRIVATE_KEY'),
]

NOT_FOUND_PHRASES = [
    "page not found", "404", "not found", "sorry", "does not exist",
    "no page found", "couldn't find", "could not find",
]


class GhostCrawler:
    def __init__(self, target, conc=10):
        self.target = target.rstrip('/')
        self.conc = conc
        self.baseline = None
        self.findings = []
        self.tokens = []

    @staticmethod
    def entropy(s):
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v/n)*math.log2(v/n) for v in c.values())

    @staticmethod
    def randpath(n=22):
        return ''.join(random.choices(string.ascii_lowercase+string.digits, k=n))

    def scan_tokens(self, body, url):
        blacklist = {'password', 'token', 'api_key', 'changeme', 'example', 'test', 'your_key'}
        for pattern, ttype in TOKEN_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                value = match if isinstance(match, str) else match
                if value.lower() in blacklist or len(value) < 10:
                    continue
                self.tokens.append({'type': ttype, 'value': value[:80], 'url': url})
                print(f"  [TOKEN] {ttype} found at {url}")

    async def fetch(self, sess, path):
        url = urljoin(self.target+'/', path.lstrip('/'))
        t0 = time.perf_counter()
        try:
            timeout = aiohttp.ClientTimeout(total=12)
            async with sess.get(url, allow_redirects=False, timeout=timeout) as r:
                body = await r.text(errors='ignore')
                self.scan_tokens(body, url)
                return {
                    'path': path,
                    'url': url,
                    'status': r.status,
                    'len': len(body),
                    'ent': self.entropy(body[:4096]),
                    'time': round(time.perf_counter()-t0, 3),
                    'hash': hashlib.md5(body.encode(errors='ignore')).hexdigest()[:12],
                    'server': r.headers.get('Server', ''),
                    'content_type': r.headers.get('Content-Type', ''),
                    'body_preview': body[:200],
                }
        except Exception as e:
            return {'path': path, 'error': str(e)[:80]}

    async def baseline_phase(self, sess):
        print("[*] Building behavioral baseline (random paths)...")
        tasks = [self.fetch(sess, self.randpath()) for _ in range(8)]
        results = await asyncio.gather(*tasks)
        rs = [r for r in results if 'error' not in r]
        if not rs:
            raise RuntimeError("Target unreachable")
        self.baseline = {
            'statuses': Counter(r['status'] for r in rs),
            'avg_len': statistics.mean(r['len'] for r in rs),
            'std_len': statistics.pstdev(r['len'] for r in rs) or 1,
            'avg_ent': statistics.mean(r['ent'] for r in rs),
            'hashes': {r['hash'] for r in rs},
        }
        print(f"[+] Baseline: {dict(self.baseline['statuses'])} avg_len={self.baseline['avg_len']:.0f}")

    def is_404_like(self, body):
        if not body:
            return True
        b = body.lower()
        return any(phrase in b for phrase in NOT_FOUND_PHRASES)

    def score(self, r):
        if 'error' in r:
            return 0, []
        s, why = 0, []
        if r['status'] not in self.baseline['statuses']:
            s += 3
            why.append(f"status={r['status']}")
        z = abs(r['len']-self.baseline['avg_len'])/self.baseline['std_len']
        if z > 3:
            s += 2
            why.append(f"size_z={z:.1f}")
        if abs(r['ent']-self.baseline['avg_ent']) > 0.8:
            s += 2
            why.append("entropy_drift")
        if r['hash'] not in self.baseline['hashes'] and r['status'] == 200:
            s += 2
            why.append("unique_body")

        if self.is_404_like(r.get('body_preview', '')):
            s = max(0, s - 4)
            why.append("404_like_body_penalised")

        if r.get('len', 0) < 300 and r['status'] == 200:
            s = max(0, s - 2)
            why.append("too_small")

        return s, why

    async def scan(self):
        conn = aiohttp.TCPConnector(limit=self.conc, ssl=False)
        async with aiohttp.ClientSession(
            connector=conn,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            await self.baseline_phase(sess)
            sem = asyncio.Semaphore(self.conc)

            async def bounded(p):
                async with sem:
                    result = await self.fetch(sess, p)
                    await asyncio.sleep(REQUEST_DELAY)
                    return result

            tasks = [bounded(w) for w in WORDLIST]
            print(f"\n[*] Probing {len(tasks)} paths...\n")

            for coro in asyncio.as_completed(tasks):
                r = await coro
                sc, why = self.score(r)
                if sc >= 4:
                    print(f"[!] HIT {r['status']} /{r['path']:40s} score={sc} {why}")
                    self.findings.append({**r, 'score': sc, 'reasons': why, 'confidence': min(100, sc * 15)})

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://"+u


def main():
    print("="*60)
    print("  GhostCrawler — Endpoint Discovery + Token Scanner")
    print("="*60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)

    crawler = GhostCrawler(target)
    findings = asyncio.run(crawler.scan())

    with open("reports/ghostcrawler.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} endpoints -> reports/ghostcrawler.json")

    if crawler.tokens:
        with open("reports/tokens_found.json", 'w') as f:
            json.dump(crawler.tokens, f, indent=2)
        print(f"[!] {len(crawler.tokens)} tokens found -> reports/tokens_found.json")
        for t in crawler.tokens:
            print(f"    [{t['type']}] {t['value'][:50]}")

if __name__ == '__main__':
    main()
