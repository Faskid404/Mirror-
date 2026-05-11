#!/usr/bin/env python3
"""TokenSniper v3 — fixes: entropy gate tightened, confidence floor, proxy, proof."""
import asyncio, aiohttp, json, re, sys, hashlib
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_truly_accessible, delay, confidence_score,
    confidence_label, shannon_entropy, meets_confidence_floor, random_ua,
    REQUEST_DELAY
)

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',                                          'AWS_ACCESS_KEY',     'CRITICAL', 3.5),
    (r'AIza[0-9A-Za-z\-_]{35}',                                    'GOOGLE_API_KEY',     'HIGH',     3.5),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}',             'GITHUB_TOKEN',       'CRITICAL', 4.0),
    (r'github_pat_[A-Za-z0-9_]{82}',                               'GITHUB_PAT',         'CRITICAL', 4.0),
    (r'xox[baprs]-[0-9A-Za-z\-]{10,80}',                          'SLACK_TOKEN',        'HIGH',     4.0),
    (r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+','SLACK_WEBHOOK','HIGH',3.5),
    (r'sk_live_[0-9a-zA-Z]{24,}',                                  'STRIPE_SECRET_KEY',  'CRITICAL', 4.0),
    (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',               'SENDGRID_API_KEY',   'HIGH',     4.0),
    (r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',               'OPENAI_API_KEY',     'CRITICAL', 4.5),
    (r'sk-proj-[A-Za-z0-9_\-]{40,}',                              'OPENAI_PROJECT_KEY', 'CRITICAL', 4.5),
    (r'sk-ant-api03-[A-Za-z0-9_\-]{90,}',                         'ANTHROPIC_KEY',      'CRITICAL', 4.5),
    (r'postgres(?:ql)?://[^\s"\'<>]{8,120}',                       'POSTGRES_URI',       'CRITICAL', 3.5),
    (r'mongodb(?:\+srv)?://[^\s"\'<>]{8,120}',                     'MONGODB_URI',        'CRITICAL', 3.5),
    (r'redis://:[^\s"\'<>]{8,80}',                                 'REDIS_URI',          'HIGH',     3.5),
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',    'PRIVATE_KEY',        'CRITICAL', 5.0),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}','JWT_TOKEN','MEDIUM',3.0),
    (r'(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-./+]{20,})["\']','GENERIC_API_KEY','HIGH',3.8),
    (r'dop_v1_[a-fA-F0-9]{64}',                                   'DIGITALOCEAN_TOKEN', 'CRITICAL', 4.5),
    (r'npm_[A-Za-z0-9]{36}',                                      'NPM_TOKEN',          'HIGH',     4.0),
]

EXPOSURE_PATHS = [
    '/.env','/.env.local','/.env.production','/.env.staging','/.env.backup',
    '/config/.env','/app/.env','/backend/.env',
    '/config.json','/config.yaml','/settings.py','/local_settings.py',
    '/credentials.json','/service-account.json',
    '/.git/config','/.git/HEAD','/.git/COMMIT_EDITMSG',
    '/actuator/env','/actuator/configprops',
    '/package.json','/.npmrc',
]

BLACKLIST = {'example','test','demo','placeholder','your_','insert_','changeme','xxxx','aaaa'}

class TokenSniper:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.seen     = set()
        self.baseline_404 = ""

    async def _get(self, sess, url):
        try:
            async with sess.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10),
                                allow_redirects=True) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    def _scan(self, text, source_url, source_type="body"):
        if not text: return
        for pattern, dtype, sev, min_ent in SECRET_PATTERNS:
            for match in re.findall(pattern, text):
                val = match if isinstance(match, str) else (match[0] if match else '')
                if not val or len(val) < 12: continue
                ent = shannon_entropy(val)
                if ent < min_ent: continue
                if any(b in val.lower() for b in BLACKLIST): continue
                h = hashlib.md5(val[:40].encode()).hexdigest()
                if h in self.seen: continue
                self.seen.add(h)
                conf = 90 if min_ent >= 4.0 else 72
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type':f'SECRET_{dtype}','severity':sev,'confidence':conf,
                        'confidence_label':confidence_label(conf),
                        'data_type':dtype,'source':source_type,'url':source_url,
                        'preview':val[:32]+('...' if len(val)>32 else ''),
                        'entropy':round(ent,2),
                        'proof':f"{dtype} pattern matched in {source_type} at {source_url} (entropy {ent:.2f} >= {min_ent})",
                        'detail':f"{dtype} found in {source_type} at {source_url}",
                        'remediation':f"Rotate the {dtype} immediately. Move secrets to a secret manager.",
                    })
                    print(f"  [{sev}] {dtype} at {source_url} (entropy:{ent:.1f})")

    async def scan_exposure_paths(self, sess):
        print("\n[*] Scanning for exposed secret files...")
        for path in EXPOSURE_PATHS:
            url = self.target + path
            s, b, hdrs = await self._get(sess, url)
            await delay()
            if not is_truly_accessible(s) or not b or len(b) < 10: continue
            print(f"  [+] Accessible: {url} ({s}, {len(b)}b)")
            self._scan(b, url, "exposed_file")
            is_crit = any(x in path for x in ['.env','.git','credentials','service-account','secrets'])
            self.findings.append({
                'type':'FILE_EXPOSURE','severity':'HIGH' if is_crit else 'MEDIUM',
                'confidence':90,'confidence_label':'High','url':url,'size':len(b),
                'proof':f"HTTP {s} — {len(b)} bytes of content accessible",
                'detail':f"Sensitive file exposed: {path}",
                'remediation':"Block web access to config/secret files. Move outside web root.",
            })

    async def scan_headers(self, sess):
        print("\n[*] Scanning response headers for secrets...")
        s, b, hdrs = await self._get(sess, self.target); await delay()
        if hdrs: self._scan(json.dumps(dict(hdrs)), self.target, "response_headers")

    async def scan_js(self, sess):
        print("\n[*] Scanning common JS file paths...")
        for path in ['/static/js/main.js','/js/app.js','/assets/index.js','/dist/bundle.js','/main.js']:
            url = self.target + path
            s, b, _ = await self._get(sess, url); await delay()
            if is_truly_accessible(s) and b and len(b) > 100:
                self._scan(b, url, "javascript")

    async def run(self):
        print("="*60)
        print(f"  TokenSniper v3 — {len(SECRET_PATTERNS)} patterns, entropy-gated")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.scan_exposure_paths(sess)
            await self.scan_headers(sess)
            await self.scan_js(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(TokenSniper(target).run())
    with open("reports/tokensniper.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/tokensniper.json")

if __name__ == '__main__': main()
