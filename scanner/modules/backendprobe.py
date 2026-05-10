#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import re
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, is_likely_real_vuln,
    confidence_score, confidence_label, severity_from_confidence,
    REQUEST_DELAY
)

class BackendProbe:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.host = urlparse(target).hostname
        self.baseline_404 = ""

    async def _get(self, sess, url, headers=None):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with sess.get(
                url, headers=headers or {}, ssl=False,
                timeout=timeout, allow_redirects=False
            ) as r:
                return r.status, await r.text(errors='ignore'), dict(r.headers)
        except Exception:
            return None, None, {}

    async def _post(self, sess, url, data=None, headers=None):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with sess.post(
                url, json=data or {}, headers=headers or {},
                ssl=False, timeout=timeout
            ) as r:
                return r.status, await r.text(errors='ignore')
        except Exception:
            return None, None

    async def scan_tech_stack(self, sess):
        print("\n[*] Detecting technology stack...")
        status, body, headers = await self._get(sess, self.target)
        if not headers:
            return

        tech_indicators = {
            'PHP': ['X-Powered-By: PHP', 'PHPSESSID', '.php'],
            'ASP.NET': ['X-AspNet-Version', 'ASP.NET', '__VIEWSTATE'],
            'Java': ['JSESSIONID'],
            'Node.js': ['X-Powered-By: Express', 'connect.sid'],
            'Python': ['csrfmiddlewaretoken', 'wsgi'],
            'Ruby': ['rack.session', '_rails'],
            'WordPress': ['wp-content', 'wp-includes'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'Django': ['csrftoken'],
            'Spring': ['JSESSIONID', 'spring'],
            'Express': ['X-Powered-By: Express'],
        }

        headers_str = str(headers).lower()
        body_check = (body or '')[:5000].lower()

        for tech, indicators in tech_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str or indicator.lower() in body_check:
                    self.findings.append({
                        'type': 'TECH_STACK_DETECTED',
                        'severity': 'INFO',
                        'confidence': 70,
                        'confidence_label': 'Medium',
                        'technology': tech,
                        'indicator': indicator,
                        'detail': f'{tech} detected via {indicator}'
                    })
                    print(f"  [TECH] {tech} detected via '{indicator}'")
                    break

    async def scan_debug_endpoints(self, sess):
        print("\n[*] Scanning debug and admin endpoints...")
        debug_paths = [
            '/actuator/env', '/actuator/heapdump', '/actuator/threaddump',
            '/actuator/beans', '/actuator/mappings', '/h2-console',
            '/__debug__', '/phpinfo.php', '/server-status',
            '/api/debug', '/api/config', '/admin/config',
            '/telescope', '/graphql/playground', '/graphiql',
            '/swagger-ui.html', '/openapi.json', '/swagger.json',
            '/v2/api-docs', '/v3/api-docs', '/wp-json/wp/v2',
        ]

        for path in debug_paths:
            url = self.target + path
            status, body, hdrs = await self._get(sess, url)
            await asyncio.sleep(REQUEST_DELAY)

            if status is None:
                continue

            if status in [401, 403]:
                self.findings.append({
                    'type': 'PROTECTED_ENDPOINT_FOUND',
                    'severity': 'LOW',
                    'confidence': 50,
                    'confidence_label': 'Low',
                    'url': url,
                    'status': status,
                    'detail': f'Protected endpoint exists: {path}'
                })
                print(f"  [LOW] Protected endpoint: {url} ({status})")
                continue

            if not is_likely_real_vuln(body or "", status or 0, self.baseline_404):
                continue

            is_critical_path = any(x in path for x in [
                'actuator', 'debug', 'config', 'env', 'heapdump', 'threaddump'
            ])
            conf = confidence_score({
                'status_200': (status == 200, 40),
                'body_size': (len(body or '') > 300, 30),
                'critical_path': (is_critical_path, 20),
                'meaningful_content': (is_likely_real_vuln(body or "", status or 0, self.baseline_404), 10),
            })
            base_sev = 'CRITICAL' if is_critical_path else 'HIGH'
            sev = severity_from_confidence(base_sev, conf)

            self.findings.append({
                'type': 'DEBUG_ENDPOINT_EXPOSED',
                'severity': sev,
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'status': status,
                'response_size': len(body or ''),
                'preview': (body or '')[:200],
                'detail': f'Debug/admin endpoint accessible: {path}'
            })
            print(f"  [{sev}] Debug endpoint: {url} ({status}) size={len(body or '')}b [confidence: {confidence_label(conf)}]")

            if body:
                self.extract_sensitive_from_body(body, url)

    def extract_sensitive_from_body(self, body, url):
        patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS_KEY'),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT'),
            (r'-----BEGIN.*PRIVATE KEY-----', 'PRIVATE_KEY'),
            (r'password["\s:=]+([^\s,"\'}{]{8,})', 'PASSWORD'),
            (r'api[_-]?key["\s:=]+([^\s,"\'}{]{16,})', 'API_KEY'),
            (r'mongodb://[^\s"\']+', 'MONGODB_URI'),
            (r'mysql://[^\s"\']+', 'MYSQL_URI'),
            (r'postgres://[^\s"\']+', 'POSTGRES_URI'),
            (r'redis://[^\s"\']+', 'REDIS_URI'),
            (r'\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b', 'INTERNAL_IP'),
        ]
        blacklist = {'password', 'secret', 'key', 'changeme'}
        for pattern, dtype in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                val = match if isinstance(match, str) else str(match)
                if len(val) < 4 or val.lower() in blacklist:
                    continue
                self.findings.append({
                    'type': 'SENSITIVE_DATA_EXPOSED',
                    'severity': 'CRITICAL',
                    'confidence': 85,
                    'confidence_label': 'High',
                    'data_type': dtype,
                    'value_preview': val[:30] + ('...' if len(val) > 30 else ''),
                    'url': url,
                    'detail': f'{dtype} found in response body'
                })
                print(f"  [CRITICAL] {dtype} exposed at {url}: {val[:30]}...")

    async def scan_environment_files(self, sess):
        print("\n[*] Scanning for exposed environment/config files...")
        env_files = [
            '/.env', '/.env.local', '/.env.production',
            '/.env.staging', '/.env.backup',
            '/config.json', '/config.yml', '/config.yaml',
            '/wp-config.php', '/application.yml',
            '/settings.py', '/appsettings.json',
            '/secrets.json', '/.git/config', '/.git/HEAD',
            '/docker-compose.yml', '/terraform.tfstate',
        ]
        for path in env_files:
            url = self.target + path
            status, body, _ = await self._get(sess, url)
            await asyncio.sleep(REQUEST_DELAY)

            if not is_likely_real_vuln(body or "", status or 0, self.baseline_404):
                continue
            if len(body or '') < 10:
                continue

            is_critical = any(x in path for x in ['.env', 'secret', 'credential', 'tfstate'])
            conf = confidence_score({
                'status_200': (status == 200, 40),
                'has_content': (len(body or '') > 20, 40),
                'critical_file': (is_critical, 20),
            })
            sev = severity_from_confidence('CRITICAL' if is_critical else 'HIGH', conf)

            self.findings.append({
                'type': 'CONFIG_FILE_EXPOSED',
                'severity': sev,
                'confidence': conf,
                'confidence_label': confidence_label(conf),
                'url': url,
                'file': path,
                'size': len(body or ''),
                'preview': (body or '')[:300],
                'detail': f'Sensitive config file accessible: {path}'
            })
            print(f"  [{sev}] Config file exposed: {url} ({len(body or '')}b) [confidence: {confidence_label(conf)}]")
            self.extract_sensitive_from_body(body or "", url)

    async def scan_cors_misconfig(self, sess):
        print("\n[*] Scanning CORS configuration...")
        test_origins = [
            'https://evil.com',
            f'https://evil.{self.host}',
            'null',
        ]
        endpoints = [self.target, self.target + '/api']

        for endpoint in endpoints:
            for origin in test_origins:
                status, body, hdrs = await self._get(
                    sess, endpoint, headers={'Origin': origin}
                )
                await asyncio.sleep(REQUEST_DELAY)
                acao = hdrs.get('Access-Control-Allow-Origin', '')
                acac = hdrs.get('Access-Control-Allow-Credentials', '')

                if acao == origin:
                    has_creds = acac.lower() == 'true'
                    conf = confidence_score({
                        'origin_reflected': (True, 60),
                        'credentials_allowed': (has_creds, 30),
                        'status_200': (status == 200, 10),
                    })
                    sev = severity_from_confidence('CRITICAL' if has_creds else 'HIGH', conf)
                    self.findings.append({
                        'type': 'CORS_MISCONFIGURATION',
                        'severity': sev,
                        'confidence': conf,
                        'confidence_label': confidence_label(conf),
                        'endpoint': endpoint,
                        'reflected_origin': origin,
                        'credentials_allowed': acac,
                        'proof': f'ACAO header set to {origin}',
                        'detail': f'Origin {origin} reflected — cross-origin requests possible'
                    })
                    print(f"  [{sev}] CORS: {origin} reflected at {endpoint} (credentials: {acac}) [confidence: {confidence_label(conf)}]")

    async def scan_ssrf_vectors(self, sess):
        print("\n[*] Scanning for SSRF vectors...")
        ssrf_params = ['url', 'uri', 'dest', 'redirect', 'callback', 'fetch', 'src', 'proxy']
        ssrf_payloads = [
            ('http://169.254.169.254/latest/meta-data/', ['ami-id', 'instance-id', 'local-ipv4', 'security-credentials', 'iam']),
            ('http://127.0.0.1/', ['root:x:0:0', 'localhost', '127.0.0.1']),
        ]

        for param in ssrf_params:
            for payload, proof_indicators in ssrf_payloads:
                url = f"{self.target}?{param}={payload}"
                status, body, _ = await self._get(sess, url)
                await asyncio.sleep(REQUEST_DELAY)
                if not body or status not in [200, 201]:
                    continue
                body_lower = body.lower()
                matched = [ind for ind in proof_indicators if ind in body_lower]
                if matched:
                    is_aws = '169.254' in payload
                    self.findings.append({
                        'type': 'SSRF_AWS_METADATA' if is_aws else 'SSRF_INTERNAL_ACCESS',
                        'severity': 'CRITICAL',
                        'confidence': 95,
                        'confidence_label': 'High',
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'proof': f'Response contained: {matched}',
                        'detail': 'SSRF confirmed — internal content returned in response'
                    })
                    print(f"  [CRITICAL] SSRF confirmed via param={param} — proof: {matched}")

    async def scan_open_ports_services(self):
        print("\n[*] Scanning common backend service ports...")
        backend_ports = {
            3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
            6379: 'Redis', 9200: 'Elasticsearch', 5672: 'RabbitMQ',
        }
        for port, service in backend_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((self.host, port))
                sock.close()
                if result == 0:
                    self.findings.append({
                        'type': 'EXPOSED_BACKEND_SERVICE',
                        'severity': 'HIGH',
                        'confidence': 90,
                        'confidence_label': 'High',
                        'host': self.host,
                        'port': port,
                        'service': service,
                        'proof': f'TCP connection to {self.host}:{port} succeeded',
                        'detail': f'{service} port {port} is publicly accessible'
                    })
                    print(f"  [HIGH] {service} exposed: {self.host}:{port}")
            except Exception:
                pass

    async def scan_graphql(self, sess):
        print("\n[*] Scanning GraphQL endpoints...")
        gql_endpoints = ['/graphql', '/api/graphql', '/gql']
        introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}

        for path in gql_endpoints:
            url = self.target + path
            status, body = await self._post(sess, url, introspection_query)
            await asyncio.sleep(REQUEST_DELAY)
            if status == 200 and body and '__schema' in body:
                self.findings.append({
                    'type': 'GRAPHQL_INTROSPECTION',
                    'severity': 'MEDIUM',
                    'confidence': 90,
                    'confidence_label': 'High',
                    'url': url,
                    'proof': '__schema present in response',
                    'detail': 'GraphQL introspection enabled — full schema exposed'
                })
                print(f"  [MEDIUM] GraphQL introspection confirmed at {url}")

    async def run(self):
        print("="*60)
        print("  BackendProbe — Deep Backend Vulnerability Scanner")
        print("="*60)

        conn = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=conn, timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)

            await self.scan_tech_stack(sess)
            await self.scan_debug_endpoints(sess)
            await self.scan_environment_files(sess)
            await self.scan_cors_misconfig(sess)
            await self.scan_ssrf_vectors(sess)
            await self.scan_graphql(sess)

        await self.scan_open_ports_services()
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    print("="*60)
    print("  BackendProbe — Deep Backend Scanner")
    print("="*60)
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)

    scanner = BackendProbe(target)
    findings = asyncio.run(scanner.run())

    with open("reports/backendprobe.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)

    print(f"\n[+] {len(findings)} findings -> reports/backendprobe.json")
    by_severity = {}
    for f in findings:
        sev = f.get('severity', 'INFO')
        by_severity[sev] = by_severity.get(sev, 0) + 1
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev in by_severity:
            print(f"    {sev:8s}: {by_severity[sev]}")

if __name__ == '__main__':
    main()
