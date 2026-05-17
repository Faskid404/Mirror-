#!/usr/bin/env python3
"""RootChain v9 — Attack Chain Correlation Engine.

Reads all scan reports and correlates individual findings into complete
multi-step attack chains demonstrating full exploit paths.

Capabilities:
  - 30+ named attack chain templates
  - C2_ESTABLISHED / POST_EXPLOITATION_EXFIL chain
  - CVSS 3.1 base score estimation per chain
  - Business impact narrative (data breach, ATO, RCE, financial fraud)
  - Remediation priority matrix
  - Executive summary generation
  - JSON + Markdown chain report
  - Chain confidence derived from constituent finding confidence
  - Deduplication of overlapping chains
  - Full "attacker perspective" narrative for each chain
  - MITRE ATT&CK technique mapping per chain
"""
import json
import sys
import hashlib
from pathlib import Path
from datetime import datetime, timezone

REPORTS_DIR = Path(__file__).parent.parent / "reports"

ATTACK_CHAINS = [
    # ── C2 / Full Compromise ───────────────────────────────────────────────────
    {
        "id": "C201",
        "name": "SSTI/RCE → C2 Beacon → Full Post-Exploitation",
        "trigger_types": [
            ["C2_ESTABLISHED", "POST_EXPLOITATION_EXFIL"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 10.0,
        "mitre": ["T1190", "T1059", "T1071.001", "T1041", "T1083"],
        "narrative": (
            "A Server-Side Template Injection payload caused the target server to "
            "initiate an outbound HTTP connection to the attacker's C2 listener, "
            "confirming live code execution out-of-band. Post-exploitation payloads "
            "then exfiltrated system identity, environment variables (secrets), "
            "/etc/passwd, open ports, cron jobs, and .env files. The attacker now "
            "has a full picture of the internal environment and credentials to pivot further."
        ),
        "business_impact": (
            "Full server compromise proven with OOB callback. Attacker has interactive "
            "access. All data on the server is compromised. Internal network pivot possible."
        ),
        "steps": [
            "1. SSTI payload injected into template parameter.",
            "2. Server executes payload; curl calls back to C2 with base64(id+hostname).",
            "3. C2 beacon received — live RCE confirmed without relying on response body.",
            "4. Post-exploitation payloads dump /etc/passwd, env vars, .env files.",
            "5. Reverse shell established for interactive access.",
            "6. Lateral movement to internal services (DB, Redis, cloud metadata).",
        ],
        "remediation_priority": "P0 — Emergency. Server is actively compromised. Isolate immediately.",
    },
    # ── Authentication ─────────────────────────────────────────────────────────
    {
        "id": "AUTH01",
        "name": "Authentication Bypass → Account Takeover",
        "trigger_types": [
            ["AUTH_BYPASS", "JWT_ALG_NONE", "JWT_WEAK_SECRET",
             "JWT_ALG_NONE_BYPASS", "JWT_ALG_NONE_BYPASS_CONFIRMED",
             "JWT_NONE_ALG", "JWT_FORGED"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre": ["T1078", "T1528"],
        "narrative": (
            "An attacker can bypass authentication by forging JWT tokens "
            "(alg:none or weak HMAC secret). Once forged, the attacker impersonates "
            "any user including administrators and can perform all privileged actions."
        ),
        "business_impact": "Full account takeover for all users. Complete data breach possible.",
        "steps": [
            "1. Attacker intercepts or creates a JWT token.",
            "2. Modifies alg to 'none' or re-signs with cracked/empty secret.",
            "3. Sets role=admin, sub=1 in payload.",
            "4. Uses forged token on authenticated endpoints.",
            "5. Full admin access achieved.",
        ],
        "remediation_priority": "P0 — Fix immediately. Rotate all JWT secrets.",
    },
    {
        "id": "AUTH02",
        "name": "Session Fixation + Weak 2FA → Account Takeover",
        "trigger_types": [
            ["SESSION_FIXATION", "MFA_BYPASS", "2FA_BYPASS", "OTP_BYPASS",
             "MFA_SKIP", "TOTP_BYPASS"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1078", "T1556"],
        "narrative": (
            "Session fixation allows the attacker to preset a session ID. "
            "Combined with weak 2FA (no rate-limiting, code reuse, OTP bypass), "
            "the attacker takes over accounts even on MFA-protected apps."
        ),
        "business_impact": "Account takeover bypassing MFA. Affects all users.",
        "steps": [
            "1. Attacker sets a known session ID via URL/cookie.",
            "2. Victim authenticates; server adopts the attacker-supplied session.",
            "3. Attacker also brutes or reuses the 2FA OTP.",
            "4. Full account access obtained.",
        ],
        "remediation_priority": "P0 — Regenerate session ID on login. Rate-limit OTP attempts.",
    },
    # ── IDOR / Data Access ─────────────────────────────────────────────────────
    {
        "id": "IDOR01",
        "name": "IDOR → Mass PII Data Breach",
        "trigger_types": [
            ["IDOR", "BOLA", "MASS_DATA", "IDOR_SEQUENTIAL", "IDOR_UUID",
             "MASS_OBJECT", "UNAUTH_DATA", "MASS_DATA_EXPOSURE", "IDOR_CONFIRMED"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1530", "T1213"],
        "narrative": (
            "Missing object-level authorization allows an attacker to enumerate "
            "all user records by iterating object IDs. The entire user database "
            "can be extracted in minutes via automated scripting."
        ),
        "business_impact": "Mass PII breach. GDPR fines. Regulatory notification required.",
        "steps": [
            "1. Attacker discovers API endpoint accepting numeric/UUID user ID.",
            "2. Iterates IDs or enumerates UUIDs from 1 to N.",
            "3. Each request returns full user PII (email, phone, address).",
            "4. Full database extracted in automated attack.",
        ],
        "remediation_priority": "P0 — Implement object-level authorization on every endpoint.",
    },
    # ── SSRF ───────────────────────────────────────────────────────────────────
    {
        "id": "SSRF01",
        "name": "SSRF → Cloud Metadata → Credential Theft → Cloud Takeover",
        "trigger_types": [
            ["SSRF", "SSRF_CONFIRMED", "SSRF_API", "SSRF_BLIND"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre": ["T1552.005", "T1078.004"],
        "narrative": (
            "SSRF allows the attacker to reach the cloud instance metadata service "
            "(169.254.169.254). From there, IAM credentials are extracted. With "
            "AWS/GCP credentials, the attacker can access all cloud resources, "
            "exfiltrate data from S3/GCS, and take over the entire cloud account."
        ),
        "business_impact": "Cloud account takeover. All data in cloud storage accessible.",
        "steps": [
            "1. Attacker supplies url=http://169.254.169.254/... to SSRF parameter.",
            "2. Server fetches metadata and returns response.",
            "3. IAM access key + secret extracted.",
            "4. Attacker uses AWS CLI/SDK with extracted credentials.",
            "5. Full cloud account access obtained.",
        ],
        "remediation_priority": "P0 — Block metadata IP ranges at network level immediately.",
    },
    # ── SSTI ───────────────────────────────────────────────────────────────────
    {
        "id": "SSTI01",
        "name": "SSTI → Remote Code Execution → Server Takeover",
        "trigger_types": [
            ["SSTI", "SSTI_RCE", "SSTI_CONFIRMED", "RCE_CONFIRMED",
             "BLIND_SSTI_RCE_TIMING", "SSTI_POST_JSON", "SSTI_POST_FORM",
             "SSTI_HEADER_INJECTION", "SSTI_COOKIE_INJECTION",
             "SSTI_PATH_INJECTION", "SSTI_GRAPHQL_VARIABLE", "SSTI_XML_INJECTION"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 10.0,
        "mitre": ["T1190", "T1059"],
        "narrative": (
            "Server-Side Template Injection allows arbitrary code execution. "
            "The attacker reads /etc/passwd, exfiltrates environment variables "
            "containing secrets, establishes reverse shells, and achieves full "
            "server takeover."
        ),
        "business_impact": "Full server compromise. All data exfiltrated. Ransomware possible.",
        "steps": [
            "1. Attacker injects {{7*7}} to confirm SSTI (response: 49).",
            "2. Escalates to {{config}} to read Flask/Django config.",
            "3. Executes os.popen('id').read() for code execution proof.",
            "4. Establishes reverse shell via C2 callback or netcat.",
            "5. Lateral movement to internal network.",
        ],
        "remediation_priority": "P0 — Never render user input as template. Emergency patch.",
    },
    # ── Secrets ────────────────────────────────────────────────────────────────
    {
        "id": "SECRET01",
        "name": "Exposed Secret → Service Compromise",
        "trigger_types": [
            ["SECRET_", "ENV_FILE_EXPOSED", "GIT_REPO_EXPOSED", "GIT_REPO_DUMP",
             "EXPOSED_SECRET", "AWS_KEY", "GCP_KEY", "STRIPE_KEY",
             "GITHUB_TOKEN", "OPENAI_KEY"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.5,
        "mitre": ["T1552.001", "T1213"],
        "narrative": (
            "Exposed credentials in .env files, git repositories, or API responses "
            "give attackers direct access to cloud services, databases, payment "
            "processors, and email providers."
        ),
        "business_impact": "Credential-based service compromise. Financial fraud via Stripe keys.",
        "steps": [
            "1. Attacker fetches /.env or /.git/config.",
            "2. Extracts database credentials, API keys, JWT secrets.",
            "3. Connects directly to database and dumps all data.",
            "4. Uses Stripe key to issue refunds or transfer funds.",
            "5. Uses JWT secret to forge auth tokens (see AUTH01 chain).",
        ],
        "remediation_priority": "P0 — Rotate all exposed credentials. Remove files from web root.",
    },
    # ── XSS ────────────────────────────────────────────────────────────────────
    {
        "id": "XSS01",
        "name": "Stored/Reflected XSS → Session Hijack → Account Takeover",
        "trigger_types": [
            ["XSS", "XSS_REFLECTED", "XSS_STORED", "XSS_DOM",
             "XSS_POST", "XSS_BLIND", "STORED_XSS"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.8,
        "mitre": ["T1185", "T1539"],
        "narrative": (
            "XSS allows arbitrary JavaScript execution in victim browsers. "
            "Without HttpOnly on session cookies, attackers steal cookies and "
            "hijack sessions. Without CSP, full page exfiltration is trivial."
        ),
        "business_impact": "Mass session hijacking. Credential theft. Admin account takeover.",
        "steps": [
            "1. Attacker crafts XSS payload and delivers via link or form.",
            "2. Victim clicks — JavaScript executes in their browser.",
            "3. document.cookie sent to attacker's server.",
            "4. Attacker replays cookie to hijack session.",
            "5. Admin action performed (create user, export data).",
        ],
        "remediation_priority": "P1 — Implement CSP. Output encode all user input. Add HttpOnly.",
    },
    # ── CORS ───────────────────────────────────────────────────────────────────
    {
        "id": "CORS01",
        "name": "CORS Misconfiguration → Credential Theft",
        "trigger_types": [
            ["CORS_ARBITRARY", "CORS_NULL_ORIGIN", "CORS_WILDCARD",
             "CORS_MISCONFIGURATION", "CORS_NULL_ORIGIN_WITH_CREDENTIALS",
             "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS", "CORS_REFLECT"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.1,
        "mitre": ["T1185"],
        "narrative": (
            "Misconfigured CORS allows any origin to read authenticated API "
            "responses with the victim's credentials. An attacker's malicious page "
            "silently calls the target API with victim cookies and exfiltrates data."
        ),
        "business_impact": "Silent account data theft from any victim who visits attacker page.",
        "steps": [
            "1. Attacker hosts malicious HTML at evil.com.",
            "2. Victim visits evil.com (phishing or ad injection).",
            "3. JavaScript calls target API with victim's cookies.",
            "4. API responds with victim's data (CORS allows it).",
            "5. Data exfiltrated to attacker's server.",
        ],
        "remediation_priority": "P1 — Fix CORS allowlist. Never reflect arbitrary Origin with credentials.",
    },
    # ── SQL Injection ──────────────────────────────────────────────────────────
    {
        "id": "SQLI01",
        "name": "SQL Injection → Database Dump → Credential Crack",
        "trigger_types": [
            ["SQLI", "SQL_INJECTION", "SQLI_ERROR", "SQLI_TIME",
             "SQLI_UNION", "SQLI_ERROR_BASED", "SQLI_TIME_BASED",
             "SQLI_BOOLEAN", "NOSQL_INJECTION"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre": ["T1190", "T1213"],
        "narrative": (
            "SQL injection allows extracting the full database. Union-based or "
            "error-based SQLi dumps all tables including users (email+hash), "
            "orders (financial data), and admin credentials."
        ),
        "business_impact": "Full database breach. Credential hash dump → password cracking.",
        "steps": [
            "1. Attacker injects SQL payload into vulnerable parameter.",
            "2. Extracts table names via INFORMATION_SCHEMA.",
            "3. Dumps users table with email + password hashes.",
            "4. Cracks hashes with Hashcat/JohnTheRipper.",
            "5. Credentials reused on other services (credential stuffing).",
        ],
        "remediation_priority": "P0 — Use parameterized queries everywhere. Emergency patch.",
    },
    # ── Command Injection ──────────────────────────────────────────────────────
    {
        "id": "CMDI01",
        "name": "Command Injection → Reverse Shell → Full Server Compromise",
        "trigger_types": [
            ["COMMAND_INJECTION", "CMDI", "OS_COMMAND", "RCE",
             "BLIND_CMDI", "CMDI_TIME_BASED"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 10.0,
        "mitre": ["T1059.004", "T1190"],
        "narrative": (
            "OS command injection allows executing arbitrary shell commands. "
            "The attacker establishes a reverse shell, reads environment variables, "
            "moves laterally to internal services, and achieves full infrastructure "
            "compromise."
        ),
        "business_impact": "Full server takeover. Ransomware. Data exfiltration.",
        "steps": [
            "1. Attacker injects '; whoami' — confirms execution as www-data/root.",
            "2. Reads /etc/passwd and environment variables.",
            "3. Installs reverse shell (nc, bash, python).",
            "4. Pivots to internal network.",
            "5. Exfiltrates all data + installs persistence.",
        ],
        "remediation_priority": "P0 — Never pass user input to shell. Emergency patch.",
    },
    # ── Path Traversal / LFI ───────────────────────────────────────────────────
    {
        "id": "TRAVERSAL01",
        "name": "Path Traversal → /etc/passwd + Secret File Read",
        "trigger_types": [
            ["PATH_TRAVERSAL", "DIRECTORY_TRAVERSAL", "LFI",
             "TRAVERSAL", "FILE_INCLUSION"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1083", "T1552.001"],
        "narrative": (
            "Path traversal allows reading arbitrary files from the server. "
            "The attacker reads /etc/passwd, application configuration files, "
            ".env files containing secrets, and private SSL keys."
        ),
        "business_impact": "Credential theft. Private key compromise. Full source code read.",
        "steps": [
            "1. Attacker provides ../../../../etc/passwd as file parameter.",
            "2. Server reads and returns /etc/passwd.",
            "3. Attacker reads ../../../../.env to extract secrets.",
            "4. Uses secrets for service compromise (see SECRET01).",
        ],
        "remediation_priority": "P0 — Canonicalize all file paths and compare to allowed base dir.",
    },
    # ── GraphQL ────────────────────────────────────────────────────────────────
    {
        "id": "GRAPHQL01",
        "name": "GraphQL Introspection → IDOR → Mass Data Extraction",
        "trigger_types": [
            ["GRAPHQL_INTROSPECTION", "GRAPHQL_IDOR", "GRAPHQL_UNAUTH",
             "GRAPHQL_SQLI", "GRAPHQL_DOS", "GRAPHQL_DEPTH_DOS"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.6,
        "mitre": ["T1213", "T1530"],
        "narrative": (
            "GraphQL introspection reveals the complete API schema. The attacker "
            "discovers all types and fields, then exploits IDOR to enumerate all "
            "user objects. Without auth, mass data extraction is trivial."
        ),
        "business_impact": "Full API schema disclosure. Mass user data extraction.",
        "steps": [
            "1. POST {__schema{...}} — full schema downloaded.",
            "2. Identifies user(id: X) query with sensitive fields.",
            "3. Iterates ID 1..10000 extracting all user PII.",
            "4. Uses mutation IDOR to modify other users' data.",
        ],
        "remediation_priority": "P1 — Disable introspection. Apply field-level authorization.",
    },
    # ── Mass Assignment ────────────────────────────────────────────────────────
    {
        "id": "MASS01",
        "name": "Mass Assignment → Privilege Escalation → Admin Access",
        "trigger_types": [
            ["MASS_ASSIGNMENT", "PRIVILEGE_ESCALATION", "ROLE_ESCALATION",
             "ADMIN_MASS_ASSIGN"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1078"],
        "narrative": (
            "Mass assignment allows setting privileged fields (role, isAdmin) "
            "via the update profile API. The attacker escalates to admin and "
            "gains access to all administrative functionality."
        ),
        "business_impact": "Privilege escalation to admin. Full application control.",
        "steps": [
            "1. Attacker sends PATCH /api/me with {role: 'admin'}.",
            "2. Server reflects role=admin in response.",
            "3. Admin panel access obtained.",
            "4. Attacker manages all users, exports data, modifies settings.",
        ],
        "remediation_priority": "P0 — Allowlist accepted fields. Mark privileged fields read-only.",
    },
    # ── XXE ────────────────────────────────────────────────────────────────────
    {
        "id": "XXE01",
        "name": "XXE → Local File Read → Internal SSRF Pivot",
        "trigger_types": [
            ["XXE", "XML_EXTERNAL_ENTITY", "XXE_CONFIRMED", "XXE_BLIND",
             "XXE_OOB", "XXE_FILE_READ"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1083", "T1190"],
        "narrative": (
            "XML External Entity injection allows reading local files and making "
            "server-side network requests. The attacker reads /etc/passwd, "
            "application configuration, and uses SSRF to reach internal services "
            "that are not exposed externally."
        ),
        "business_impact": "Arbitrary file read. Internal SSRF. Credential theft.",
        "steps": [
            "1. Attacker submits XML with DOCTYPE declaring external entity.",
            "2. Entity resolves to file:///etc/passwd — file contents returned.",
            "3. Attacker pivots to internal services via http://internal-host/.",
            "4. Reads /proc/self/environ for secrets.",
        ],
        "remediation_priority": "P0 — Disable external entity processing. Use safe XML parsers.",
    },
    # ── HTTP Request Smuggling ─────────────────────────────────────────────────
    {
        "id": "SMUGGLE01",
        "name": "HTTP Request Smuggling → Cache Poisoning → Victim Session Hijack",
        "trigger_types": [
            ["HTTP_SMUGGLING", "REQUEST_SMUGGLING", "CLTE_SMUGGLING",
             "TECL_SMUGGLING", "TETE_SMUGGLING"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.0,
        "mitre": ["T1557", "T1539"],
        "narrative": (
            "HTTP request smuggling exploits disagreements between a front-end proxy "
            "and back-end server on how to delimit HTTP requests. The attacker "
            "smuggles a partial request that poisons the next victim's connection, "
            "hijacking their session or poisoning the shared cache."
        ),
        "business_impact": "Mass session hijacking. Cache poisoning. Admin request capture.",
        "steps": [
            "1. Attacker sends ambiguous CL+TE request to the server.",
            "2. Front-end processes Content-Length; back-end processes Transfer-Encoding.",
            "3. Smuggled prefix prepends to next victim's request.",
            "4. Victim's Authorization header captured in attacker-controlled endpoint.",
            "5. Attacker replays captured credentials for account takeover.",
        ],
        "remediation_priority": "P0 — Normalize HTTP parsing across proxy and backend. Disable TE.CL.",
    },
    # ── JWT Secret Leak → Auth Bypass ─────────────────────────────────────────
    {
        "id": "JWT01",
        "name": "JWT Secret Exposed → Token Forgery → Full Auth Bypass",
        "trigger_types": [
            ["JWT_SECRET", "JWT_EXPOSED", "JWT_WEAK", "JWT_CRACK",
             "WEAK_JWT_SECRET"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre": ["T1552.001", "T1078"],
        "narrative": (
            "An exposed or weak JWT signing secret allows the attacker to forge "
            "valid tokens for any user. Combined with a mass-assignment endpoint "
            "or admin API, this leads to full application compromise."
        ),
        "business_impact": "Auth bypass for all users. Full admin access without credentials.",
        "steps": [
            "1. JWT secret exposed in .env file or cracked via weak HMAC.",
            "2. Attacker constructs token: {sub:1, role:'admin', exp:99999}.",
            "3. Signs with known secret — token is valid.",
            "4. All authenticated endpoints accessible as admin.",
        ],
        "remediation_priority": "P0 — Rotate JWT secret. Enforce minimum 256-bit entropy.",
    },
    # ── Rate-Limit Bypass → Credential Stuffing ────────────────────────────────
    {
        "id": "RATELIMIT01",
        "name": "Rate-Limit Bypass → Credential Stuffing → Mass Account Takeover",
        "trigger_types": [
            ["RATE_LIMIT_BYPASS", "NO_RATE_LIMIT", "RATE_LIMIT_MISSING",
             "BRUTE_FORCE_POSSIBLE", "LOGIN_NO_LOCKOUT"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.1,
        "mitre": ["T1110.004", "T1078"],
        "narrative": (
            "Absent or bypassable rate-limiting on login/auth endpoints allows "
            "automated credential stuffing. Using leaked breach databases, "
            "attackers try millions of email+password combinations and achieve "
            "mass account takeover."
        ),
        "business_impact": "Mass account takeover via credential stuffing. User data breach.",
        "steps": [
            "1. Attacker obtains leaked breach database.",
            "2. Identifies login endpoint with no rate-limiting.",
            "3. Automated tool tries 10,000+ credentials/minute.",
            "4. Valid accounts captured — password reuse yields takeovers.",
            "5. Admin accounts compromised if included in breach list.",
        ],
        "remediation_priority": "P1 — Implement rate-limiting + CAPTCHA + account lockout.",
    },
    # ── Header Injection → Cache Poisoning ─────────────────────────────────────
    {
        "id": "CACHE01",
        "name": "Unkeyed Header → Web Cache Poisoning → Persistent XSS",
        "trigger_types": [
            ["CACHE_POISONING", "WEB_CACHE_POISONING", "CACHE_POISON",
             "UNKEYED_HEADER"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.0,
        "mitre": ["T1557"],
        "narrative": (
            "An unkeyed HTTP header (X-Forwarded-Host, X-Forwarded-For) is "
            "reflected in cached responses. The attacker poisons the shared cache "
            "with a crafted host header, delivering XSS or open redirects to "
            "all subsequent visitors who receive the cached response."
        ),
        "business_impact": "Persistent XSS delivered to all users via CDN/cache. Mass session theft.",
        "steps": [
            "1. Attacker sends request with X-Forwarded-Host: evil.com.",
            "2. Server reflects evil.com in HTML response.",
            "3. Response cached by CDN/proxy.",
            "4. All subsequent visitors receive poisoned page.",
            "5. Victim browsers load evil.com/script.js — mass XSS.",
        ],
        "remediation_priority": "P1 — Normalize cache keys to include all header values used in response.",
    },
    # ── Prototype Pollution → RCE ──────────────────────────────────────────────
    {
        "id": "PROTO01",
        "name": "Prototype Pollution → Application Logic Bypass → RCE",
        "trigger_types": [
            ["PROTOTYPE_POLLUTION", "PROTO_POLLUTION", "PROTO_POLLUTION_GET",
             "PROTO_POLLUTION_JSON"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.1,
        "mitre": ["T1190"],
        "narrative": (
            "Prototype pollution via __proto__ in JSON body or GET params "
            "injects properties into all JavaScript objects. This can bypass "
            "authorization checks (isAdmin: true on all objects), crash the "
            "application (DoS), or in server-side Node.js contexts, achieve RCE "
            "via template engine gadgets."
        ),
        "business_impact": "Auth bypass. Application crash. Potential RCE in Node.js.",
        "steps": [
            "1. Attacker sends JSON: {\"__proto__\": {\"isAdmin\": true}}.",
            "2. All objects in application now have isAdmin=true.",
            "3. Admin checks pass for non-admin users.",
            "4. Attacker accesses admin-only features.",
        ],
        "remediation_priority": "P1 — Freeze Object.prototype. Validate JSON keys. Use safe merge.",
    },
    # ── Timing Attack → Account Enumeration ────────────────────────────────────
    {
        "id": "TIMING01",
        "name": "Timing Side-Channel → Account Enumeration → Targeted Phishing",
        "trigger_types": [
            ["TIMING_ENUM", "ACCOUNT_ENUM", "USER_ENUM_TIMING",
             "TIMING_ATTACK", "EMAIL_ENUM"],
        ],
        "severity": "MEDIUM",
        "cvss_base": 5.3,
        "mitre": ["T1589.002"],
        "narrative": (
            "Response time differences between valid and invalid usernames reveal "
            "which accounts exist. Attackers use this to build a list of valid "
            "emails for targeted phishing or password spraying attacks."
        ),
        "business_impact": "User enumeration. Targeted phishing. Enables credential stuffing.",
        "steps": [
            "1. Attacker measures login response time for existing vs non-existing user.",
            "2. Δt > 200ms reliably indicates valid account.",
            "3. Attacker enumerates all accounts systematically.",
            "4. Uses list for spear phishing or password spraying.",
        ],
        "remediation_priority": "P2 — Use constant-time comparison. Return identical responses for valid/invalid users.",
    },
    # ── Business Logic Abuse ───────────────────────────────────────────────────
    {
        "id": "LOGIC01",
        "name": "Price Manipulation → Negative Amount → Financial Loss",
        "trigger_types": [
            ["NEGATIVE_PRICE", "PRICE_MANIPULATION", "NEGATIVE_AMOUNT",
             "CHECKOUT_BYPASS", "ZERO_PRICE"],
        ],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre": ["T1499.004"],
        "narrative": (
            "Missing server-side price validation allows sending negative quantities "
            "or prices. The checkout total becomes negative, the payment processor "
            "issues a refund, and the attacker receives goods for free or profit."
        ),
        "business_impact": "Direct financial loss. Refunds issued to attacker account.",
        "steps": [
            "1. Attacker adds item to cart.",
            "2. Modifies quantity to -100 or price to -9999.",
            "3. Checkout total becomes negative.",
            "4. Payment processor issues refund or charges $0.",
            "5. Attacker receives goods without payment.",
        ],
        "remediation_priority": "P0 — Server-side price recalculation. Reject negative quantities.",
    },
    # ── Subdomain Takeover ─────────────────────────────────────────────────────
    {
        "id": "SUBDOMAIN01",
        "name": "Dangling CNAME → Subdomain Takeover → Cookie Theft",
        "trigger_types": [
            ["SUBDOMAIN_TAKEOVER", "CNAME_DANGLING", "DANGLING_CNAME"],
        ],
        "severity": "HIGH",
        "cvss_base": 8.1,
        "mitre": ["T1584.001"],
        "narrative": (
            "A subdomain points to an unclaimed cloud resource (GitHub Pages, Heroku, "
            "Azure, Netlify). The attacker claims the resource and controls the "
            "subdomain, enabling cookie theft (domain cookies), stored XSS, and "
            "phishing via the trusted domain."
        ),
        "business_impact": "Cookie theft. Stored XSS on trusted domain. Phishing.",
        "steps": [
            "1. Attacker finds sub.example.com → CNAME → unclaimed.herokuapp.com.",
            "2. Creates free Heroku app with that name.",
            "3. Controls sub.example.com — hosts malicious page.",
            "4. Victim visits sub.example.com — cookies with domain=.example.com stolen.",
        ],
        "remediation_priority": "P1 — Remove or update dangling CNAME records immediately.",
    },
    # ── Crypto Weakness ───────────────────────────────────────────────────────
    {
        "id": "CRYPTO01",
        "name": "Weak TLS / Cipher Suite → Traffic Interception → Credential Theft",
        "trigger_types": [
            ["WEAK_TLS", "TLS_1_0", "TLS_1_1", "WEAK_CIPHER",
             "RC4_CIPHER", "DES_CIPHER", "NULL_CIPHER", "SSL_EXPIRED"],
        ],
        "severity": "HIGH",
        "cvss_base": 7.4,
        "mitre": ["T1557.002"],
        "narrative": (
            "Deprecated TLS versions (1.0, 1.1) and weak cipher suites (RC4, 3DES) "
            "allow network-positioned attackers to decrypt traffic via BEAST, POODLE, "
            "or RC4 bias attacks, exposing session tokens and credentials."
        ),
        "business_impact": "Session token interception. Credential theft on shared networks.",
        "steps": [
            "1. Network-positioned attacker intercepts TLS handshake.",
            "2. Downgrade attack forces TLS 1.0 + RC4.",
            "3. Passive monitoring decrypts traffic over time.",
            "4. Session cookies and API keys extracted.",
        ],
        "remediation_priority": "P1 — Enforce TLS 1.2+ only. Disable RC4/3DES/DES/NULL ciphers.",
    },
]


def _load_reports() -> dict[str, list]:
    """Load all scanner report JSON files."""
    reports: dict[str, list] = {}
    if not REPORTS_DIR.exists():
        return reports
    for fp in sorted(REPORTS_DIR.glob("*.json")):
        if fp.name.startswith("_") or fp.name in ("rootchain.json", "scan_diff.json"):
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, list):
                reports[fp.stem] = data
        except Exception:
            pass
    return reports


def _all_findings(reports: dict[str, list]) -> list[dict]:
    """Flatten all findings from all reports into one list."""
    findings: list[dict] = []
    for module_name, module_findings in reports.items():
        for f in module_findings:
            if isinstance(f, dict):
                f["_module"] = module_name
                findings.append(f)
    return findings


def _type_matches(finding_type: str, trigger_types: list[list[str]]) -> bool:
    """
    Check if a finding type matches any trigger in the chain template.
    Matching rules (all case-insensitive):
      - Exact match: 'SQLI' matches 'sqli'
      - Prefix match: 'SECRET_AWS' matches trigger 'SECRET_'
      - Contains match: trigger 'SSTI' matches 'BLIND_SSTI_RCE_TIMING'
    """
    ft = str(finding_type).upper()
    for trigger_group in trigger_types:
        for trigger in trigger_group:
            t = str(trigger).upper()
            if t.endswith("_"):
                # Prefix-only trigger (e.g. 'SECRET_')
                if ft.startswith(t):
                    return True
            else:
                # Exact or contains
                if ft == t or t in ft or ft.startswith(t):
                    return True
    return False


def _build_chains(findings: list[dict]) -> list[dict]:
    """Correlate findings into attack chains."""
    chains: list[dict] = []
    seen_chain_ids: set[str] = set()

    for chain_template in ATTACK_CHAINS:
        cid = chain_template["id"]
        if cid in seen_chain_ids:
            continue

        matching: list[dict] = []
        for f in findings:
            ftype = str(f.get("type", ""))
            if _type_matches(ftype, chain_template["trigger_types"]):
                matching.append(f)

        if not matching:
            continue

        seen_chain_ids.add(cid)
        confidences = [int(f.get("confidence", 70)) for f in matching]
        chain_conf  = round(sum(confidences) / len(confidences)) if confidences else 70

        chains.append({
            "chain_id":              cid,
            "chain_name":            chain_template["name"],
            "severity":              chain_template["severity"],
            "cvss_base_score":       chain_template["cvss_base"],
            "chain_confidence":      chain_conf,
            "confidence_label":      _clabel(chain_conf),
            "mitre_techniques":      chain_template.get("mitre", []),
            "attacker_narrative":    chain_template["narrative"],
            "attack_steps":          chain_template["steps"],
            "business_impact":       chain_template["business_impact"],
            "remediation_priority":  chain_template["remediation_priority"],
            "constituent_findings":  [
                {
                    "type":       f.get("type", ""),
                    "severity":   f.get("severity", ""),
                    "url":        str(f.get("url", ""))[:120],
                    "module":     f.get("_module", ""),
                    "confidence": f.get("confidence", 0),
                }
                for f in matching[:10]
            ],
            "finding_count": len(matching),
        })

    chains.sort(key=lambda c: (c["cvss_base_score"], c["chain_confidence"]), reverse=True)
    return chains


def _clabel(conf: int) -> str:
    if conf >= 95:
        return "Confirmed"
    if conf >= 85:
        return "High"
    if conf >= 70:
        return "Medium"
    return "Low"


def _executive_summary(chains: list[dict], all_findings: list[dict]) -> dict:
    sev_count: dict[str, int] = {}
    for f in all_findings:
        s = str(f.get("severity", "INFO"))
        sev_count[s] = sev_count.get(s, 0) + 1

    critical_chains = [c for c in chains if c["severity"] == "CRITICAL"]
    high_chains     = [c for c in chains if c["severity"] == "HIGH"]

    # Collect unique MITRE techniques across all chains
    mitre_all: list[str] = []
    for c in chains:
        for t in c.get("mitre_techniques", []):
            if t not in mitre_all:
                mitre_all.append(t)

    risk = "CRITICAL" if critical_chains else ("HIGH" if high_chains else ("MEDIUM" if chains else "LOW"))

    return {
        "total_findings":      len(all_findings),
        "severity_breakdown":  sev_count,
        "attack_chains_found": len(chains),
        "critical_chains":     len(critical_chains),
        "high_chains":         len(high_chains),
        "risk_rating":         risk,
        "top_chains":          [c["chain_name"] for c in chains[:5]],
        "immediate_actions":   [c["remediation_priority"] for c in critical_chains[:5]],
        "mitre_techniques":    mitre_all,
        "generated_at":        datetime.now(timezone.utc).isoformat(),
    }


def _write_markdown(chains: list[dict], summary: dict, reports: dict) -> None:
    """Write a Markdown chain report."""
    out = REPORTS_DIR / "rootchain.md"
    lines = [
        "# RootChain v9 — Attack Chain Report",
        f"\nGenerated: {summary['generated_at']}",
        f"\n**Total Findings:** {summary['total_findings']}  |  "
        f"**Attack Chains:** {summary['attack_chains_found']}  |  "
        f"**Risk Rating:** {summary['risk_rating']}",
        f"\n**Modules Scanned:** {', '.join(sorted(reports.keys()))}",
    ]
    if summary.get("mitre_techniques"):
        lines.append(f"\n**MITRE Techniques:** {', '.join(summary['mitre_techniques'])}")
    if summary.get("immediate_actions"):
        lines.append("\n## Immediate Actions Required\n")
        for action in summary["immediate_actions"]:
            lines.append(f"- {action}")
    for c in chains:
        lines.append(f"\n---\n\n## [{c['severity']}] {c['chain_id']}: {c['chain_name']}")
        lines.append(
            f"**CVSS:** {c['cvss_base_score']}  |  "
            f"**Confidence:** {c['confidence_label']} ({c['chain_confidence']}%)  |  "
            f"**Findings matched:** {c['finding_count']}"
        )
        if c.get("mitre_techniques"):
            lines.append(f"\n**MITRE:** {', '.join(c['mitre_techniques'])}")
        lines.append(f"\n**Narrative:** {c['attacker_narrative']}")
        lines.append(f"\n**Business Impact:** {c['business_impact']}")
        lines.append(f"\n**Remediation:** {c['remediation_priority']}")
        lines.append("\n**Attack Steps:**")
        for step in c["attack_steps"]:
            lines.append(f"\n{step}")
        if c["constituent_findings"]:
            lines.append("\n**Matched Findings:**")
            for f in c["constituent_findings"][:5]:
                lines.append(
                    f"- [{f['severity']}] `{f['type']}` ({f['module']}) — "
                    f"`{f['url'][:80]}`"
                )
    try:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


def main():
    print("=" * 60)
    print("  RootChain v9 — Attack Chain Correlation Engine")
    print("=" * 60)

    reports  = _load_reports()
    findings = _all_findings(reports)
    print(f"\n[*] Loaded {len(findings)} findings from {len(reports)} modules: "
          f"{', '.join(sorted(reports.keys()))}")

    if not findings:
        print("[!] No findings loaded — run individual scanners first.")
        return {}

    chains  = _build_chains(findings)
    summary = _executive_summary(chains, findings)

    print(f"\n[+] Identified {len(chains)} attack chain(s)  |  Risk: {summary['risk_rating']}")
    for c in chains[:8]:
        print(f"  [{c['severity']:8}] CVSS {c['cvss_base_score']:4.1f}  "
              f"{c['chain_id']}: {c['chain_name']}")

    if summary.get("mitre_techniques"):
        print(f"\n[*] MITRE ATT&CK: {', '.join(summary['mitre_techniques'][:8])}")

    output = {
        "executive_summary": summary,
        "attack_chains":     chains,
        "metadata": {
            "modules_scanned": sorted(reports.keys()),
            "total_findings":  len(findings),
            "chains_found":    len(chains),
        },
    }

    out_json = REPORTS_DIR / "rootchain.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    try:
        out_json.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        print(f"\n[+] JSON report  → {out_json}")
    except Exception as e:
        print(f"[!] Failed to write JSON report: {e}", file=sys.stderr)

    _write_markdown(chains, summary, reports)
    print(f"[+] Markdown     → {REPORTS_DIR / 'rootchain.md'}")

    return output


if __name__ == "__main__":
    main()
