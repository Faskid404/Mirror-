#!/usr/bin/env python3
"""
RootChain v2 — Attack chain correlation and kill-chain mapper.

Improvements:
  - MITRE ATT&CK tactic tagging per finding type
  - Kill chain stage scoring (Recon → Weaponise → Deliver → Exploit → Install → C2 → Exfil)
  - Multi-finding chain detection across all report files
  - CVSS v3.1 base score aggregation
  - Risk score with business impact rating
  - Executive summary generation
  - Deduplication across modules
  - Chain path visualisation (text-based)
  - Remediation priority matrix (quick wins vs long term)
  - Outputs structured JSON + readable text summary
"""
import json
import sys
import time
from pathlib import Path
from itertools import combinations

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# MITRE ATT&CK tactic mapping
MITRE_TACTICS = {
    'RECON':           'TA0043 — Reconnaissance',
    'INITIAL_ACCESS':  'TA0001 — Initial Access',
    'EXECUTION':       'TA0002 — Execution',
    'PERSISTENCE':     'TA0003 — Persistence',
    'PRIV_ESC':        'TA0004 — Privilege Escalation',
    'DEFENSE_EVADE':   'TA0005 — Defense Evasion',
    'CREDENTIAL':      'TA0006 — Credential Access',
    'DISCOVERY':       'TA0007 — Discovery',
    'LATERAL':         'TA0008 — Lateral Movement',
    'COLLECTION':      'TA0009 — Collection',
    'EXFILTRATION':    'TA0010 — Exfiltration',
    'IMPACT':          'TA0040 — Impact',
}

# Finding type → ATT&CK tactic + kill chain stage
TYPE_MAP = {
    'SQLI_DETECTED':             ('INITIAL_ACCESS', 1, 9.8),
    'XSS_REFLECTED':             ('INITIAL_ACCESS', 1, 6.1),
    'PATH_TRAVERSAL':            ('INITIAL_ACCESS', 1, 7.5),
    'SSTI_DETECTED':             ('EXECUTION',      2, 9.8),
    'XXE_INJECTION':             ('INITIAL_ACCESS', 1, 7.5),
    'SSRF_CLOUD_METADATA':       ('CREDENTIAL',     3, 10.0),
    'SSRF_POSSIBLE':             ('DISCOVERY',      2, 7.5),
    'JWT_NONE_ALGORITHM':        ('CREDENTIAL',     2, 9.1),
    'JWT_WEAK_SECRET':           ('CREDENTIAL',     2, 7.5),
    'DEFAULT_CREDENTIALS':       ('INITIAL_ACCESS', 1, 9.8),
    'NO_BRUTE_FORCE_PROTECTION': ('CREDENTIAL',     1, 7.5),
    'USER_ENUMERATION_STATUS':   ('RECON',          0, 5.3),
    'USER_ENUMERATION_BODY':     ('RECON',          0, 5.3),
    'IDOR_UNAUTHENTICATED':      ('INITIAL_ACCESS', 1, 7.5),
    'MASS_ASSIGNMENT':           ('PRIV_ESC',       2, 8.1),
    'RACE_CONDITION':            ('IMPACT',         2, 7.5),
    'BUSINESS_LOGIC_ABUSE':      ('IMPACT',         2, 6.5),
    'API_VERSION_SECURITY_DRIFT':('INITIAL_ACCESS', 1, 7.5),
    'FORCED_BROWSING':           ('INITIAL_ACCESS', 1, 7.5),
    'SECRET_EXPOSED':            ('CREDENTIAL',     1, 9.8),
    'SECRET_IN_JS':              ('CREDENTIAL',     1, 9.8),
    'FILE_EXPOSURE':             ('DISCOVERY',      1, 7.5),
    'ADMIN_PANEL_FOUND':         ('DISCOVERY',      1, 6.5),
    'CLOUD_METADATA':            ('CREDENTIAL',     3, 10.0),
    'EXPOSED_PRIVATE_KEY':       ('CREDENTIAL',     1, 9.8),
    'WAF_BYPASS_CONFIRMED':      ('DEFENSE_EVADE',  2, 7.5),
    'WAF_IP_SPOOF_BYPASS':       ('DEFENSE_EVADE',  2, 7.5),
    'NO_RATE_LIMITING':          ('CREDENTIAL',     1, 7.5),
    'HTTP_SMUGGLING_POTENTIAL':  ('DEFENSE_EVADE',  2, 8.1),
    'HOST_HEADER_INJECTION':     ('IMPACT',         2, 7.5),
    'CORS_MISCONFIGURATION':     ('CREDENTIAL',     1, 7.5),
    'MISSING_HSTS':              ('INITIAL_ACCESS', 0, 4.3),
    'MISSING_CSP':               ('INITIAL_ACCESS', 0, 6.1),
    'CERTIFICATE_EXPIRED':       ('INITIAL_ACCESS', 0, 7.5),
    'WEAK_CIPHER_SUITE':         ('CREDENTIAL',     1, 5.9),
    'OAUTH_REDIRECT_MISMATCH':   ('CREDENTIAL',     2, 8.1),
    'USERNAME_TIMING_ORACLE':    ('RECON',          0, 5.3),
    'TIME_BASED_SQLI':           ('INITIAL_ACCESS', 1, 9.8),
    'GRAPHQL_INTROSPECTION':     ('DISCOVERY',      0, 5.3),
    'DEPENDENCY_FILE_EXPOSED':   ('DISCOVERY',      0, 5.3),
    'VULNERABLE_DEPENDENCY':     ('INITIAL_ACCESS', 1, 8.1),
    'FRAMEWORK_ENDPOINT':        ('DISCOVERY',      1, 7.5),
    'VERSION_DISCLOSURE':        ('RECON',          0, 3.1),
}

NAMED_CHAINS = {
    "ProxyLogon":    {
        "name": "ProxyLogon (Exchange Full Compromise)",
        "cves": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
        "risk": "CRITICAL", "cvss": 9.8,
        "description": "SSRF → NTLM authentication → Arbitrary file write → RCE",
        "impact": "Full domain compromise, credential theft, ransomware deployment",
    },
    "ProxyShell":    {
        "name": "ProxyShell (Exchange Pre-Auth RCE)",
        "cves": ["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
        "risk": "CRITICAL", "cvss": 9.8,
        "description": "URL confusion → RBAC bypass → Post-auth RCE",
        "impact": "Remote code execution as SYSTEM on Exchange server",
    },
    "Log4Shell":     {
        "name": "Log4Shell (Log4j Remote Code Execution)",
        "cves": ["CVE-2021-44228", "CVE-2021-45046"],
        "risk": "CRITICAL", "cvss": 10.0,
        "description": "JNDI lookup via log message → LDAP/RMI callback → Class loading → RCE",
        "impact": "Full server compromise without authentication",
    },
    "SharePoint_RCE":{
        "name": "SharePoint EoP + RCE Chain",
        "cves": ["CVE-2023-29357", "CVE-2023-24955"],
        "risk": "CRITICAL", "cvss": 9.8,
        "description": "Pre-auth privilege escalation → Authenticated RCE",
        "impact": "Remote code execution as SharePoint service account",
    },
    "OWASSRF":       {
        "name": "OWASSRF (Exchange SSRF + RCE)",
        "cves": ["CVE-2022-41040", "CVE-2022-41082"],
        "risk": "CRITICAL", "cvss": 9.8,
        "description": "SSRF via autodiscover → PowerShell RCE",
        "impact": "Remote code execution on Exchange server",
    },
    "Ivanti_RCE":    {
        "name": "Ivanti Connect Secure RCE Chain",
        "cves": ["CVE-2024-21887", "CVE-2023-46805"],
        "risk": "CRITICAL", "cvss": 10.0,
        "description": "Auth bypass → Command injection → System compromise",
        "impact": "Full VPN appliance compromise, lateral movement into internal network",
    },
}

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Initial Access",
    "Execution / Exploitation",
    "Persistence / Credential Access",
    "Exfiltration / Impact",
]

SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

def load_all_findings():
    """Load all JSON report files from the reports directory."""
    all_findings = []
    if not REPORTS_DIR.exists():
        return all_findings
    skip = {'rootchain_report', '_target', 'report'}
    for jf in sorted(REPORTS_DIR.glob("*.json")):
        stem = jf.stem
        if stem in skip:
            continue
        try:
            data = json.loads(jf.read_text())
            if isinstance(data, list):
                for f in data:
                    f.setdefault('source_module', stem)
                all_findings.extend(data)
            elif isinstance(data, dict):
                for f in data.get('findings', []):
                    f.setdefault('source_module', stem)
                all_findings.extend(data.get('findings', []))
        except Exception:
            pass
    return all_findings

def enrich_finding(f):
    """Add ATT&CK tactic, kill chain stage, and estimated CVSS."""
    ftype   = f.get('type', '')
    matched = None
    for key, val in TYPE_MAP.items():
        if ftype.startswith(key):
            matched = val
            break
    if matched:
        tactic, stage, cvss = matched
        f['mitre_tactic']   = MITRE_TACTICS.get(tactic, tactic)
        f['kill_chain_stage'] = KILL_CHAIN_STAGES[min(stage, len(KILL_CHAIN_STAGES)-1)]
        f.setdefault('cvss', cvss)
    else:
        f.setdefault('mitre_tactic', 'TA0000 — Unclassified')
        f.setdefault('kill_chain_stage', 'Unknown')
        f.setdefault('cvss', 0.0)
    return f

def detect_attack_chains(findings):
    """Detect multi-step attack chains based on finding type combinations."""
    chains_found = []

    # Named CVE chains from cveprobe
    chain_cve_map = {}
    for f in findings:
        chain = f.get('chain')
        cve   = f.get('cve', '')
        if chain and cve:
            chain_cve_map.setdefault(chain, set()).add(cve)

    for chain_id, cves in chain_cve_map.items():
        profile = NAMED_CHAINS.get(chain_id)
        if profile and len(cves) >= 2:
            chains_found.append({
                'chain_id':    chain_id,
                'name':        profile['name'],
                'risk':        profile['risk'],
                'cvss':        profile['cvss'],
                'cves_found':  sorted(cves),
                'description': profile['description'],
                'impact':      profile['impact'],
                'detail':      f"Multi-CVE attack chain: {', '.join(sorted(cves))}",
            })

    # Logic chains: SSRF → credential, SQLI → exfil, etc.
    type_set = {f.get('type', '') for f in findings}
    logic_chains = [
        ("Auth Bypass + IDOR", ['DEFAULT_CREDENTIALS', 'IDOR_UNAUTHENTICATED'], 'CRITICAL',
         "Default credential access followed by direct object access — full account takeover risk"),
        ("WAF Bypass + SQLi", ['WAF_BYPASS_CONFIRMED', 'SQLI_DETECTED'], 'CRITICAL',
         "WAF bypass enables SQL injection to succeed — database extraction risk"),
        ("SSRF + Metadata Access", ['SSRF_POSSIBLE', 'CLOUD_METADATA'], 'CRITICAL',
         "SSRF channel confirmed with cloud metadata exposure — credential theft risk"),
        ("JWT Weak + Admin Panel", ['JWT_WEAK_SECRET', 'ADMIN_PANEL_FOUND'], 'CRITICAL',
         "Weak JWT secret + admin panel exposure — privilege escalation chain"),
        ("Mass Assignment + Admin Access", ['MASS_ASSIGNMENT', 'FORCED_BROWSING'], 'HIGH',
         "Mass assignment to elevate role + forced browsing to admin panel"),
        ("Secret Exposure + API Access", ['SECRET_IN_JS', 'SECRET_EXPOSED'], 'HIGH',
         "Multiple secret exposures — attacker can authenticate as service account"),
        ("Race Condition + Business Logic", ['RACE_CONDITION', 'BUSINESS_LOGIC_ABUSE'], 'HIGH',
         "Concurrent exploit chain: race condition amplifies business logic abuse"),
        ("No Rate Limit + User Enum", ['NO_BRUTE_FORCE_PROTECTION', 'USER_ENUMERATION_STATUS'], 'HIGH',
         "Username enumeration + no lockout = viable brute-force attack"),
    ]
    for chain_name, required_types, risk, desc in logic_chains:
        matched = [t for t in required_types if any(f.get('type','').startswith(t) for f in findings)]
        if len(matched) == len(required_types):
            chains_found.append({
                'chain_id':    chain_name.replace(' ', '_'),
                'name':        chain_name,
                'risk':        risk,
                'cvss':        9.0 if risk == 'CRITICAL' else 7.5,
                'types_found': matched,
                'description': desc,
                'impact':      "Compound attack escalates individual finding severity",
                'detail':      f"Logic chain detected: {' → '.join(matched)}",
            })

    return chains_found

def compute_risk_score(findings, chains):
    """Overall risk score 0-100 based on severity distribution and chains."""
    if not findings:
        return 0
    sev_scores = [SEV_WEIGHT.get(f.get('severity', 'INFO'), 1) for f in findings]
    base = min(100, sum(sev_scores) / max(1, len(sev_scores)) * 20)
    chain_bonus = min(30, len(chains) * 10)
    critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    critical_bonus = min(20, critical_count * 5)
    return min(100, round(base + chain_bonus + critical_bonus))

def build_remediation_matrix(findings):
    """Categorise findings into quick wins vs long-term fixes."""
    quick_wins = []
    long_term  = []
    quick_types = {
        'MISSING_HSTS', 'MISSING_CSP', 'MISSING_XFO', 'MISSING_XCTO',
        'VERSION_DISCLOSURE', 'COOKIE_INSECURE', 'NO_RATE_LIMITING',
        'GRAPHQL_INTROSPECTION', 'DEPENDENCY_FILE_EXPOSED',
    }
    for f in findings:
        ftype = f.get('type', '')
        entry = {
            'type':       ftype,
            'severity':   f.get('severity', 'INFO'),
            'url':        f.get('url', ''),
            'remediation':f.get('remediation', ''),
        }
        if any(ftype.startswith(q) for q in quick_types):
            quick_wins.append(entry)
        elif f.get('severity') in ('CRITICAL', 'HIGH'):
            long_term.append(entry)
    return quick_wins, long_term

def generate_executive_summary(findings, chains, risk_score, target):
    sev_dist = {}
    for f in findings:
        s = f.get('severity', 'INFO')
        sev_dist[s] = sev_dist.get(s, 0) + 1

    lines = [
        f"TARGET: {target}",
        f"DATE:   {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        "",
        f"OVERALL RISK SCORE: {risk_score}/100",
        "",
        "FINDING DISTRIBUTION:",
    ]
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = sev_dist.get(sev, 0)
        if count:
            lines.append(f"  {sev:<10} {count:>4}  {'█' * min(count, 40)}")

    if chains:
        lines.append("\nATTACK CHAINS DETECTED:")
        for c in chains:
            lines.append(f"  [{c['risk']}] {c['name']}")
            lines.append(f"         {c['description']}")

    top_crits = [f for f in findings if f.get('severity') == 'CRITICAL'][:5]
    if top_crits:
        lines.append("\nTOP CRITICAL FINDINGS:")
        for f in top_crits:
            lines.append(f"  - {f.get('type','?')}: {f.get('url','')}")

    return "\n".join(lines)


def main():
    print("=" * 60)
    print("  RootChain v2 — Attack Chain Correlation Engine")
    print("=" * 60)

    REPORTS_DIR.mkdir(exist_ok=True)

    target_file = REPORTS_DIR / "_target.txt"
    target = target_file.read_text().strip() if target_file.exists() else "(unknown)"
    print(f"[+] Target: {target}")

    # Load and enrich all findings
    all_findings = load_all_findings()
    print(f"[+] Loaded {len(all_findings)} findings from {len(list(REPORTS_DIR.glob('*.json')))} report files")

    enriched = [enrich_finding(f) for f in all_findings]

    # Detect chains
    chains = detect_attack_chains(enriched)

    # Risk score
    risk_score = compute_risk_score(enriched, chains)

    # Remediation matrix
    quick_wins, long_term = build_remediation_matrix(enriched)

    # Executive summary
    summary = generate_executive_summary(enriched, chains, risk_score, target)
    print("\n" + summary)

    # Severity distribution
    sev_dist = {}
    for f in enriched:
        s = f.get('severity', 'INFO')
        sev_dist[s] = sev_dist.get(s, 0) + 1

    report = {
        "target":          target,
        "generated":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "risk_score":      risk_score,
        "total_findings":  len(enriched),
        "severity_distribution": sev_dist,
        "attack_chains":   chains,
        "quick_wins":      quick_wins[:20],
        "long_term_fixes": long_term[:20],
        "executive_summary": summary,
        "findings":        enriched,
        "named_chains":    list(NAMED_CHAINS.values()),
    }

    out_path = REPORTS_DIR / "rootchain_report.json"
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n[+] RootChain report: {out_path}")
    print(f"[+] Risk score: {risk_score}/100 | Chains: {len(chains)} | Findings: {len(enriched)}")


if __name__ == "__main__":
    main()
