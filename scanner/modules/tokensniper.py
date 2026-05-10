#!/usr/bin/env python3
import json
import base64
import re
import math
from collections import Counter
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from smart_filter import high_entropy, is_demo_value, confidence_score, confidence_label, severity_from_confidence

ENTROPY_THRESHOLD = 3.8
MIN_KEY_LENGTH = 16

class TokenSniper:
    def __init__(self):
        self.findings = []

    def entropy(self, s):
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v/n)*math.log2(v/n) for v in c.values())

    def decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header_raw = parts[0] + '=' * (4 - len(parts[0]) % 4)
            payload_raw = parts[1] + '=' * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_raw))
            payload = json.loads(base64.urlsafe_b64decode(payload_raw))
            return {'header': header, 'payload': payload, 'sig': parts[2]}
        except Exception:
            return None

    def analyze_jwt(self, token, source):
        decoded = self.decode_jwt(token)
        if not decoded:
            return None

        if is_demo_value(token):
            return None

        issues = []
        alg = decoded['header'].get('alg', '').lower()

        if alg == 'none':
            issues.append({
                'severity': 'CRITICAL',
                'issue': 'JWT_NONE_ALGORITHM',
                'detail': 'No signature verification — token can be forged'
            })
            print(f"  [CRITICAL] JWT uses none algorithm at {source}")

        if alg in ['hs256', 'hs384', 'hs512']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'JWT_SYMMETRIC',
                'detail': f'Symmetric {alg.upper()} — vulnerable to brute force if secret is weak'
            })
            print(f"  [MEDIUM] JWT uses symmetric {alg.upper()} at {source}")

        if 'exp' not in decoded['payload']:
            issues.append({
                'severity': 'HIGH',
                'issue': 'JWT_NO_EXPIRY',
                'detail': 'Token never expires — stolen token is valid indefinitely'
            })
            print(f"  [HIGH] JWT has no expiry at {source}")

        sensitive = ['password', 'secret', 'private', 'key', 'ssn', 'credit']
        for k in decoded['payload'].keys():
            if any(s in k.lower() for s in sensitive):
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'JWT_SENSITIVE_PAYLOAD',
                    'detail': f'Sensitive field in token: {k}'
                })
                print(f"  [HIGH] JWT contains sensitive field '{k}' at {source}")

        if not issues:
            return None

        conf = confidence_score({
            'has_issues': (len(issues) > 0, 50),
            'critical_issue': (any(i['severity'] == 'CRITICAL' for i in issues), 30),
            'not_demo': (not is_demo_value(token), 20),
        })

        return {
            'token_preview': token[:40] + '...',
            'source': source,
            'algorithm': decoded['header'].get('alg'),
            'payload_keys': list(decoded['payload'].keys()),
            'issues': issues,
            'confidence': conf,
            'confidence_label': confidence_label(conf),
        }

    def analyze_api_key(self, key, ktype, source):
        if len(key) < MIN_KEY_LENGTH:
            return None
        if is_demo_value(key):
            return None

        issues = []
        ent = self.entropy(key)

        if len(key) < 32:
            issues.append({
                'severity': 'HIGH',
                'issue': 'SHORT_KEY',
                'detail': f'Only {len(key)} chars — should be 32+'
            })
            print(f"  [HIGH] Short {ktype} ({len(key)} chars) at {source}")

        if ent < ENTROPY_THRESHOLD:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'LOW_ENTROPY',
                'detail': f'Entropy {ent:.2f} (threshold {ENTROPY_THRESHOLD}) — weak randomness'
            })
            print(f"  [MEDIUM] Low entropy {ktype} ({ent:.2f}) at {source}")

        if re.match(r'^[a-f0-9]{32}$', key.lower()):
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'POSSIBLE_MD5',
                'detail': 'Looks like MD5 hash — collision risk'
            })
            print(f"  [MEDIUM] Possible MD5 key at {source}")

        if not issues:
            return None

        conf = confidence_score({
            'has_issues': (len(issues) > 0, 40),
            'high_entropy_ok': (ent >= ENTROPY_THRESHOLD, 30),
            'long_enough': (len(key) >= 32, 20),
            'not_demo': (not is_demo_value(key), 10),
        })

        return {
            'type': ktype,
            'preview': key[:20] + '...',
            'source': source,
            'length': len(key),
            'entropy': round(ent, 2),
            'issues': issues,
            'confidence': conf,
            'confidence_label': confidence_label(conf),
        }

    def load_all_tokens(self):
        sources = [
            'reports/tokens_found.json',
            'reports/authdrift_leaks.json',
        ]
        tokens = []
        for src in sources:
            if Path(src).exists():
                try:
                    with open(src) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            tokens.extend(data)
                except Exception:
                    pass
        return tokens

    def run(self):
        print("="*60)
        print("  TokenSniper — Token & Key Weakness Analyzer")
        print("="*60)

        tokens = self.load_all_tokens()

        if not tokens:
            print("\n[*] No tokens found — run ghostcrawler.py first")
            return []

        print(f"\n[*] Analyzing {len(tokens)} tokens...\n")

        for t in tokens:
            ttype = t.get('type', '')
            value = t.get('value', '')
            source = t.get('url', 'unknown')

            if not value or len(value) < MIN_KEY_LENGTH:
                continue

            if is_demo_value(value):
                print(f"  [SKIP] Demo/placeholder value skipped at {source}")
                continue

            if ttype == 'JWT':
                result = self.analyze_jwt(value, source)
                if result and result['issues']:
                    self.findings.append(result)

            elif ttype in ['API_KEY', 'ACCESS_TOKEN', 'SECRET', 'BEARER', 'TOKEN']:
                if not high_entropy(value, threshold=ENTROPY_THRESHOLD, min_length=MIN_KEY_LENGTH):
                    print(f"  [SKIP] Low entropy or short {ttype} at {source} — likely not real")
                    continue
                result = self.analyze_api_key(value, ttype, source)
                if result and result['issues']:
                    self.findings.append(result)

            elif ttype == 'PASSWORD_LEAK':
                if len(value) < 6 or is_demo_value(value):
                    continue
                self.findings.append({
                    'type': 'PASSWORD_EXPOSED',
                    'severity': 'CRITICAL',
                    'confidence': 85,
                    'confidence_label': 'High',
                    'preview': value[:20] + '...',
                    'source': source,
                    'detail': 'Password exposed in API response'
                })
                print(f"  [CRITICAL] Password exposed at {source}")

            elif ttype == 'AWS_KEY':
                if not re.match(r'^AKIA[0-9A-Z]{16}$', value):
                    continue
                self.findings.append({
                    'type': 'AWS_KEY_EXPOSED',
                    'severity': 'CRITICAL',
                    'confidence': 95,
                    'confidence_label': 'High',
                    'preview': value[:20] + '...',
                    'source': source,
                    'proof': 'Matches AKIA[0-9A-Z]{16} pattern exactly',
                    'detail': 'AWS Access Key exposed'
                })
                print(f"  [CRITICAL] AWS key exposed at {source}")

            elif ttype == 'PRIVATE_KEY':
                self.findings.append({
                    'type': 'PRIVATE_KEY_EXPOSED',
                    'severity': 'CRITICAL',
                    'confidence': 95,
                    'confidence_label': 'High',
                    'source': source,
                    'detail': 'Private key material exposed'
                })
                print(f"  [CRITICAL] Private key exposed at {source}")

        return self.findings

def main():
    Path("reports").mkdir(exist_ok=True)
    sniper = TokenSniper()
    findings = sniper.run()
    with open("reports/tokensniper.json", 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"\n[+] {len(findings)} token issues -> reports/tokensniper.json")
    critical = [f for f in findings if
                any(i.get('severity') == 'CRITICAL'
                    for i in f.get('issues', [])) or
                f.get('severity') == 'CRITICAL']
    if critical:
        print(f"\n[!] {len(critical)} CRITICAL token issues found")
        for c in critical:
            print(f"    - {c.get('type', c.get('issue', 'UNKNOWN'))}: {c.get('source', '')}")

if __name__ == '__main__':
    main()
