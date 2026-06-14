#!/usr/bin/python3

# RC4 Cross-Reference Analysis
# Cross-references RC4 servers with certificate health and TLS version data
# to understand WHY servers are still running RC4 in 2026
# Hypothesis: RC4 servers are neglected infrastructure, not deliberate choices

import json
import argparse
import collections

parser = argparse.ArgumentParser(description='Cross-reference RC4 servers with cert data')
parser.add_argument('--rc4', dest='rc4file', default='rc4_analysis.json',
                    help='RC4 analysis JSON (default: rc4_analysis.json)')
parser.add_argument('--records', dest='recordsfile', default='records.fresh',
                    help='records.fresh from FreshGrab (default: records.fresh)')
parser.add_argument('--providers', dest='providersfile', default='rc4_providers.txt',
                    help='rc4_providers.txt from whois lookup (default: rc4_providers.txt)')
parser.add_argument('-o', '--output', dest='outfile', default='rc4_crossref.json',
                    help='Output file (default: rc4_crossref.json)')
args = parser.parse_args()

TLS_PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']

print("Loading RC4 analysis...")
with open(args.rc4file, 'r') as f:
    rc4_data = json.load(f)

# Build set of RC4 IPs
rc4_ips = set(entry['ip'] for entry in rc4_data['rc4_ip_list'])
print(f"RC4 servers found: {len(rc4_ips)}")

# Load provider data if available
provider_map = {}
try:
    with open(args.providersfile, 'r') as f:
        for line in f:
            line = line.strip()
            if ',' in line and not line.startswith('IP'):
                parts = line.split(',', 1)
                if len(parts) == 2:
                    provider_map[parts[0].strip()] = parts[1].strip()
    print(f"Provider data loaded for {len(provider_map)} IPs")
except FileNotFoundError:
    print("No provider file found, skipping provider analysis")

from datetime import datetime, timezone
now = datetime.now(timezone.utc)

def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S %Z', '%Y-%m-%dT%H:%M:%S%z']:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None

def get_cert(record, port):
    try:
        return record[port]['data']['tls']['server_certificates']['certificate']['parsed']
    except (KeyError, TypeError):
        return None

def get_tls_version(record, port):
    try:
        return record[port]['data']['tls']['server_hello']['version']['name']
    except (KeyError, TypeError):
        return None

def is_expired(cert):
    try:
        end_str = cert['validity']['end']
        end_date = parse_date(end_str)
        if end_date:
            return end_date < now, (now - end_date).days if end_date < now else 0
        return False, 0
    except (KeyError, TypeError):
        return False, 0

def is_self_signed(cert):
    try:
        issuer = cert.get('issuer_dn', '')
        subject = cert.get('subject_dn', '')
        if issuer and subject:
            return issuer == subject
        return False
    except (KeyError, TypeError):
        return False

# Results storage
rc4_server_profiles = []
neglect_indicators = {
    'expired_cert': 0,
    'self_signed': 0,
    'legacy_tls': 0,         # TLS 1.0 or 1.1
    'expired_and_legacy': 0, # both expired AND legacy TLS — strong neglect signal
    'triple_neglect': 0,     # expired + legacy TLS + self-signed
    'all_fine_except_rc4': 0 # valid cert, modern TLS, just RC4 — possibly deliberate
}
provider_rc4_counts = collections.Counter()
days_expired_distribution = collections.Counter()

print(f"\nScanning records.fresh for RC4 server profiles...")
print("This may take a few minutes...")

processed = 0
rc4_found = 0

with open(args.recordsfile, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = record.get('ip', 'unknown')
        processed += 1

        if processed % 2000 == 0:
            print(f"  Processed {processed} records, found {rc4_found} RC4 servers...")

        if ip not in rc4_ips:
            continue

        rc4_found += 1
        profile = {
            'ip': ip,
            'provider': provider_map.get(ip, 'Unknown'),
            'has_expired_cert': False,
            'has_self_signed': False,
            'has_legacy_tls': False,
            'max_days_expired': 0,
            'tls_versions': [],
            'neglect_score': 0,  # 0-3, higher = more neglected
        }

        for port in TLS_PORTS:
            cert = get_cert(record, port)
            tls_ver = get_tls_version(record, port)

            if tls_ver:
                if tls_ver not in profile['tls_versions']:
                    profile['tls_versions'].append(tls_ver)
                if tls_ver in ('TLSv1.0', 'TLSv1.1'):
                    profile['has_legacy_tls'] = True

            if cert is None:
                continue

            expired, days = is_expired(cert)
            if expired:
                profile['has_expired_cert'] = True
                profile['max_days_expired'] = max(profile['max_days_expired'], days)

            if is_self_signed(cert):
                profile['has_self_signed'] = True

        # Calculate neglect score
        if profile['has_expired_cert']:
            profile['neglect_score'] += 1
            neglect_indicators['expired_cert'] += 1
        if profile['has_self_signed']:
            profile['neglect_score'] += 1
            neglect_indicators['self_signed'] += 1
        if profile['has_legacy_tls']:
            profile['neglect_score'] += 1
            neglect_indicators['legacy_tls'] += 1

        if profile['has_expired_cert'] and profile['has_legacy_tls']:
            neglect_indicators['expired_and_legacy'] += 1
        if profile['has_expired_cert'] and profile['has_legacy_tls'] and profile['has_self_signed']:
            neglect_indicators['triple_neglect'] += 1
        if not profile['has_expired_cert'] and not profile['has_legacy_tls']:
            neglect_indicators['all_fine_except_rc4'] += 1

        # Days expired distribution
        if profile['max_days_expired'] > 0:
            if profile['max_days_expired'] <= 90:
                days_expired_distribution['0-90 days'] += 1
            elif profile['max_days_expired'] <= 365:
                days_expired_distribution['91-365 days'] += 1
            elif profile['max_days_expired'] <= 730:
                days_expired_distribution['1-2 years'] += 1
            else:
                days_expired_distribution['2+ years'] += 1

        # Provider breakdown
        if profile['provider'] and profile['provider'] != 'Unknown':
            provider_rc4_counts[profile['provider']] += 1

        rc4_server_profiles.append(profile)

# Summarise findings
total = len(rc4_server_profiles)

print("\n" + "="*60)
print("RC4 CROSS-REFERENCE ANALYSIS")
print("="*60)
print(f"RC4 servers analysed: {total}")

print(f"\n--- Neglect Indicators ---")
print(f"Also have expired certificates:  {neglect_indicators['expired_cert']} ({neglect_indicators['expired_cert']/max(total,1)*100:.1f}%)")
print(f"Also have self-signed certs:     {neglect_indicators['self_signed']} ({neglect_indicators['self_signed']/max(total,1)*100:.1f}%)")
print(f"Also use legacy TLS (1.0/1.1):   {neglect_indicators['legacy_tls']} ({neglect_indicators['legacy_tls']/max(total,1)*100:.1f}%)")
print(f"Expired cert + legacy TLS:       {neglect_indicators['expired_and_legacy']} ({neglect_indicators['expired_and_legacy']/max(total,1)*100:.1f}%)")
print(f"Triple neglect (all three):      {neglect_indicators['triple_neglect']} ({neglect_indicators['triple_neglect']/max(total,1)*100:.1f}%)")
print(f"Only issue is RC4 (otherwise OK):{neglect_indicators['all_fine_except_rc4']} ({neglect_indicators['all_fine_except_rc4']/max(total,1)*100:.1f}%)")

print(f"\n--- Neglect Score Distribution ---")
score_dist = collections.Counter(p['neglect_score'] for p in rc4_server_profiles)
for score in sorted(score_dist.keys()):
    label = {0: 'RC4 only (possibly deliberate)', 1: 'One other issue', 2: 'Two other issues', 3: 'Fully neglected'}.get(score, str(score))
    print(f"  Score {score} ({label}): {score_dist[score]} servers")

print(f"\n--- Days Expired Distribution (for servers with expired certs) ---")
for bucket, count in sorted(days_expired_distribution.items()):
    print(f"  {bucket}: {count} servers")

print(f"\n--- Top Providers with RC4 Servers ---")
for provider, count in provider_rc4_counts.most_common(10):
    print(f"  {provider}: {count} servers")

print(f"\n--- Interpretation ---")
neglected_pct = (total - neglect_indicators['all_fine_except_rc4']) / max(total, 1) * 100
print(f"  {neglected_pct:.1f}% of RC4 servers show at least one other sign of neglect")
print(f"  {neglect_indicators['all_fine_except_rc4']} servers ({neglect_indicators['all_fine_except_rc4']/max(total,1)*100:.1f}%) are otherwise healthy — RC4 may be deliberate config")
print(f"  {neglect_indicators['triple_neglect']} servers have expired certs, legacy TLS AND RC4 — clearly abandoned")

# Save results
output = {
    'summary': {
        'total_rc4_servers_analysed': total,
        'neglect_indicators': neglect_indicators,
        'neglect_score_distribution': dict(score_dist),
        'days_expired_distribution': dict(days_expired_distribution),
        'top_providers': dict(provider_rc4_counts.most_common(15)),
    },
    'server_profiles': rc4_server_profiles,
}

with open(args.outfile, 'w') as f:
    json.dump(output, f, indent=2)

print(f"\nFull results saved to {args.outfile}")