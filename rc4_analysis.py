#!/usr/bin/python3

# RC4 Analysis Script for MSc Dissertation
# Extracts and analyses Irish mail servers still using RC4 cipher suites
# RC4 was deprecated in RFC 7465 (February 2015) - finding RC4 in 2026 is significant

import json
import argparse
import collections

parser = argparse.ArgumentParser(description='Analyse RC4 usage from records.fresh')
parser.add_argument('-i', '--input', dest='infile', default='records.fresh',
                    help='Input file (default: records.fresh)')
parser.add_argument('-o', '--output', dest='outfile', default='rc4_analysis.json',
                    help='Output file (default: rc4_analysis.json)')
args = parser.parse_args()

TLS_PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']

PORT_SERVICES = {
    'p25': 'SMTP',
    'p110': 'POP3',
    'p143': 'IMAP',
    'p443': 'HTTPS',
    'p587': 'SMTP Submission',
    'p993': 'IMAPS',
}

# RC4 cipher suites to detect
RC4_CIPHERS = [
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_RC4_128_MD5',
    'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    'RC4',  # catch any others containing RC4
]

results = {
    'total_ips_scanned': 0,
    'rc4_servers': 0,
    'rc4_rate': 0.0,
    'by_port': {},
    'by_cipher': collections.Counter(),
    'rc4_ip_list': [],
    'asn_breakdown': collections.Counter(),
    'summary': {}
}

for port in TLS_PORTS:
    results['by_port'][port] = {
        'rc4_count': 0,
        'rc4_ciphers': collections.Counter(),
        'service': PORT_SERVICES[port],
    }

def get_cipher_suite(record, port):
    try:
        return record[port]['data']['tls']['server_hello']['cipher_suite']['name']
    except (KeyError, TypeError):
        return None

def get_tls_version(record, port):
    try:
        return record[port]['data']['tls']['server_hello']['version']['name']
    except (KeyError, TypeError):
        return None

def is_rc4(cipher):
    if not cipher:
        return False
    return 'RC4' in cipher.upper()

def get_asn(record):
    try:
        return record.get('autonomous_system', {}).get('name', 'Unknown')
    except (KeyError, TypeError):
        return 'Unknown'

def get_banner(record):
    try:
        return record['p25']['data']['banner'].strip()
    except (KeyError, TypeError):
        return None

print(f"Analysing RC4 usage from {args.infile}...")
print("RC4 was deprecated in RFC 7465 (February 2015)")
print("Finding RC4 in 2026 indicates severely outdated infrastructure\n")

processed = 0
rc4_ips = set()

with open(args.infile, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = record.get('ip', 'unknown')
        results['total_ips_scanned'] += 1
        processed += 1

        if processed % 1000 == 0:
            print(f"Processed {processed} IPs...")

        ip_rc4_ports = []

        for port in TLS_PORTS:
            cipher = get_cipher_suite(record, port)
            tls_ver = get_tls_version(record, port)

            if is_rc4(cipher):
                results['by_port'][port]['rc4_count'] += 1
                results['by_port'][port]['rc4_ciphers'][cipher] += 1
                results['by_cipher'][cipher] += 1
                ip_rc4_ports.append({
                    'port': port,
                    'service': PORT_SERVICES[port],
                    'cipher': cipher,
                    'tls_version': tls_ver,
                })

        if ip_rc4_ports:
            rc4_ips.add(ip)
            banner = get_banner(record)
            asn = get_asn(record)
            results['asn_breakdown'][asn] += 1
            results['rc4_ip_list'].append({
                'ip': ip,
                'asn': asn,
                'banner': banner,
                'rc4_ports': ip_rc4_ports,
                'num_rc4_ports': len(ip_rc4_ports),
            })

results['rc4_servers'] = len(rc4_ips)
results['rc4_rate'] = round(len(rc4_ips) / max(results['total_ips_scanned'], 1) * 100, 2)

# Convert Counters to dicts
results['by_cipher'] = dict(
    sorted(results['by_cipher'].items(), key=lambda x: x[1], reverse=True)
)
results['asn_breakdown'] = dict(
    sorted(results['asn_breakdown'].items(), key=lambda x: x[1], reverse=True)[:20]
)
for port in TLS_PORTS:
    results['by_port'][port]['rc4_ciphers'] = dict(results['by_port'][port]['rc4_ciphers'])

# Sort RC4 IP list by number of RC4 ports (worst offenders first)
results['rc4_ip_list'].sort(key=lambda x: x['num_rc4_ports'], reverse=True)

# Build summary
results['summary'] = {
    'total_ips_scanned': results['total_ips_scanned'],
    'rc4_servers': results['rc4_servers'],
    'rc4_rate_percent': results['rc4_rate'],
    'years_since_deprecation': 11,
    'most_common_rc4_cipher': list(results['by_cipher'].keys())[0] if results['by_cipher'] else 'None',
    'worst_asn': list(results['asn_breakdown'].keys())[0] if results['asn_breakdown'] else 'Unknown',
    'multi_port_rc4_servers': sum(1 for ip in results['rc4_ip_list'] if ip['num_rc4_ports'] > 1),
}

# Print summary
print("\n" + "="*60)
print("RC4 ANALYSIS SUMMARY")
print("="*60)
print(f"Total IPs scanned:          {results['total_ips_scanned']:,}")
print(f"Servers using RC4:          {results['rc4_servers']:,}")
print(f"RC4 prevalence rate:        {results['rc4_rate']}%")
print(f"Years since RFC 7465:       11 years (deprecated Feb 2015)")

print(f"\n--- RC4 Cipher Suites Found ---")
for cipher, count in results['by_cipher'].items():
    print(f"  {cipher}: {count}")

print(f"\n--- RC4 by Port ---")
for port in TLS_PORTS:
    p = results['by_port'][port]
    if p['rc4_count'] > 0:
        print(f"  {port} ({p['service']}): {p['rc4_count']} servers")
        for cipher, count in p['rc4_ciphers'].items():
            print(f"    └─ {cipher}: {count}")

print(f"\n--- Top ASNs with RC4 Servers ---")
for asn, count in list(results['asn_breakdown'].items())[:10]:
    print(f"  {asn}: {count} servers")

print(f"\n--- Servers with RC4 on Multiple Ports ---")
multi = [ip for ip in results['rc4_ip_list'] if ip['num_rc4_ports'] > 1]
print(f"  Count: {len(multi)}")
for ip_info in multi[:5]:
    ports = [p['port'] for p in ip_info['rc4_ports']]
    print(f"  {ip_info['ip']} — ports: {', '.join(ports)}")

print(f"\n--- Security Implication ---")
print(f"RC4 allows plaintext recovery attacks.")
print(f"These {results['rc4_servers']} servers have not been updated in 11+ years.")
print(f"Email traffic through these servers is potentially vulnerable.")

# Save results
with open(args.outfile, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nFull RC4 analysis saved to {args.outfile}")
print(f"RC4 server IPs saved — handle responsibly (do not publish individual IPs)")