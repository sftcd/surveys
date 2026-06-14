#!/usr/bin/env python3
"""
rc4_software_hygiene.py

Classifies each host's mail server software from its SMTP banner
(records.fresh) and cross-references it with the TLS Hygiene Index
(rc4/hygiene/host_scores.json) to identify which software stacks /
deployment models are associated with poor TLS hygiene.

Usage:
  source venv/bin/activate
  python3 rc4_software_hygiene.py \
      --records results/IE-20260317-171424/records.fresh \
      --hygiene rc4/hygiene/host_scores.json \
      --outdir rc4/software_hygiene
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

PORTS = ['p25', 'p587']

# Ordered (regex, software_name, version_regex_or_None)
SOFTWARE_PATTERNS = [
    (re.compile(r'Amazon SES', re.I), 'Amazon SES', None),
    (re.compile(r'Microsoft ESMTP MAIL Service', re.I), 'Microsoft Exchange',
     re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'plesk', re.I), 'Plesk', re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'MailEnable', re.I), 'MailEnable', re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'Postfix', re.I), 'Postfix', None),
    (re.compile(r'Exim', re.I), 'Exim', re.compile(r'Exim\s+([\d.]+)')),
    (re.compile(r'Sendmail', re.I), 'Sendmail', re.compile(r'Sendmail\s+([\d.]+)')),
    (re.compile(r'Haraka', re.I), 'Haraka', re.compile(r'Haraka/([\d.]+)')),
    (re.compile(r'MDaemon', re.I), 'MDaemon', None),
    (re.compile(r'IceWarp', re.I), 'IceWarp', re.compile(r'IceWarp\s+([\d.]+)')),
    (re.compile(r'Trend Micro', re.I), 'Trend Micro', None),
    (re.compile(r'Sophos', re.I), 'Sophos', None),
    (re.compile(r'cisco', re.I), 'Cisco ESA', None),
    (re.compile(r'barracuda', re.I), 'Barracuda', None),
    (re.compile(r'Kerio', re.I), 'Kerio', re.compile(r'Kerio Connect\s+([\d.]+)')),
    (re.compile(r'Axigen', re.I), 'Axigen', None),
    (re.compile(r'CommuniGate', re.I), 'Communigate', re.compile(r'CommuniGate Pro\s+([\d.]+)')),
    (re.compile(r'OpenSMTPD', re.I), 'OpenSMTPD', None),
    (re.compile(r'Postcow|qmail', re.I), 'Qmail', None),
]

# Deployment model classification per identified software
DEPLOYMENT_MAP = {
    'Amazon SES': 'Managed Cloud',
    'Microsoft Exchange': 'Self-Hosted',  # refined below for Exchange Online
    'Microsoft Exchange Online': 'Managed Cloud',
    'Postfix': 'Self-Hosted',
    'Exim': 'Self-Hosted',
    'Sendmail': 'Self-Hosted',
    'Haraka': 'Self-Hosted',
    'OpenSMTPD': 'Self-Hosted',
    'Communigate': 'Self-Hosted',
    'Axigen': 'Self-Hosted',
    'Kerio': 'Self-Hosted',
    'Qmail': 'Self-Hosted',
    'MailEnable': 'Hosting Panel',
    'Plesk': 'Hosting Panel',
    'MDaemon': 'Hosting Panel',
    'IceWarp': 'Hosting Panel',
    'Trend Micro': 'Security Gateway',
    'Sophos': 'Security Gateway',
    'Cisco ESA': 'Security Gateway',
    'Barracuda': 'Security Gateway',
    'Other': 'Unknown/Other',
    'Unknown': 'Unknown/Other',
}

INDICATORS = ['rc4', 'legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']

# Exim versions older than this are affected by CVE-2019-10149 (RCE)
EXIM_EOL_VERSION = (4, 92)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def classify_banner(banner):
    if not banner:
        return 'Unknown', None
    for pattern, name, ver_re in SOFTWARE_PATTERNS:
        if pattern.search(banner):
            version = None
            if ver_re:
                m = ver_re.search(banner)
                if m:
                    version = m.group(1)
            if name == 'Microsoft Exchange' and 'outlook.office365.com' in banner.lower():
                name = 'Microsoft Exchange Online'
            return name, version
    return 'Other', None


def version_tuple(v):
    try:
        parts = [int(p) for p in v.split('.')[:2]]
        while len(parts) < 2:
            parts.append(0)
        return tuple(parts)
    except (ValueError, AttributeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--records', default='results/IE-20260317-171424/records.fresh')
    ap.add_argument('--hygiene', default='rc4/hygiene/host_scores.json')
    ap.add_argument('--outdir', default='rc4/software_hygiene')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.hygiene) as f:
        host_scores = json.load(f)
    log(f"Loaded hygiene scores for {len(host_scores)} hosts")

    software_count = Counter()
    deployment_count = Counter()
    # software -> list of (score, flags)
    software_records = defaultdict(list)
    deployment_records = defaultdict(list)
    exim_versions = []  # (version_str, score)

    total = 0
    with open(args.records) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            ip = rec.get('ip')

            banner = None
            for port in PORTS:
                pdata = rec.get(port, {})
                b = pdata.get('data', {}).get('banner')
                if b:
                    banner = b
                    break

            software, version = classify_banner(banner)
            deployment = DEPLOYMENT_MAP.get(software, 'Unknown/Other')

            software_count[software] += 1
            deployment_count[deployment] += 1

            entry = host_scores.get(ip)
            if entry is None:
                continue  # host had no usable TLS handshake

            software_records[software].append(entry)
            deployment_records[deployment].append(entry)

            if software == 'Exim' and version:
                exim_versions.append((version, entry['score']))

            if total % 5000 == 0:
                log(f"  processed {total} hosts...")

    log(f"Done. total_hosts={total}")

    def summarize(records_dict, min_n=10):
        out = []
        for name, entries in records_dict.items():
            if len(entries) < min_n:
                continue
            scores = [e['score'] for e in entries]
            indicator_rates = {}
            for ind in INDICATORS:
                indicator_rates[ind] = sum(1 for e in entries if e['flags'].get(ind)) / len(entries)
            out.append({
                'name': name,
                'n_hosts_with_tls': len(entries),
                'mean_hygiene_score': sum(scores) / len(scores),
                'indicator_rates': indicator_rates,
            })
        out.sort(key=lambda x: x['mean_hygiene_score'], reverse=True)
        return out

    software_summary = summarize(software_records, min_n=10)
    deployment_summary = summarize(deployment_records, min_n=5)

    # Exim version / EOL analysis
    eol_scores, supported_scores = [], []
    for v, score in exim_versions:
        vt = version_tuple(v)
        if vt is None:
            continue
        if vt < EXIM_EOL_VERSION:
            eol_scores.append(score)
        else:
            supported_scores.append(score)

    exim_summary = {
        'n_with_version': len(exim_versions),
        'eol_threshold': f'<{EXIM_EOL_VERSION[0]}.{EXIM_EOL_VERSION[1]} (CVE-2019-10149)',
        'n_eol': len(eol_scores),
        'n_supported': len(supported_scores),
        'mean_score_eol': sum(eol_scores) / len(eol_scores) if eol_scores else None,
        'mean_score_supported': sum(supported_scores) / len(supported_scores) if supported_scores else None,
    }

    summary = {
        'total_hosts': total,
        'software_share': dict(software_count.most_common()),
        'deployment_share': dict(deployment_count.most_common()),
        'software_hygiene': software_summary,
        'deployment_hygiene': deployment_summary,
        'exim_version_analysis': exim_summary,
    }

    with open(os.path.join(args.outdir, 'software_hygiene_summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    log(f"Wrote {os.path.join(args.outdir, 'software_hygiene_summary.json')}")

    # Print quick report
    print("\n=== Software / Deployment vs TLS Hygiene ===")
    print(f"\nSoftware share (top 10, all hosts incl. those without TLS):")
    for name, c in software_count.most_common(10):
        print(f"  {name:25s}: {c:6d} ({c/total:.1%})")

    print(f"\nMean hygiene score by software (n>=10 TLS hosts):")
    for s in software_summary:
        print(f"  {s['name']:25s} n={s['n_hosts_with_tls']:5d}  mean_score={s['mean_hygiene_score']:.2f}  "
              f"self_signed={s['indicator_rates']['self_signed']:.1%}  expired={s['indicator_rates']['expired_cert']:.1%}")

    print(f"\nMean hygiene score by deployment model:")
    for d in deployment_summary:
        print(f"  {d['name']:20s} n={d['n_hosts_with_tls']:5d}  mean_score={d['mean_hygiene_score']:.2f}")

    print(f"\nExim version / EOL analysis:")
    print(f"  {exim_summary}")


if __name__ == '__main__':
    main()
