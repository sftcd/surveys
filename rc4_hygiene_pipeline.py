#!/usr/bin/env python3
"""
rc4_hygiene_pipeline.py

Full RC4 / TLS Hygiene Index analysis pipeline — runs all four
computation stages in sequence, passing results in memory between stages:

  1. TLS Hygiene Index   — per-host 6-indicator score + Mann-Whitney U
                           validation → rc4/hygiene/
  2. Software hygiene    — SMTP banner classification + deployment model
                           attribution → rc4/software_hygiene/
  3. Advanced methods    — logistic-regression weighting + k-means ASN
                           typology → rc4/hygiene_advanced/
  4. Anomaly report      — prioritised RC4 outreach list (JSON + Markdown)
                           → rc4/anomaly_report/

Inputs (no scanning — all already on disk):
  results/IE-20260317-171424/records.fresh
  results/IE-20260317-171424/cluster*.json
  rc4/rc4_analysis.json
  mmdb/GeoLite2-ASN.mmdb

Usage:
  source venv/bin/activate
  python3 rc4_hygiene_pipeline.py
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

try:
    import geoip2.database
except ImportError:
    geoip2 = None

try:
    from scipy.stats import mannwhitneyu
except ImportError:
    mannwhitneyu = None

PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']
SMTP_PORTS = ['p25', 'p587']
INDICATORS = ['rc4', 'legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']
OTHER_INDICATORS = ['legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']
LEGACY_VERSIONS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}
RC4_CIPHER_VALUES = {5, 49169}
EXIM_EOL_VERSION = (4, 92)

SOFTWARE_PATTERNS = [
    (re.compile(r'Amazon SES', re.I),                   'Amazon SES',           None),
    (re.compile(r'Microsoft ESMTP MAIL Service', re.I), 'Microsoft Exchange',   re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'plesk', re.I),                        'Plesk',                re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'MailEnable', re.I),                   'MailEnable',           re.compile(r'Version:\s*([\d.]+)')),
    (re.compile(r'Postfix', re.I),                      'Postfix',              None),
    (re.compile(r'Exim', re.I),                         'Exim',                 re.compile(r'Exim\s+([\d.]+)')),
    (re.compile(r'Sendmail', re.I),                     'Sendmail',             re.compile(r'Sendmail\s+([\d.]+)')),
    (re.compile(r'Haraka', re.I),                       'Haraka',               re.compile(r'Haraka/([\d.]+)')),
    (re.compile(r'MDaemon', re.I),                      'MDaemon',              None),
    (re.compile(r'IceWarp', re.I),                      'IceWarp',              re.compile(r'IceWarp\s+([\d.]+)')),
    (re.compile(r'Trend Micro', re.I),                  'Trend Micro',          None),
    (re.compile(r'Sophos', re.I),                       'Sophos',               None),
    (re.compile(r'cisco', re.I),                        'Cisco ESA',            None),
    (re.compile(r'barracuda', re.I),                    'Barracuda',            None),
    (re.compile(r'Kerio', re.I),                        'Kerio',                re.compile(r'Kerio Connect\s+([\d.]+)')),
    (re.compile(r'Axigen', re.I),                       'Axigen',               None),
    (re.compile(r'CommuniGate', re.I),                  'Communigate',          re.compile(r'CommuniGate Pro\s+([\d.]+)')),
    (re.compile(r'OpenSMTPD', re.I),                    'OpenSMTPD',            None),
    (re.compile(r'Postcow|qmail', re.I),                'Qmail',                None),
]

DEPLOYMENT_MAP = {
    'Amazon SES': 'Managed Cloud', 'Microsoft Exchange': 'Self-Hosted',
    'Microsoft Exchange Online': 'Managed Cloud', 'Postfix': 'Self-Hosted',
    'Exim': 'Self-Hosted', 'Sendmail': 'Self-Hosted', 'Haraka': 'Self-Hosted',
    'OpenSMTPD': 'Self-Hosted', 'Communigate': 'Self-Hosted', 'Axigen': 'Self-Hosted',
    'Kerio': 'Self-Hosted', 'Qmail': 'Self-Hosted', 'MailEnable': 'Hosting Panel',
    'Plesk': 'Hosting Panel', 'MDaemon': 'Hosting Panel', 'IceWarp': 'Hosting Panel',
    'Trend Micro': 'Security Gateway', 'Sophos': 'Security Gateway',
    'Cisco ESA': 'Security Gateway', 'Barracuda': 'Security Gateway',
    'Other': 'Unknown/Other', 'Unknown': 'Unknown/Other',
}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def parse_ts(s):
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def score_port(port_data, scan_time):
    tls = port_data.get('data', {}).get('tls')
    if not tls or 'server_hello' not in tls:
        return None
    hello = tls['server_hello']
    cipher = hello.get('cipher_suite', {})
    cipher_name = cipher.get('name', '')
    cipher_value = cipher.get('value')
    version_name = hello.get('version', {}).get('name', '')
    certs = tls.get('server_certificates', {})
    leaf = certs.get('certificate', {}).get('parsed', {})
    sig = leaf.get('signature', {})
    validity = leaf.get('validity', {})
    validation = certs.get('validation', {})
    flags = {}
    flags['rc4'] = cipher_value in RC4_CIPHER_VALUES or 'RC4' in cipher_name
    flags['legacy_tls'] = version_name in LEGACY_VERSIONS
    flags['no_fwd_secrecy'] = not ('ECDHE' in cipher_name or 'DHE' in cipher_name)
    flags['self_signed'] = bool(sig.get('self_signed', False))
    end = validity.get('end')
    if end:
        try:
            flags['expired_cert'] = parse_ts(end) < scan_time
        except ValueError:
            flags['expired_cert'] = False
    else:
        flags['expired_cert'] = False
    flags['untrusted_chain'] = not validation.get('browser_trusted', True) if 'browser_trusted' in validation else False
    return sum(1 for v in flags.values() if v), flags


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


def best_hostname(nameset):
    if not nameset:
        return None
    for key in ('p25dn', 'p587dn', 'p443dn', 'rdns', 'banner'):
        v = nameset.get(key)
        if v and v not in ('Parallels Panel',):
            return v
    return nameset.get('rdns') or nameset.get('banner')


def open_asn_db(path):
    if geoip2 and os.path.exists(path):
        return geoip2.database.Reader(path)
    log("WARNING: no ASN database, ASN lookups skipped")
    return None


def run_hygiene_index(args, rc4_ips):
    log("\n=== Stage 1: TLS Hygiene Index ===")
    os.makedirs(args.hygiene_outdir, exist_ok=True)
    asn_reader = open_asn_db(args.asn_db)
    host_scores = {}
    host_flag_counts = {}
    flag_totals = Counter()
    total_with_tls = 0
    total_hosts = 0

    with open(args.records) as f:
        for i, line in enumerate(f):
            if args.limit and i >= args.limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total_hosts += 1
            ip = rec.get('ip')
            host_flags = None
            saw_tls = False
            for port in PORTS:
                pdata = rec.get(port)
                if not pdata:
                    continue
                ts = pdata.get('timestamp')
                try:
                    scan_time = parse_ts(ts) if ts else None
                except ValueError:
                    scan_time = None
                if scan_time is None:
                    continue
                result = score_port(pdata, scan_time)
                if result is None:
                    continue
                _, flags = result
                saw_tls = True
                if host_flags is None:
                    host_flags = dict(flags)
                else:
                    for k, v in flags.items():
                        host_flags[k] = host_flags[k] or v
            if not saw_tls:
                continue
            host_score = sum(1 for v in host_flags.values() if v)
            total_with_tls += 1
            host_scores[ip] = host_score
            host_flag_counts[ip] = host_flags
            for k, v in host_flags.items():
                if v:
                    flag_totals[k] += 1
            if total_with_tls % 2000 == 0:
                log(f"  {total_with_tls} TLS hosts processed...")

    rc4_scores = [s for ip, s in host_scores.items() if ip in rc4_ips]
    non_rc4_scores = [s for ip, s in host_scores.items() if ip not in rc4_ips]
    rc4_other, non_rc4_other = [], []
    for ip, flags in host_flag_counts.items():
        other = sum(1 for k, v in flags.items() if v and k != 'rc4')
        (rc4_other if ip in rc4_ips else non_rc4_other).append(other)

    mwu_result = None
    if mannwhitneyu and rc4_other and non_rc4_other:
        stat, p = mannwhitneyu(rc4_other, non_rc4_other, alternative='greater')
        mwu_result = {'statistic': stat, 'p_value': p}
        log(f"Mann-Whitney U: p={p:.3e}")

    asn_scores = defaultdict(list)
    if asn_reader:
        for ip, score in host_scores.items():
            try:
                org = asn_reader.asn(ip).autonomous_system_organization or 'Unknown'
            except Exception:
                org = 'Unknown'
            asn_scores[org].append(score)

    asn_summary = sorted([
        {'org': org, 'n_hosts': len(sc), 'mean_score': sum(sc)/len(sc), 'max_score': max(sc)}
        for org, sc in asn_scores.items() if len(sc) >= 5
    ], key=lambda x: x['mean_score'], reverse=True)

    cluster_summary = []
    for cf in sorted(glob.glob(os.path.join(args.results, 'cluster*.json'))):
        with open(cf) as fh:
            members = json.load(fh)
        scores = [host_scores[m['ip']] for m in members if m['ip'] in host_scores]
        if scores:
            cluster_summary.append({
                'clusternum': members[0]['clusternum'], 'csize': len(members),
                'n_scored': len(scores), 'mean_score': sum(scores)/len(scores),
                'max_score': max(scores)})

    summary = {
        'total_hosts': total_hosts, 'total_with_tls': total_with_tls,
        'flag_totals': dict(flag_totals),
        'flag_rates': {k: v/total_with_tls for k, v in flag_totals.items()},
        'score_distribution': dict(sorted(Counter(host_scores.values()).items())),
        'rc4': {
            'n_rc4_hosts_scored': len(rc4_scores),
            'rc4_score_distribution': dict(sorted(Counter(rc4_scores).items())),
            'non_rc4_score_distribution': dict(sorted(Counter(non_rc4_scores).items())),
            'rc4_mean_score': sum(rc4_scores)/len(rc4_scores) if rc4_scores else None,
            'non_rc4_mean_score': sum(non_rc4_scores)/len(non_rc4_scores) if non_rc4_scores else None,
            'rc4_mean_other_neglect': sum(rc4_other)/len(rc4_other) if rc4_other else None,
            'non_rc4_mean_other_neglect': sum(non_rc4_other)/len(non_rc4_other) if non_rc4_other else None,
            'mann_whitney_u': mwu_result,
        },
        'asn_top20_worst': asn_summary[:20],
        'asn_top20_best': sorted(asn_summary, key=lambda x: x['mean_score'])[:20],
    }

    with open(os.path.join(args.hygiene_outdir, 'hygiene_summary.json'), 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    with open(os.path.join(args.hygiene_outdir, 'host_scores.json'), 'w') as f:
        json.dump({ip: {'score': s, 'flags': host_flag_counts[ip]} for ip, s in host_scores.items()}, f)
    with open(os.path.join(args.hygiene_outdir, 'cluster_hygiene.json'), 'w') as f:
        json.dump(cluster_summary, f, indent=2)

    log(f"  Wrote rc4/hygiene/ (total_with_tls={total_with_tls})")
    print(f"\n[1] TLS Hygiene Index: {total_with_tls} hosts scored, "
          f"Mann-Whitney p={mwu_result['p_value']:.3e}" if mwu_result else
          f"\n[1] TLS Hygiene Index: {total_with_tls} hosts scored")

    return {ip: {'score': s, 'flags': host_flag_counts[ip]} for ip, s in host_scores.items()}


def run_software_hygiene(args, host_scores):
    log("\n=== Stage 2: Software hygiene ===")
    os.makedirs(args.software_outdir, exist_ok=True)
    software_count = Counter()
    deployment_count = Counter()
    software_records = defaultdict(list)
    deployment_records = defaultdict(list)
    exim_versions = []
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
            banner = next((rec.get(p, {}).get('data', {}).get('banner')
                           for p in SMTP_PORTS if rec.get(p, {}).get('data', {}).get('banner')), None)
            software, version = classify_banner(banner)
            deployment = DEPLOYMENT_MAP.get(software, 'Unknown/Other')
            software_count[software] += 1
            deployment_count[deployment] += 1
            entry = host_scores.get(ip)
            if entry is None:
                continue
            software_records[software].append(entry)
            deployment_records[deployment].append(entry)
            if software == 'Exim' and version:
                exim_versions.append((version, entry['score']))

    def summarize(records_dict, min_n=10):
        out = []
        for name, entries in records_dict.items():
            if len(entries) < min_n:
                continue
            scores = [e['score'] for e in entries]
            out.append({
                'name': name, 'n_hosts_with_tls': len(entries),
                'mean_hygiene_score': sum(scores)/len(scores),
                'indicator_rates': {ind: sum(1 for e in entries if e['flags'].get(ind))/len(entries)
                                    for ind in INDICATORS}})
        return sorted(out, key=lambda x: x['mean_hygiene_score'], reverse=True)

    eol_scores, supported_scores = [], []
    for v, score in exim_versions:
        vt = version_tuple(v)
        if vt:
            (eol_scores if vt < EXIM_EOL_VERSION else supported_scores).append(score)

    with open(os.path.join(args.software_outdir, 'software_hygiene_summary.json'), 'w') as f:
        json.dump({
            'total_hosts': total,
            'software_share': dict(software_count.most_common()),
            'deployment_share': dict(deployment_count.most_common()),
            'software_hygiene': summarize(software_records, min_n=10),
            'deployment_hygiene': summarize(deployment_records, min_n=5),
            'exim_version_analysis': {
                'n_with_version': len(exim_versions),
                'eol_threshold': f'<{EXIM_EOL_VERSION[0]}.{EXIM_EOL_VERSION[1]} (CVE-2019-10149)',
                'n_eol': len(eol_scores), 'n_supported': len(supported_scores),
                'mean_score_eol': sum(eol_scores)/len(eol_scores) if eol_scores else None,
                'mean_score_supported': sum(supported_scores)/len(supported_scores) if supported_scores else None,
            }}, f, indent=2)

    log("  Wrote rc4/software_hygiene/")
    print(f"[2] Software hygiene: {total} hosts classified")


def run_hygiene_advanced(args, host_scores):
    log("\n=== Stage 3: Advanced methods ===")
    os.makedirs(args.advanced_outdir, exist_ok=True)
    all_indicators = ['rc4'] + OTHER_INDICATORS

    X = np.array([[1 if e['flags'][k] else 0 for k in OTHER_INDICATORS]
                  for e in host_scores.values()], dtype=float)
    y = np.array([1 if e['flags']['rc4'] else 0 for e in host_scores.values()], dtype=int)

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, y)
    coefs = clf.coef_[0]
    odds = {k: float(np.exp(c)) for k, c in zip(OTHER_INDICATORS, coefs)}
    weights = {k: float(c) for k, c in zip(OTHER_INDICATORS, coefs)}
    max_coef = max(abs(c) for c in coefs)
    rescaled = {k: weights[k] / max_coef for k in OTHER_INDICATORS}

    rc4_ips_set = {ip for ip, e in host_scores.items() if e['flags']['rc4']}
    weighted_scores = {ip: sum(rescaled[k] for k in OTHER_INDICATORS if host_scores[ip]['flags'][k])
                       for ip in host_scores}
    rc4_w = [weighted_scores[ip] for ip in rc4_ips_set]
    non_rc4_w = [weighted_scores[ip] for ip in host_scores if ip not in rc4_ips_set]

    asn_reader = open_asn_db(args.asn_db)
    typology_summary = None
    if asn_reader:
        asn_hosts = defaultdict(list)
        for ip, entry in host_scores.items():
            try:
                org = asn_reader.asn(ip).autonomous_system_organization or 'Unknown'
            except Exception:
                org = 'Unknown'
            asn_hosts[org].append(entry['flags'])

        asn_names, asn_vectors, asn_counts = [], [], []
        for org, flag_list in asn_hosts.items():
            if len(flag_list) < args.min_asn_hosts:
                continue
            n = len(flag_list)
            asn_names.append(org)
            asn_vectors.append([sum(1 for f in flag_list if f[k]) / n for k in all_indicators])
            asn_counts.append(n)

        labels = KMeans(n_clusters=args.k, random_state=42, n_init=10).fit_predict(
            StandardScaler().fit_transform(np.array(asn_vectors)))

        clusters = []
        for c in range(args.k):
            idx = [i for i, l in enumerate(labels) if l == c]
            if not idx:
                continue
            mean_rates = {k: float(np.mean([asn_vectors[i][j] for i in idx]))
                          for j, k in enumerate(all_indicators)}
            members = sorted([{'org': asn_names[i], 'n_hosts': asn_counts[i],
                                'rates': dict(zip(all_indicators, asn_vectors[i]))} for i in idx],
                             key=lambda m: -m['n_hosts'])
            clusters.append({'cluster_id': c, 'n_asns': len(idx),
                              'mean_rates': mean_rates, 'members': members})
        clusters.sort(key=lambda c: sum(c['mean_rates'].values()), reverse=True)
        typology_summary = {'k': args.k, 'n_asns_clustered': len(asn_names),
                             'min_hosts_threshold': args.min_asn_hosts, 'clusters': clusters}

    with open(os.path.join(args.advanced_outdir, 'hygiene_advanced.json'), 'w') as f:
        json.dump({
            'weighting': {
                'logistic_regression': {'coefficients': weights, 'odds_ratios': odds,
                                         'rescaled_weights': rescaled},
                'weighted_score_comparison': {
                    'rc4_mean_weighted_score': float(np.mean(rc4_w)),
                    'non_rc4_mean_weighted_score': float(np.mean(non_rc4_w)),
                    'naive_equal_weight_for_reference': {
                        'rc4_mean': float(np.mean([sum(1 for k in OTHER_INDICATORS if host_scores[ip]['flags'][k]) for ip in rc4_ips_set])),
                        'non_rc4_mean': float(np.mean([sum(1 for k in OTHER_INDICATORS if host_scores[ip]['flags'][k]) for ip in host_scores if ip not in rc4_ips_set])),
                    }}},
            'asn_typology': typology_summary}, f, indent=2)

    log("  Wrote rc4/hygiene_advanced/")
    print(f"[3] Advanced methods: logistic regression + k-means done")


def run_anomaly_report(args, host_scores, rc4_ips, rc4_ip_info):
    log("\n=== Stage 4: Anomaly report ===")
    os.makedirs(args.anomaly_outdir, exist_ok=True)
    asn_reader = open_asn_db(args.asn_db)

    all_clusters = {}
    for cf in sorted(glob.glob(os.path.join(args.results, 'cluster*.json'))):
        with open(cf) as f:
            for m in json.load(f):
                all_clusters.setdefault(m['clusternum'], []).append(m)

    rc4_cluster_nums, rc4_in_clusters = set(), set()
    for cnum, members in all_clusters.items():
        for m in members:
            if m['ip'] in rc4_ips:
                rc4_cluster_nums.add(cnum)
                rc4_in_clusters.add(m['ip'])

    isolated_rc4 = rc4_ips - rc4_in_clusters

    CLASS_LABELS = {
        'cross_asn_rc4': 'Priority 1 — Cross-ASN key reuse (RC4 outlier in shared-key cluster)',
        'mass_rc4': 'Priority 2 — Mass RC4 deployment (>50% of cluster uses RC4)',
        'ecdhe_rc4_paradox': 'Priority 3 — ECDHE+RC4 paradox',
        'port_selective_rc4': 'Priority 3 — Port-selective RC4',
        'standard': 'Priority 4 — Other RC4 cluster',
    }

    cluster_reports = []
    for cnum in sorted(rc4_cluster_nums):
        members = all_clusters[cnum]
        rc4_members = [m for m in members if m['ip'] in rc4_ips]
        asns = sorted(set(m['asn'] for m in members))
        rc4_ratio = len(rc4_members) / len(members)
        has_paradox = any(m['analysis'].get('p25', {}).get('cipher_suite') == 49169 for m in rc4_members)
        has_port_selective = any(
            m['analysis'].get('p25', {}).get('cipher_suite') not in RC4_CIPHER_VALUES
            and m['analysis'].get('p25', {}).get('cipher_suite') is not None
            for m in rc4_members)
        if len(asns) > 1:
            cls, priority = 'cross_asn_rc4', 1
        elif rc4_ratio > 0.5:
            cls, priority = 'mass_rc4', 2
        elif has_paradox:
            cls, priority = 'ecdhe_rc4_paradox', 3
        elif has_port_selective:
            cls, priority = 'port_selective_rc4', 3
        else:
            cls, priority = 'standard', 4

        cluster_reports.append({
            'clusternum': cnum, 'classification': cls, 'priority': priority,
            'csize': len(members), 'rc4_count': len(rc4_members),
            'rc4_ratio': rc4_ratio, 'asns': asns, 'cross_asn': len(asns) > 1,
            'members': [{'ip': m['ip'], 'asn': m['asn'], 'asndec': m.get('asndec'),
                         'hostname': best_hostname(m['analysis'].get('nameset', {})),
                         'is_rc4': m['ip'] in rc4_ips,
                         'rc4_ports': [p['port'] for p in rc4_ip_info.get(m['ip'], {}).get('rc4_ports', [])],
                         'hygiene_score': host_scores.get(m['ip'], {}).get('score')} for m in members],
        })

    cluster_reports.sort(key=lambda c: (c['priority'], -c['rc4_count']))

    isolated_by_asn = defaultdict(list)
    for ip in isolated_rc4:
        info = rc4_ip_info[ip]
        asn = info.get('asn', 'Unknown')
        if (not asn or asn == 'Unknown') and asn_reader:
            try:
                asn = asn_reader.asn(ip).autonomous_system_organization or 'Unknown'
            except Exception:
                asn = 'Unknown'
        isolated_by_asn[asn].append({'ip': ip, 'banner': info.get('banner'),
                                      'rc4_ports': [p['port'] for p in info.get('rc4_ports', [])],
                                      'hygiene_score': host_scores.get(ip, {}).get('score')})

    isolated_summary = [{'asn': asn, 'n_hosts': len(hosts), 'hosts': hosts}
                        for asn, hosts in sorted(isolated_by_asn.items(), key=lambda x: -len(x[1]))]

    with open(os.path.join(args.anomaly_outdir, 'rc4_anomaly_report.json'), 'w') as f:
        json.dump({'cluster_reports': cluster_reports, 'isolated_rc4_by_asn': isolated_summary},
                  f, indent=2, default=str)

    md_path = os.path.join(args.anomaly_outdir, 'rc4_anomaly_report.md')
    with open(md_path, 'w') as f:
        f.write("# RC4 Remediation Outreach Report\n\n")
        f.write("Generated from `results/IE-20260317-171424`. For internal use ahead of "
                "supervisor consultation — do not contact providers without sign-off.\n\n")
        f.write(f"- {len(rc4_ips)} hosts running RC4 ciphers in total\n")
        f.write(f"- {len(rc4_in_clusters)} are in {len(rc4_cluster_nums)} key-reuse clusters\n")
        f.write(f"- {len(isolated_rc4)} are isolated (no key reuse)\n\n")
        f.write("## Part 1: RC4 hosts inside key-reuse clusters\n\n")
        for c in cluster_reports:
            f.write(f"### Cluster {c['clusternum']} — {CLASS_LABELS[c['classification']]}\n\n")
            f.write(f"- Size: {c['csize']} hosts, {c['rc4_count']} using RC4 ({c['rc4_ratio']:.0%})\n")
            f.write(f"- ASN(s): {', '.join(c['asns'])}{'  **<-- CROSS-ASN**' if c['cross_asn'] else ''}\n\n")
            f.write("| IP | ASN/Provider | Hostname | RC4? | RC4 ports | Hygiene score |\n")
            f.write("|---|---|---|---|---|---|\n")
            for m in c['members']:
                ports = ', '.join(p.replace('p', '') for p in m['rc4_ports']) or '-'
                f.write(f"| {m['ip']} | {m['asn']} | {m['hostname'] or '-'} | "
                        f"{'**YES**' if m['is_rc4'] else 'no'} | {ports} | {m['hygiene_score']} |\n")
            f.write("\n")
        f.write("## Part 2: Isolated RC4 hosts, grouped by ASN/provider\n\n")
        for grp in isolated_summary:
            f.write(f"### {grp['asn']} ({grp['n_hosts']} hosts)\n\n")
            f.write("| IP | Banner | RC4 ports | Hygiene score |\n|---|---|---|---|\n")
            for h in grp['hosts']:
                ports = ', '.join(p.replace('p', '') for p in h['rc4_ports'])
                f.write(f"| {h['ip']} | {(h['banner'] or '').replace('|','|')[:80]} | {ports} | {h['hygiene_score']} |\n")
            f.write("\n")

    log("  Wrote rc4/anomaly_report/")
    print(f"[4] Anomaly report: {len(rc4_cluster_nums)} RC4 clusters, {len(isolated_rc4)} isolated hosts")


def main():
    ap = argparse.ArgumentParser(description='RC4 / TLS Hygiene Index pipeline')
    ap.add_argument('--records',          default='results/IE-20260317-171424/records.fresh')
    ap.add_argument('--rc4',              default='rc4/rc4_analysis.json')
    ap.add_argument('--results',          default='results/IE-20260317-171424')
    ap.add_argument('--asn-db',           default='mmdb/GeoLite2-ASN.mmdb')
    ap.add_argument('--hygiene-outdir',   default='rc4/hygiene')
    ap.add_argument('--software-outdir',  default='rc4/software_hygiene')
    ap.add_argument('--advanced-outdir',  default='rc4/hygiene_advanced')
    ap.add_argument('--anomaly-outdir',   default='rc4/anomaly_report')
    ap.add_argument('--min-asn-hosts',    type=int, default=10)
    ap.add_argument('--k',                type=int, default=4)
    ap.add_argument('--limit',            type=int, default=0, help='debug: first N hosts only')
    args = ap.parse_args()

    with open(args.rc4) as f:
        rc4_data = json.load(f)
    rc4_ip_info = {e['ip']: e for e in rc4_data['rc4_ip_list']}
    rc4_ips = set(rc4_ip_info)
    log(f"Loaded {len(rc4_ips)} RC4 IPs")

    host_scores = run_hygiene_index(args, rc4_ips)
    run_software_hygiene(args, host_scores)
    run_hygiene_advanced(args, host_scores)
    run_anomaly_report(args, host_scores, rc4_ips, rc4_ip_info)
    print("\nAll analysis done.")


if __name__ == '__main__':
    main()
