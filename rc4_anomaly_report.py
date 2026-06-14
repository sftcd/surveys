#!/usr/bin/env python3
"""
rc4_anomaly_report.py

Produces a detailed, prioritised report of RC4-affected key-reuse clusters
and providers, intended as the basis for remediation outreach (after
consultation with supervisor).

For each of the clusters that contain >=1 RC4 server, this lists:
  - cluster id, size, classification (cross-ASN / mass RC4 / paradox /
    port-selective / standard)
  - every member's IP, ASN/provider, hostname (from nameset), and
    TLS Hygiene Index score
  - which RC4 servers are involved and on which ports

Clusters are ordered by outreach priority:
  1. Cross-ASN clusters (a key is shared across organisations - one
     degraded peer may indicate a forgotten/cloned image)
  2. Mass RC4 deployments (single provider, many affected hosts -
     one contact fixes many servers)
  3. ECDHE+RC4 paradox / port-selective / standard

Also reports RC4 hosts that are NOT part of any key-reuse cluster
(isolated RC4 servers), grouped by ASN/provider.

Inputs:
  - rc4/rc4_analysis.json
  - rc4/hygiene/host_scores.json
  - results/IE-20260317-171424/cluster*.json

Usage:
  source venv/bin/activate
  python3 rc4_anomaly_report.py --outdir rc4/anomaly_report
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict

try:
    import geoip2.database
except ImportError:
    geoip2 = None

RC4_CIPHERS = {5, 49169}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def best_hostname(nameset):
    if not nameset:
        return None
    for key in ('p25dn', 'p587dn', 'p443dn', 'rdns', 'banner'):
        v = nameset.get(key)
        if v and v not in ('Parallels Panel',):
            return v
    return nameset.get('rdns') or nameset.get('banner')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rc4', default='rc4/rc4_analysis.json')
    ap.add_argument('--hygiene', default='rc4/hygiene/host_scores.json')
    ap.add_argument('--results', default='results/IE-20260317-171424')
    ap.add_argument('--outdir', default='rc4/anomaly_report')
    ap.add_argument('--asn-db', default='mmdb/GeoLite2-ASN.mmdb')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    asn_reader = None
    if geoip2 and os.path.exists(args.asn_db):
        asn_reader = geoip2.database.Reader(args.asn_db)
    else:
        log("WARNING: no ASN database, isolated-host ASNs will be 'Unknown'")

    with open(args.rc4) as f:
        rc4_data = json.load(f)
    rc4_ip_info = {e['ip']: e for e in rc4_data['rc4_ip_list']}
    rc4_ips = set(rc4_ip_info)
    log(f"Loaded {len(rc4_ips)} RC4 hosts")

    with open(args.hygiene) as f:
        host_scores = json.load(f)

    # Load all clusters
    cluster_files = sorted(glob.glob(os.path.join(args.results, 'cluster*.json')))
    all_clusters = {}
    for cf in cluster_files:
        with open(cf) as f:
            members = json.load(f)
        for m in members:
            cnum = m['clusternum']
            all_clusters.setdefault(cnum, []).append(m)

    # Find RC4-containing clusters
    rc4_cluster_nums = set()
    rc4_in_clusters = set()
    for cnum, members in all_clusters.items():
        for m in members:
            if m['ip'] in rc4_ips:
                rc4_cluster_nums.add(cnum)
                rc4_in_clusters.add(m['ip'])

    isolated_rc4 = rc4_ips - rc4_in_clusters
    log(f"RC4 hosts in key-reuse clusters: {len(rc4_in_clusters)} "
        f"(in {len(rc4_cluster_nums)} clusters)")
    log(f"Isolated RC4 hosts (no key reuse): {len(isolated_rc4)}")

    # Classify and build cluster reports
    cluster_reports = []
    for cnum in sorted(rc4_cluster_nums):
        members = all_clusters[cnum]
        rc4_members = [m for m in members if m['ip'] in rc4_ips]
        asns = sorted(set(m['asn'] for m in members))
        rc4_ratio = len(rc4_members) / len(members)

        has_paradox = any(
            m['analysis'].get('p25', {}).get('cipher_suite') == 49169
            for m in rc4_members
        )
        has_port_selective = any(
            m['analysis'].get('p25', {}).get('cipher_suite') not in RC4_CIPHERS
            and m['analysis'].get('p25', {}).get('cipher_suite') is not None
            for m in rc4_members
        )

        if len(asns) > 1:
            cls = 'cross_asn_rc4'
            priority = 1
        elif rc4_ratio > 0.5:
            cls = 'mass_rc4'
            priority = 2
        elif has_paradox:
            cls = 'ecdhe_rc4_paradox'
            priority = 3
        elif has_port_selective:
            cls = 'port_selective_rc4'
            priority = 3
        else:
            cls = 'standard'
            priority = 4

        member_details = []
        for m in members:
            ip = m['ip']
            score_entry = host_scores.get(ip, {})
            rc4_ports = rc4_ip_info.get(ip, {}).get('rc4_ports', [])
            member_details.append({
                'ip': ip,
                'asn': m['asn'],
                'asndec': m.get('asndec'),
                'hostname': best_hostname(m['analysis'].get('nameset', {})),
                'is_rc4': ip in rc4_ips,
                'rc4_ports': [p['port'] for p in rc4_ports],
                'hygiene_score': score_entry.get('score'),
            })

        cluster_reports.append({
            'clusternum': cnum,
            'classification': cls,
            'priority': priority,
            'csize': len(members),
            'rc4_count': len(rc4_members),
            'rc4_ratio': rc4_ratio,
            'asns': asns,
            'cross_asn': len(asns) > 1,
            'members': member_details,
        })

    cluster_reports.sort(key=lambda c: (c['priority'], -c['rc4_count']))

    # Isolated RC4 hosts grouped by ASN
    isolated_by_asn = defaultdict(list)
    for ip in isolated_rc4:
        info = rc4_ip_info[ip]
        score_entry = host_scores.get(ip, {})
        asn = info.get('asn', 'Unknown')
        if (not asn or asn == 'Unknown') and asn_reader:
            try:
                resp = asn_reader.asn(ip)
                asn = resp.autonomous_system_organization or 'Unknown'
            except Exception:
                asn = 'Unknown'
        isolated_by_asn[asn].append({
            'ip': ip,
            'banner': info.get('banner'),
            'rc4_ports': [p['port'] for p in info.get('rc4_ports', [])],
            'hygiene_score': score_entry.get('score'),
        })

    isolated_summary = []
    for asn, hosts in sorted(isolated_by_asn.items(), key=lambda x: -len(x[1])):
        isolated_summary.append({'asn': asn, 'n_hosts': len(hosts), 'hosts': hosts})

    out = {
        'cluster_reports': cluster_reports,
        'isolated_rc4_by_asn': isolated_summary,
    }
    with open(os.path.join(args.outdir, 'rc4_anomaly_report.json'), 'w') as f:
        json.dump(out, f, indent=2, default=str)
    log(f"Wrote {os.path.join(args.outdir, 'rc4_anomaly_report.json')}")

    # ── Markdown report ──────────────────────────────────────────────────
    md_path = os.path.join(args.outdir, 'rc4_anomaly_report.md')
    with open(md_path, 'w') as f:
        f.write("# RC4 Remediation Outreach Report\n\n")
        f.write("Generated from `results/IE-20260317-171424`. For internal "
                "use ahead of supervisor consultation — do not contact "
                "providers without sign-off.\n\n")
        f.write(f"- {len(rc4_ips)} hosts running RC4 ciphers in total\n")
        f.write(f"- {len(rc4_in_clusters)} of these are in {len(rc4_cluster_nums)} "
                f"key-reuse clusters\n")
        f.write(f"- {len(isolated_rc4)} are isolated (no key reuse with other hosts)\n\n")

        f.write("## Part 1: RC4 hosts inside key-reuse clusters\n\n")
        f.write("Ordered by outreach priority: cross-ASN anomalies first "
                "(shared key across organisations), then mass-RC4 "
                "deployments (single provider, many hosts), then other "
                "anomaly types.\n\n")

        CLASS_LABELS = {
            'cross_asn_rc4': 'Priority 1 — Cross-ASN key reuse (RC4 outlier in shared-key cluster)',
            'mass_rc4': 'Priority 2 — Mass RC4 deployment (>50% of cluster uses RC4)',
            'ecdhe_rc4_paradox': 'Priority 3 — ECDHE+RC4 paradox (forward secrecy negotiated, RC4 cipher offered)',
            'port_selective_rc4': 'Priority 3 — Port-selective RC4 (RC4 on some services, modern TLS on others)',
            'standard': 'Priority 4 — Other RC4 cluster',
        }

        for c in cluster_reports:
            f.write(f"### Cluster {c['clusternum']} — {CLASS_LABELS[c['classification']]}\n\n")
            f.write(f"- Size: {c['csize']} hosts, {c['rc4_count']} using RC4 "
                    f"({c['rc4_ratio']:.0%})\n")
            f.write(f"- ASN(s): {', '.join(c['asns'])}"
                    f"{'  **<-- CROSS-ASN**' if c['cross_asn'] else ''}\n\n")
            f.write("| IP | ASN/Provider | Hostname | RC4? | RC4 ports | Hygiene score |\n")
            f.write("|---|---|---|---|---|---|\n")
            for m in c['members']:
                rc4_mark = '**YES**' if m['is_rc4'] else 'no'
                ports = ', '.join(p.replace('p', '') for p in m['rc4_ports']) or '-'
                f.write(f"| {m['ip']} | {m['asn']} | {m['hostname'] or '-'} | "
                        f"{rc4_mark} | {ports} | {m['hygiene_score']} |\n")
            f.write("\n")

        f.write("## Part 2: Isolated RC4 hosts (no key reuse), grouped by ASN/provider\n\n")
        f.write("These hosts use RC4 but don't share keys with other scanned "
                "hosts. Grouped here so a single contact at a provider can "
                "be made for multiple hosts where applicable.\n\n")
        for grp in isolated_summary:
            f.write(f"### {grp['asn']} ({grp['n_hosts']} hosts)\n\n")
            f.write("| IP | Banner | RC4 ports | Hygiene score |\n")
            f.write("|---|---|---|---|\n")
            for h in grp['hosts']:
                ports = ', '.join(p.replace('p', '') for p in h['rc4_ports'])
                banner = (h['banner'] or '').replace('|', '\\|')[:80]
                f.write(f"| {h['ip']} | {banner} | {ports} | {h['hygiene_score']} |\n")
            f.write("\n")

    log(f"Wrote {md_path}")

    # ── Print summary ───────────────────────────────────────────────────
    print("\n=== RC4 Anomaly / Outreach Report Summary ===")
    print(f"Total RC4 hosts: {len(rc4_ips)}")
    print(f"  In key-reuse clusters: {len(rc4_in_clusters)} ({len(rc4_cluster_nums)} clusters)")
    print(f"  Isolated: {len(isolated_rc4)}")
    print("\nClusters by priority:")
    for c in cluster_reports:
        cross = ' [CROSS-ASN]' if c['cross_asn'] else ''
        print(f"  Cluster {c['clusternum']:4d}  {c['classification']:20s} "
              f"size={c['csize']:3d} rc4={c['rc4_count']:3d}  ASNs={c['asns']}{cross}")
    print("\nIsolated RC4 hosts by ASN (top 10):")
    for grp in isolated_summary[:10]:
        print(f"  {grp['asn']:40s} n={grp['n_hosts']}")


if __name__ == '__main__':
    main()
