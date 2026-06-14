#!/usr/bin/env python3
"""
rc4_hygiene_index.py

Computes a per-host "TLS Hygiene Index" from the existing FreshGrab.py scan
results (records.fresh) and validates it by comparing the score distribution
of known RC4 hosts (rc4/rc4_analysis.json) against the full population.

Indicators (1 point each, per port, host score = max over its TLS ports):
  - rc4              : RC4 cipher suite negotiated
  - legacy_tls       : SSLv3 / TLSv1.0 / TLSv1.1 negotiated
  - expired_cert     : leaf certificate expired at scan time
  - self_signed      : leaf certificate is self-signed
  - no_fwd_secrecy   : cipher suite is not (EC)DHE
  - untrusted_chain  : certificate chain not browser-trusted

Usage:
  source venv/bin/activate
  python3 rc4_hygiene_index.py \
      --records results/IE-20260317-171424/records.fresh \
      --rc4 rc4/rc4_analysis.json \
      --results results/IE-20260317-171424 \
      --outdir rc4/hygiene
"""

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import geoip2.database
except ImportError:
    geoip2 = None

try:
    from scipy.stats import mannwhitneyu
except ImportError:
    mannwhitneyu = None

PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']
LEGACY_VERSIONS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'}
RC4_CIPHER_VALUES = {5, 49169}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def parse_ts(s):
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def score_port(port_data, scan_time):
    """Return (score, flags_dict) for a single port's TLS data, or None if no TLS."""
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
    validity = leaf.get('validity', {})
    sig = leaf.get('signature', {})
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

    if 'browser_trusted' in validation:
        flags['untrusted_chain'] = not validation['browser_trusted']
    else:
        flags['untrusted_chain'] = False

    score = sum(1 for v in flags.values() if v)
    return score, flags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--records', default='results/IE-20260317-171424/records.fresh')
    ap.add_argument('--rc4', default='rc4/rc4_analysis.json')
    ap.add_argument('--results', default='results/IE-20260317-171424')
    ap.add_argument('--outdir', default='rc4/hygiene')
    ap.add_argument('--asn-db', default='mmdb/GeoLite2-ASN.mmdb')
    ap.add_argument('--limit', type=int, default=0, help='debug: only process first N hosts')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.rc4) as f:
        rc4_data = json.load(f)
    rc4_ips = set(e['ip'] for e in rc4_data['rc4_ip_list'])
    log(f"Loaded {len(rc4_ips)} known RC4 host IPs")

    asn_reader = None
    if geoip2 and os.path.exists(args.asn_db):
        asn_reader = geoip2.database.Reader(args.asn_db)
        log(f"Loaded ASN database: {args.asn_db}")
    else:
        log("WARNING: no ASN database available, ASN aggregation will be skipped")

    host_scores = {}        # ip -> overall score
    host_flag_counts = {}   # ip -> flags dict for the worst port
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
            host_flags = None  # OR'd across all TLS-bearing ports
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
                continue  # no TLS anywhere on this host

            host_score = sum(1 for v in host_flags.values() if v)
            total_with_tls += 1
            host_scores[ip] = host_score
            host_flag_counts[ip] = host_flags
            for k, v in host_flags.items():
                if v:
                    flag_totals[k] += 1

            if total_with_tls % 2000 == 0:
                log(f"  processed {total_with_tls} TLS hosts ({total_hosts} total lines)...")

    log(f"Done streaming. total_hosts={total_hosts} total_with_tls={total_with_tls}")

    # ── Population score distribution ──────────────────────────────────────
    score_dist = Counter(host_scores.values())

    # ── RC4 subset vs population ────────────────────────────────────────────
    rc4_scores = [s for ip, s in host_scores.items() if ip in rc4_ips]
    non_rc4_scores = [s for ip, s in host_scores.items() if ip not in rc4_ips]
    # exclude the rc4 indicator itself when comparing "other" neglect, since
    # rc4 hosts trivially score >=1 on that flag
    rc4_other_scores = []
    non_rc4_other_scores = []
    for ip, flags in host_flag_counts.items():
        other = sum(1 for k, v in flags.items() if v and k != 'rc4')
        if ip in rc4_ips:
            rc4_other_scores.append(other)
        else:
            non_rc4_other_scores.append(other)

    mwu_result = None
    if mannwhitneyu and rc4_other_scores and non_rc4_other_scores:
        stat, p = mannwhitneyu(rc4_other_scores, non_rc4_other_scores, alternative='greater')
        mwu_result = {'statistic': stat, 'p_value': p}
        log(f"Mann-Whitney U (RC4 hosts have higher 'other neglect' score than non-RC4): "
            f"U={stat:.1f}, p={p:.3e}")

    # ── ASN aggregation ──────────────────────────────────────────────────────
    asn_scores = defaultdict(list)
    if asn_reader:
        for ip, score in host_scores.items():
            try:
                resp = asn_reader.asn(ip)
                org = resp.autonomous_system_organization or 'Unknown'
            except Exception:
                org = 'Unknown'
            asn_scores[org].append(score)

    asn_summary = []
    for org, scores in asn_scores.items():
        if len(scores) < 5:
            continue
        asn_summary.append({
            'org': org,
            'n_hosts': len(scores),
            'mean_score': sum(scores) / len(scores),
            'max_score': max(scores),
        })
    asn_summary.sort(key=lambda x: x['mean_score'], reverse=True)

    # ── Cluster overlay ────────────────────────────────────────────────────
    cluster_files = sorted(glob.glob(os.path.join(args.results, 'cluster*.json')))
    cluster_summary = []
    for cf in cluster_files:
        with open(cf) as fh:
            members = json.load(fh)
        scores = [host_scores[m['ip']] for m in members if m['ip'] in host_scores]
        if not scores:
            continue
        cnum = members[0]['clusternum']
        cluster_summary.append({
            'clusternum': cnum,
            'csize': len(members),
            'n_scored': len(scores),
            'mean_score': sum(scores) / len(scores),
            'max_score': max(scores),
        })

    # ── Save outputs ─────────────────────────────────────────────────────────
    summary = {
        'total_hosts': total_hosts,
        'total_with_tls': total_with_tls,
        'flag_totals': dict(flag_totals),
        'flag_rates': {k: v / total_with_tls for k, v in flag_totals.items()},
        'score_distribution': dict(sorted(score_dist.items())),
        'rc4': {
            'n_rc4_hosts_scored': len(rc4_scores),
            'rc4_score_distribution': dict(sorted(Counter(rc4_scores).items())),
            'non_rc4_score_distribution': dict(sorted(Counter(non_rc4_scores).items())),
            'rc4_mean_score': sum(rc4_scores) / len(rc4_scores) if rc4_scores else None,
            'non_rc4_mean_score': sum(non_rc4_scores) / len(non_rc4_scores) if non_rc4_scores else None,
            'rc4_mean_other_neglect': sum(rc4_other_scores) / len(rc4_other_scores) if rc4_other_scores else None,
            'non_rc4_mean_other_neglect': sum(non_rc4_other_scores) / len(non_rc4_other_scores) if non_rc4_other_scores else None,
            'mann_whitney_u': mwu_result,
        },
        'asn_top20_worst': asn_summary[:20],
        'asn_top20_best': sorted(asn_summary, key=lambda x: x['mean_score'])[:20],
    }

    with open(os.path.join(args.outdir, 'hygiene_summary.json'), 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    log(f"Wrote {os.path.join(args.outdir, 'hygiene_summary.json')}")

    with open(os.path.join(args.outdir, 'host_scores.json'), 'w') as f:
        json.dump({ip: {'score': s, 'flags': host_flag_counts[ip]} for ip, s in host_scores.items()}, f)
    log(f"Wrote {os.path.join(args.outdir, 'host_scores.json')}")

    with open(os.path.join(args.outdir, 'cluster_hygiene.json'), 'w') as f:
        json.dump(cluster_summary, f, indent=2)
    log(f"Wrote {os.path.join(args.outdir, 'cluster_hygiene.json')}")

    # ── Print quick summary ───────────────────────────────────────────────
    print("\n=== TLS Hygiene Index summary ===")
    print(f"Total hosts in records.fresh: {total_hosts}")
    print(f"Hosts with usable TLS handshake on >=1 port: {total_with_tls}")
    print("\nIndicator prevalence (fraction of TLS hosts):")
    for k, v in flag_totals.items():
        print(f"  {k:18s}: {v:6d} ({v/total_with_tls:.2%})")
    print("\nHost score distribution (0-6):")
    for s in sorted(score_dist):
        print(f"  score {s}: {score_dist[s]:6d}")
    print(f"\nRC4 hosts (n={len(rc4_scores)}): mean total score = {summary['rc4']['rc4_mean_score']:.2f}, "
          f"mean OTHER-neglect score (excl. rc4 flag) = {summary['rc4']['rc4_mean_other_neglect']:.2f}")
    print(f"Non-RC4 hosts (n={len(non_rc4_scores)}): mean total score = {summary['rc4']['non_rc4_mean_score']:.2f}, "
          f"mean OTHER-neglect score = {summary['rc4']['non_rc4_mean_other_neglect']:.2f}")
    if mwu_result:
        print(f"Mann-Whitney U test (RC4 > non-RC4 on other-neglect score): "
              f"U={mwu_result['statistic']:.1f}, p={mwu_result['p_value']:.3e}")

    print("\nWorst 10 ASNs by mean hygiene score (n_hosts >= 5):")
    for a in asn_summary[:10]:
        print(f"  {a['org']:40s} n={a['n_hosts']:5d} mean={a['mean_score']:.2f} max={a['max_score']}")


if __name__ == '__main__':
    main()
