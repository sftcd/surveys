#!/usr/bin/env python3
"""
rc4_hygiene_advanced.py

Two methodological extensions to the TLS Hygiene Index:

1. Data-driven weighting: fit a logistic regression predicting RC4 presence
   from the other 5 indicators. The resulting (standardised) coefficients
   give an empirically-derived weight for each indicator, replacing the
   naive equal-weight (+1 each) scheme. We then recompute a "weighted
   hygiene score" using these weights and compare its distribution for
   RC4 vs non-RC4 hosts.

2. ASN typology: cluster ASNs (>= min hosts) on their 6-dimensional
   indicator-rate vectors using k-means, producing an empirically-derived
   typology of provider "neglect profiles" rather than a manually sorted
   ranking.

Inputs:
  - rc4/hygiene/host_scores.json   (per-host flags, from rc4_hygiene_index.py)
  - mmdb/GeoLite2-ASN.mmdb         (for ASN lookup)

Usage:
  source venv/bin/activate
  python3 rc4_hygiene_advanced.py --hygiene rc4/hygiene/host_scores.json --outdir rc4/hygiene_advanced
"""

import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

try:
    import geoip2.database
except ImportError:
    geoip2 = None

INDICATORS = ['legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']
ALL_INDICATORS = ['rc4'] + INDICATORS


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hygiene', default='rc4/hygiene/host_scores.json')
    ap.add_argument('--asn-db', default='mmdb/GeoLite2-ASN.mmdb')
    ap.add_argument('--outdir', default='rc4/hygiene_advanced')
    ap.add_argument('--min-asn-hosts', type=int, default=10)
    ap.add_argument('--k', type=int, default=4, help='number of k-means clusters')
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    with open(args.hygiene) as f:
        host_scores = json.load(f)
    log(f"Loaded {len(host_scores)} hosts")

    # ── Part 1: data-driven weighting via logistic regression ──────────────
    X = []
    y = []
    ips = []
    for ip, entry in host_scores.items():
        flags = entry['flags']
        X.append([1 if flags[k] else 0 for k in INDICATORS])
        y.append(1 if flags['rc4'] else 0)
        ips.append(ip)
    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, y)
    coefs = clf.coef_[0]
    odds_ratios = np.exp(coefs)

    weights = {k: float(c) for k, c in zip(INDICATORS, coefs)}
    odds = {k: float(o) for k, o in zip(INDICATORS, odds_ratios)}

    log("Logistic regression coefficients (RC4 ~ other indicators):")
    for k in INDICATORS:
        log(f"  {k:18s} coef={weights[k]:+.3f}  odds_ratio={odds[k]:.2f}")

    # Recompute a weighted hygiene score using these coefficients
    # (rescale so the most predictive indicator = 1.0, for interpretability)
    max_coef = max(abs(c) for c in coefs)
    rescaled = {k: weights[k] / max_coef for k in INDICATORS}

    weighted_scores = {}
    for ip, entry in host_scores.items():
        flags = entry['flags']
        w = sum(rescaled[k] for k in INDICATORS if flags[k])
        weighted_scores[ip] = w

    rc4_ips = set(ip for ip, e in host_scores.items() if e['flags']['rc4'])
    rc4_weighted = [weighted_scores[ip] for ip in rc4_ips]
    non_rc4_weighted = [weighted_scores[ip] for ip in host_scores if ip not in rc4_ips]

    weighting_summary = {
        'logistic_regression': {
            'coefficients': weights,
            'odds_ratios': odds,
            'rescaled_weights': rescaled,
            'interpretation': (
                'odds_ratio > 1 means hosts with this issue are more likely '
                'to also use RC4; odds_ratio is the multiplicative change in '
                'odds of RC4 presence per indicator.'
            ),
        },
        'weighted_score_comparison': {
            'rc4_mean_weighted_score': float(np.mean(rc4_weighted)),
            'non_rc4_mean_weighted_score': float(np.mean(non_rc4_weighted)),
            'naive_equal_weight_for_reference': {
                'rc4_mean': float(np.mean([sum(1 for k in INDICATORS if host_scores[ip]['flags'][k]) for ip in rc4_ips])),
                'non_rc4_mean': float(np.mean([sum(1 for k in INDICATORS if host_scores[ip]['flags'][k]) for ip in host_scores if ip not in rc4_ips])),
            },
        },
    }

    # ── Part 2: ASN typology via k-means ────────────────────────────────────
    asn_reader = None
    if geoip2 and os.path.exists(args.asn_db):
        asn_reader = geoip2.database.Reader(args.asn_db)
    else:
        log("WARNING: no ASN DB, skipping typology")
        asn_reader = None

    typology_summary = None
    if asn_reader:
        asn_hosts = defaultdict(list)
        for ip, entry in host_scores.items():
            try:
                resp = asn_reader.asn(ip)
                org = resp.autonomous_system_organization or 'Unknown'
            except Exception:
                org = 'Unknown'
            asn_hosts[org].append(entry['flags'])

        asn_names = []
        asn_vectors = []
        asn_counts = []
        for org, flag_list in asn_hosts.items():
            if len(flag_list) < args.min_asn_hosts:
                continue
            n = len(flag_list)
            vec = [sum(1 for f in flag_list if f[k]) / n for k in ALL_INDICATORS]
            asn_names.append(org)
            asn_vectors.append(vec)
            asn_counts.append(n)

        X_asn = np.array(asn_vectors)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_asn)

        km = KMeans(n_clusters=args.k, random_state=42, n_init=10)
        labels = km.fit_predict(X_scaled)

        # Characterize each cluster by mean indicator rates (in original units)
        clusters = []
        for c in range(args.k):
            idx = [i for i, l in enumerate(labels) if l == c]
            if not idx:
                continue
            members = [{'org': asn_names[i], 'n_hosts': asn_counts[i],
                        'rates': dict(zip(ALL_INDICATORS, asn_vectors[i]))} for i in idx]
            mean_rates = {k: float(np.mean([asn_vectors[i][j] for i in idx]))
                           for j, k in enumerate(ALL_INDICATORS)}
            members.sort(key=lambda m: -m['n_hosts'])
            clusters.append({
                'cluster_id': c,
                'n_asns': len(idx),
                'mean_rates': mean_rates,
                'members': members,
            })
        clusters.sort(key=lambda c: sum(c['mean_rates'].values()), reverse=True)

        typology_summary = {
            'k': args.k,
            'n_asns_clustered': len(asn_names),
            'min_hosts_threshold': args.min_asn_hosts,
            'clusters': clusters,
        }

    out = {
        'weighting': weighting_summary,
        'asn_typology': typology_summary,
    }
    with open(os.path.join(args.outdir, 'hygiene_advanced.json'), 'w') as f:
        json.dump(out, f, indent=2)
    log(f"Wrote {os.path.join(args.outdir, 'hygiene_advanced.json')}")

    # ── Print report ────────────────────────────────────────────────────────
    print("\n=== Data-driven indicator weighting (logistic regression, RC4 ~ others) ===")
    for k in sorted(INDICATORS, key=lambda k: -odds[k]):
        print(f"  {k:18s} odds_ratio={odds[k]:6.2f}  rescaled_weight={rescaled[k]:+.2f}")
    print(f"\nWeighted score: RC4 hosts mean={weighting_summary['weighted_score_comparison']['rc4_mean_weighted_score']:.2f}, "
          f"non-RC4 mean={weighting_summary['weighted_score_comparison']['non_rc4_mean_weighted_score']:.2f}")
    print(f"Naive (equal-weight) score for reference: RC4 mean="
          f"{weighting_summary['weighted_score_comparison']['naive_equal_weight_for_reference']['rc4_mean']:.2f}, "
          f"non-RC4 mean={weighting_summary['weighted_score_comparison']['naive_equal_weight_for_reference']['non_rc4_mean']:.2f}")

    if typology_summary:
        print(f"\n=== ASN typology (k-means, k={args.k}, {typology_summary['n_asns_clustered']} ASNs with >={args.min_asn_hosts} hosts) ===")
        for c in typology_summary['clusters']:
            print(f"\nCluster {c['cluster_id']} ({c['n_asns']} ASNs):")
            for k in ALL_INDICATORS:
                print(f"    {k:18s} mean_rate={c['mean_rates'][k]:.2%}")
            top = ', '.join(f"{m['org']} (n={m['n_hosts']})" for m in c['members'][:5])
            print(f"    top members: {top}")


if __name__ == '__main__':
    main()
