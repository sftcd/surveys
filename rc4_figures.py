#!/usr/bin/env python3
"""
rc4_figures.py

Generates all 12 figures for the RC4 / TLS Hygiene Index dissertation chapter.
Reads from the JSON outputs of rc4_hygiene_pipeline.py and writes PNGs to
rc4_hygiene_charts/.

  fig1   — Population TLS Hygiene Index score distribution
  fig2   — RC4 vs non-RC4 host score comparison (validation)
  fig3   — Indicator prevalence across population
  fig4   — ASN/provider ranking (best & worst)
  fig5   — Key-reuse cluster hygiene vs cluster size
  fig6   — Mean hygiene score by mail server software
  fig7   — Mean hygiene score by deployment model
  fig8   — Exim EOL vs supported version hygiene
  fig9   — Logistic regression indicator weighting
  fig10  — ASN typology k-means heatmap
  fig11  — RC4 hosts by ASN/provider (clustered vs isolated)
  fig12  — Cluster 43 deep-dive: cipher per port per host

Usage:
  source venv/bin/activate
  python3 rc4_figures.py
"""

import argparse
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

ap = argparse.ArgumentParser(description='RC4/Hygiene Index figures')
ap.add_argument('--results',      default='',
                help='Results directory, e.g. results/IE-20260317-171424 '
                     '(auto-detected if omitted)')
ap.add_argument('--hygiene-dir',  default='rc4/hygiene')
ap.add_argument('--software-dir', default='rc4/software_hygiene')
ap.add_argument('--advanced-dir', default='rc4/hygiene_advanced')
ap.add_argument('--anomaly-dir',  default='rc4/anomaly_report')
ap.add_argument('--cluster',      default='',
                help='Path to cluster JSON for the cross-ASN RC4 deep-dive figure '
                     '(auto-derived from --results if omitted)')
ap.add_argument('--outdir',       default='rc4_hygiene_charts')
args = ap.parse_args()

# Auto-detect results directory if not given
if not args.results:
    import glob as _glob
    candidates = sorted(_glob.glob('results/*/'), reverse=True)
    args.results = candidates[0].rstrip('/') if candidates else 'results'

# Auto-derive cluster path if not given
if not args.cluster:
    args.cluster = os.path.join(args.results, 'cluster43.json')

os.makedirs(args.outdir, exist_ok=True)

RED    = '#e74c3c'
BLUE   = '#3498db'
GREY   = '#bdc3c7'
GREEN  = '#27ae60'
ORANGE = '#f39c12'

INDICATOR_LABELS = {
    'rc4':            'RC4 cipher\nin use',
    'legacy_tls':     'Legacy TLS\n(<=1.1)',
    'expired_cert':   'Expired\ncertificate',
    'self_signed':    'Self-signed\ncertificate',
    'no_fwd_secrecy': 'No forward\nsecrecy',
    'untrusted_chain':'Untrusted\ncert chain',
}
ALL_INDICATORS = ['rc4', 'legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']
OTHER_INDICATORS = ['legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']


def clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def save(fig, name):
    path = os.path.join(args.outdir, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


def label_bar(ax, bar, val, fmt=None, offset=0.02):
    s = fmt if fmt else str(val)
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + offset, s,
            ha='center', va='bottom', fontsize=10, fontweight='bold')


def label_hbar(ax, bar, val, fmt=None, offset=0.02):
    s = fmt if fmt else str(val)
    ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2, s,
            ha='left', va='center', fontsize=9, fontweight='bold')


# ── Load data ─────────────────────────────────────────────────────────────────
with open(os.path.join(args.hygiene_dir, 'hygiene_summary.json')) as f:
    hygiene = json.load(f)
with open(os.path.join(args.hygiene_dir, 'cluster_hygiene.json')) as f:
    clusters = json.load(f)
with open(os.path.join(args.hygiene_dir, 'host_scores.json')) as f:
    host_scores = json.load(f)
with open(os.path.join(args.software_dir, 'software_hygiene_summary.json')) as f:
    software = json.load(f)
with open(os.path.join(args.advanced_dir, 'hygiene_advanced.json')) as f:
    advanced = json.load(f)
with open(os.path.join(args.anomaly_dir, 'rc4_anomaly_report.json')) as f:
    anomaly = json.load(f)

# ══════════════════════════════════════════════════════════════════════════════
# Figure 1 — Population score distribution
# ══════════════════════════════════════════════════════════════════════════════
print('[1] Hygiene score distribution...')

score_dist = {int(k): v for k, v in hygiene['score_distribution'].items()}
scores_sorted = sorted(score_dist)
counts = [score_dist[s] for s in scores_sorted]
total = sum(counts)

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(scores_sorted, counts, color=BLUE, edgecolor='white', width=0.6)
for bar, c in zip(bars, counts):
    label_bar(ax, bar, c, fmt=f'{c}\n({c/total:.1%})', offset=total * 0.005)
ax.set_xlabel('TLS Hygiene Index score (0 = clean, 6 = all indicators present)')
ax.set_ylabel('Number of hosts')
ax.set_title(f'Distribution of TLS Hygiene Index scores\nacross {total:,} hosts with a usable TLS handshake')
ax.set_xticks(scores_sorted)
clean(ax)
save(fig, 'fig1_score_distribution.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 2 — RC4 hosts vs population
# ══════════════════════════════════════════════════════════════════════════════
print('[2] RC4 vs population...')

rc4 = hygiene['rc4']
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle('RC4 hosts show systematically worse TLS hygiene\nthan the rest of the scanned population',
             fontsize=13, fontweight='bold', y=1.03)

labels = [f"RC4 hosts\n(n={rc4['n_rc4_hosts_scored']})",
          f"Non-RC4 hosts\n(n={total - rc4['n_rc4_hosts_scored']})"]
means = [rc4['rc4_mean_other_neglect'], rc4['non_rc4_mean_other_neglect']]
bars = ax1.bar(labels, means, color=[RED, GREY], edgecolor='white', width=0.5)
for bar, v in zip(bars, means):
    label_bar(ax1, bar, v, fmt=f'{v:.2f}', offset=0.05)
ax1.set_ylabel('Mean number of OTHER neglect indicators\n(expired cert, self-signed, untrusted chain,\nno forward secrecy, legacy TLS)')
ax1.set_title('Mean "other neglect" score')
ax1.set_ylim(0, max(means) * 1.3)
mwu = rc4.get('mann_whitney_u')
if mwu:
    ax1.text(0.5, 0.95, f"Mann-Whitney U test: p = {mwu['p_value']:.1e}",
             transform=ax1.transAxes, ha='center', va='top', fontsize=10, style='italic')
clean(ax1)

rc4_dist = {int(k): v for k, v in rc4['rc4_score_distribution'].items()}
non_rc4_dist = {int(k): v for k, v in rc4['non_rc4_score_distribution'].items()}
all_scores = sorted(set(rc4_dist) | set(non_rc4_dist))
rc4_n = sum(rc4_dist.values())
non_rc4_n = sum(non_rc4_dist.values())
rc4_frac = [rc4_dist.get(s, 0) / rc4_n for s in all_scores]
non_rc4_frac = [non_rc4_dist.get(s, 0) / non_rc4_n for s in all_scores]

x = np.arange(len(all_scores))
w = 0.35
ax2.bar(x - w/2, non_rc4_frac, w, label='Non-RC4 hosts', color=GREY, edgecolor='white')
ax2.bar(x + w/2, rc4_frac, w, label='RC4 hosts', color=RED, edgecolor='white')
ax2.set_xticks(x)
ax2.set_xticklabels(all_scores)
ax2.set_xlabel('Total TLS Hygiene Index score (0-6, includes RC4 flag)')
ax2.set_ylabel('Fraction of group')
ax2.set_title('Score distribution: RC4 vs non-RC4 hosts')
ax2.legend()
clean(ax2)
save(fig, 'fig2_rc4_vs_population.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 3 — Indicator prevalence
# ══════════════════════════════════════════════════════════════════════════════
print('[3] Indicator prevalence...')

order = ['untrusted_chain', 'self_signed', 'expired_cert', 'no_fwd_secrecy', 'rc4', 'legacy_tls']
rates = [hygiene['flag_rates'].get(k, 0) for k in order]
labels_3 = [INDICATOR_LABELS[k] for k in order]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(labels_3, [r * 100 for r in rates], color=BLUE, edgecolor='white')
for bar, r in zip(bars, rates):
    label_bar(ax, bar, r, fmt=f'{r:.1%}', offset=0.5)
ax.set_ylabel('Percentage of TLS hosts (%)')
ax.set_title(f'Prevalence of TLS Hygiene Index indicators\nacross {total:,} hosts with a usable TLS handshake')
clean(ax)
save(fig, 'fig3_indicator_prevalence.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 4 — ASN ranking
# ══════════════════════════════════════════════════════════════════════════════
print('[4] ASN ranking...')

worst = hygiene['asn_top20_worst'][:10]
best = hygiene['asn_top20_best'][:10]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
fig.subplots_adjust(wspace=0.6)
fig.suptitle('ASN/provider ranking by mean TLS Hygiene Index score\n(providers with >=5 scanned hosts)',
             fontsize=13, fontweight='bold', y=1.02)

for ax, data_list, color, title in [
    (ax1, worst, RED, 'Worst 10 providers'),
    (ax2, best, GREEN, 'Best 10 providers'),
]:
    orgs = [f"{d['org']} (n={d['n_hosts']})" for d in data_list][::-1]
    means = [d['mean_score'] for d in data_list][::-1]
    bars = ax.barh(orgs, means, color=color, edgecolor='white')
    for bar, v in zip(bars, means):
        label_hbar(ax, bar, f'{v:.2f}', offset=0.03)
    ax.set_xlabel('Mean TLS Hygiene Index score')
    ax.set_title(title)
    ax.set_xlim(0, max(max(worst, key=lambda d: d['mean_score'])['mean_score'], 1) * 1.25)
    clean(ax)
save(fig, 'fig4_asn_ranking.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 5 — Cluster hygiene vs size
# ══════════════════════════════════════════════════════════════════════════════
print('[5] Cluster hygiene vs size...')

big = [c for c in clusters if c['csize'] >= 5]
small = [c for c in clusters if c['csize'] < 5]
big_mean = sum(c['mean_score'] for c in big) / len(big)
small_mean = sum(c['mean_score'] for c in small) / len(small)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle('Key-reuse clusters and TLS hygiene', fontsize=13, fontweight='bold', y=1.02)

sizes = [c['csize'] for c in clusters]
means_c = [c['mean_score'] for c in clusters]
ax1.scatter(sizes, means_c, alpha=0.4, color=BLUE, edgecolor='none', s=25)
ax1.set_xscale('log')
ax1.set_xlabel('Cluster size (hosts sharing a key, log scale)')
ax1.set_ylabel('Mean TLS Hygiene Index score of cluster members')
ax1.set_title('Cluster size vs mean hygiene score\n(each point = one key-reuse cluster)')
clean(ax1)

bar_labels_5 = [f'Small clusters\n(<5 members, n={len(small)})',
                f'Large clusters\n(>=5 members, n={len(big)})']
bars = ax2.bar(bar_labels_5, [small_mean, big_mean], color=[GREY, BLUE], edgecolor='white', width=0.5)
for bar, v in zip(bars, [small_mean, big_mean]):
    label_bar(ax2, bar, v, fmt=f'{v:.2f}', offset=0.01)
ax2.set_ylabel('Mean TLS Hygiene Index score')
ax2.set_title('Large key-reuse clusters skew toward\nworse TLS hygiene')
clean(ax2)
save(fig, 'fig5_cluster_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 6 — Hygiene score by software
# ══════════════════════════════════════════════════════════════════════════════
print('[6] Hygiene score by software...')

sw = sorted(software['software_hygiene'], key=lambda x: x['mean_hygiene_score'], reverse=True)
names6 = [f"{s['name']} (n={s['n_hosts_with_tls']})" for s in sw][::-1]
scores6 = [s['mean_hygiene_score'] for s in sw][::-1]
colors6 = [RED if s['mean_hygiene_score'] >= 1.5 else (ORANGE if s['mean_hygiene_score'] >= 0.7 else GREEN)
           for s in sw][::-1]

fig, ax = plt.subplots(figsize=(9, 7))
bars = ax.barh(names6, scores6, color=colors6, edgecolor='white')
for bar, v in zip(bars, scores6):
    label_hbar(ax, bar, f'{v:.2f}', offset=0.03)
ax.set_xlabel('Mean TLS Hygiene Index score')
ax.set_title('Mean TLS Hygiene Index score by mail server software\n'
             '(identified via SMTP banner, n>=10 hosts with TLS)')
ax.set_xlim(0, max(scores6) * 1.15)
clean(ax)
save(fig, 'fig6_software_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 7 — Hygiene score by deployment model
# ══════════════════════════════════════════════════════════════════════════════
print('[7] Hygiene score by deployment model...')

dep = sorted(software['deployment_hygiene'], key=lambda x: x['mean_hygiene_score'], reverse=True)
names7 = [f"{d['name']}\n(n={d['n_hosts_with_tls']})" for d in dep]
scores7 = [d['mean_hygiene_score'] for d in dep]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(names7, scores7, color=BLUE, edgecolor='white', width=0.55)
for bar, v in zip(bars, scores7):
    label_bar(ax, bar, v, fmt=f'{v:.2f}', offset=0.02)
ax.set_ylabel('Mean TLS Hygiene Index score')
ax.set_title('TLS hygiene by deployment model\nManaged cloud mail platforms vs self-managed infrastructure')
clean(ax)
save(fig, 'fig7_deployment_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 8 — Exim EOL vs supported
# ══════════════════════════════════════════════════════════════════════════════
print('[8] Exim EOL vs supported...')

ex = software['exim_version_analysis']
labels8 = [f"EOL Exim (<4.92)\nCVE-2019-10149\n(n={ex['n_eol']})",
           f"Supported Exim (>=4.92)\n(n={ex['n_supported']})"]
means8 = [ex['mean_score_eol'], ex['mean_score_supported']]

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(labels8, means8, color=[RED, GREY], edgecolor='white', width=0.45)
for bar, v in zip(bars, means8):
    label_bar(ax, bar, v, fmt=f'{v:.2f}', offset=0.02)
ax.set_ylabel('Mean TLS Hygiene Index score')
ax.set_title('TLS hygiene of Exim deployments\nrunning end-of-life vs supported versions')
ax.set_ylim(0, max(means8) * 1.3)
clean(ax)
save(fig, 'fig8_exim_eol_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 9 — Logistic regression weighting
# ══════════════════════════════════════════════════════════════════════════════
print('[9] Logistic regression weighting...')

w = advanced['weighting']['logistic_regression']
order9 = sorted(OTHER_INDICATORS, key=lambda k: w['odds_ratios'][k], reverse=True)
odds9 = [w['odds_ratios'][k] for k in order9]
labels9 = [INDICATOR_LABELS[k] for k in order9]
colors9 = [RED if o > 1 else BLUE for o in odds9]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
fig.subplots_adjust(wspace=0.35)
fig.suptitle('Data-driven indicator weighting via logistic regression\n'
             '(predicting RC4 presence from the other 5 hygiene indicators)',
             fontsize=13, fontweight='bold', y=1.04)

bars9 = ax1.bar(labels9, odds9, color=colors9, edgecolor='white')
ax1.axhline(1.0, color='black', linewidth=1, linestyle='--')
ax1.set_yscale('log')
for bar, o in zip(bars9, odds9):
    ax1.text(bar.get_x() + bar.get_width()/2, o * 1.15, f'{o:.2f}',
             ha='center', fontsize=10, fontweight='bold')
ax1.set_ylabel('Odds ratio for RC4 presence (log scale)')
ax1.set_title('Odds ratio per indicator\n(>1 = co-occurs more with RC4, <1 = less)')
clean(ax1)

comp = advanced['weighting']['weighted_score_comparison']
naive = comp['naive_equal_weight_for_reference']
groups9 = ['Naive\n(equal weight, 0-5)', 'Data-driven\n(logistic-weighted)']
rc4_vals9 = [naive['rc4_mean'], comp['rc4_mean_weighted_score']]
non_rc4_vals9 = [naive['non_rc4_mean'], comp['non_rc4_mean_weighted_score']]

x9 = np.arange(len(groups9))
wbar = 0.35
b1 = ax2.bar(x9 - wbar/2, non_rc4_vals9, wbar, label='Non-RC4 hosts', color=GREY, edgecolor='white')
b2 = ax2.bar(x9 + wbar/2, rc4_vals9, wbar, label='RC4 hosts', color=RED, edgecolor='white')
for bar, v in zip(list(b1) + list(b2), non_rc4_vals9 + rc4_vals9):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.03, f'{v:.2f}',
             ha='center', fontsize=10, fontweight='bold')
ax2.set_xticks(x9)
ax2.set_xticklabels(groups9)
ax2.set_ylabel('Mean "other neglect" score')
ax2.set_title('Naive vs data-driven scoring:\nseparation between RC4 and non-RC4 hosts')
ax2.legend()
clean(ax2)
save(fig, 'fig9_logistic_weighting.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 10 — ASN typology heatmap
# ══════════════════════════════════════════════════════════════════════════════
print('[10] ASN typology heatmap...')

typ = advanced['asn_typology']
typ_clusters = typ['clusters']

matrix10 = np.array([[c['mean_rates'][k] for k in ALL_INDICATORS] for c in typ_clusters])
row_labels10 = [f"Cluster {c['cluster_id']}\n({c['n_asns']} ASNs)\ne.g. {c['members'][0]['org']}"
                for c in typ_clusters]
col_labels10 = [INDICATOR_LABELS[k] for k in ALL_INDICATORS]

fig, ax = plt.subplots(figsize=(10, 1.2 * len(typ_clusters) + 2))
im = ax.imshow(matrix10, cmap='Reds', vmin=0, vmax=1, aspect='auto')
ax.set_xticks(range(len(col_labels10)))
ax.set_xticklabels(col_labels10, fontsize=9)
ax.set_yticks(range(len(row_labels10)))
ax.set_yticklabels(row_labels10, fontsize=9)
for i in range(matrix10.shape[0]):
    for j in range(matrix10.shape[1]):
        val = matrix10[i, j]
        ax.text(j, i, f'{val:.0%}', ha='center', va='center',
                color='white' if val > 0.5 else 'black', fontsize=10, fontweight='bold')
ax.set_title(f'ASN typology via k-means clustering (k={typ["k"]})\n'
             f'Mean indicator prevalence per cluster, {typ["n_asns_clustered"]} ASNs '
             f'with >={typ["min_hosts_threshold"]} scanned hosts')
fig.colorbar(im, ax=ax, label='Mean prevalence within cluster', shrink=0.8)
save(fig, 'fig10_asn_typology_heatmap.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 11 — RC4 hosts by provider
# ══════════════════════════════════════════════════════════════════════════════
print('[11] RC4 hosts by provider...')

clustered_asn = defaultdict(int)
for c in anomaly['cluster_reports']:
    for m in c['members']:
        if m['is_rc4']:
            clustered_asn[m['asn']] += 1

isolated_asn = {grp['asn']: grp['n_hosts'] for grp in anomaly['isolated_rc4_by_asn']}

providers = set(clustered_asn) | set(isolated_asn)
totals11 = {p: clustered_asn.get(p, 0) + isolated_asn.get(p, 0) for p in providers}
ordered11 = sorted(providers, key=lambda p: totals11[p], reverse=True)

names11 = ordered11[::-1]
clustered_vals11 = [clustered_asn.get(p, 0) for p in names11]
isolated_vals11 = [isolated_asn.get(p, 0) for p in names11]

fig, ax = plt.subplots(figsize=(9, 0.4 * len(names11) + 2))
ax.barh(names11, clustered_vals11, color=RED, edgecolor='white', label='In key-reuse cluster')
ax.barh(names11, isolated_vals11, left=clustered_vals11, color=BLUE, edgecolor='white', label='Isolated')
for i, p in enumerate(names11):
    ax.text(totals11[p] + 0.5, i, str(totals11[p]), va='center', fontsize=9, fontweight='bold')
ax.set_xlabel('Number of RC4 hosts')
ax.set_title('RC4 hosts by ASN/provider\n(remediation outreach priority — split by key-reuse status)')
ax.legend()
clean(ax)
save(fig, 'fig11_rc4_by_provider.png')


# ══════════════════════════════════════════════════════════════════════════════
# Figure 12 — Cluster 43 deep-dive
# ══════════════════════════════════════════════════════════════════════════════
print('[12] Cluster 43 deep-dive...')

PORTS_12 = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']

CIPHER_INFO = {
    None:  ('-', 0),
    5:     ('RC4', 1),
    53:    ('AES256-CBC\n(RSA)', 2),
    47:    ('AES128-CBC\n(RSA)', 2),
    49171: ('ECDHE-AES128\nCBC', 3),
    49172: ('ECDHE-AES256\nCBC', 3),
    49199: ('ECDHE-AES128\nGCM', 4),
}

CAT_COLORS = {
    0: '#f5f5f5', 1: '#e74c3c', 2: '#f39c12', 3: '#85c1e9', 4: '#3498db',
}
CAT_LABELS = {
    0: 'No TLS on this port',
    1: 'RC4 (broken cipher, no forward secrecy)',
    2: 'AES-CBC / RSA key exchange (no forward secrecy)',
    3: 'ECDHE + AES-CBC (forward secrecy)',
    4: 'ECDHE + AES-GCM (forward secrecy, modern)',
}

RC4_IP = '46.22.131.131'
with open(args.cluster) as f:
    members43 = json.load(f)

members_sorted = sorted(members43, key=lambda m: (m['ip'] != RC4_IP, m['asn'], m['ip']))

cat_matrix = np.zeros((len(members_sorted), len(PORTS_12)), dtype=int)
text_matrix = []
row_labels12 = []

for i, m in enumerate(members_sorted):
    a = m['analysis']
    row_text = []
    for j, p in enumerate(PORTS_12):
        cipher = a.get(p, {}).get('cipher_suite')
        label, cat = CIPHER_INFO.get(cipher, (f'#{cipher}', 1))
        cat_matrix[i, j] = cat
        row_text.append(label)
    text_matrix.append(row_text)
    score = host_scores.get(m['ip'], {}).get('score')
    score_str = str(score) if score is not None else '-'
    short_asn = 'Blacknight' if 'Blacknight' in m['asn'] else 'Iomart/bluemonkeyweb'
    flag = '  <-- RC4 OUTLIER' if m['ip'] == RC4_IP else ''
    row_labels12.append(f"{m['ip']}  ({short_asn}, hygiene={score_str}){flag}")

cmap12 = mcolors.ListedColormap([CAT_COLORS[c] for c in range(5)])
bounds12 = [-0.5, 0.5, 1.5, 2.5, 3.5, 4.5]
norm12 = mcolors.BoundaryNorm(bounds12, cmap12.N)

fig, ax = plt.subplots(figsize=(10, 0.45 * len(members_sorted) + 2))
ax.imshow(cat_matrix, cmap=cmap12, norm=norm12, aspect='auto')

ax.set_xticks(range(len(PORTS_12)))
ax.set_xticklabels([p.replace('p', 'Port ') for p in PORTS_12], fontsize=10)
ax.set_yticks(range(len(members_sorted)))
ax.set_yticklabels(row_labels12, fontsize=8)

for i in range(cat_matrix.shape[0]):
    for j in range(cat_matrix.shape[1]):
        ax.text(j, i, text_matrix[i][j], ha='center', va='center', fontsize=6.5)

ax.add_patch(plt.Rectangle((-0.5, -0.5), len(PORTS_12), 1, fill=False,
                            edgecolor='lime', linewidth=3.5, zorder=5))
ax.set_title('Cluster 43 — cross-ASN key-reuse cluster (23 hosts share the same TLS certificate)\n'
             'Negotiated cipher per mail port — one host (top row) is the only member using RC4',
             fontsize=11, fontweight='bold')

handles = [plt.Rectangle((0, 0), 1, 1, color=CAT_COLORS[c]) for c in range(5)]
ax.legend(handles, [CAT_LABELS[c] for c in range(5)],
          loc='upper center', bbox_to_anchor=(0.5, -0.04 - 0.012 * len(members_sorted)),
          ncol=2, fontsize=8, frameon=False)

fig.tight_layout()
path = os.path.join(args.outdir, 'fig12_cluster43_deepdive.png')
fig.savefig(path, dpi=150, bbox_inches='tight')
plt.close(fig)
print(f'  Saved: {path}')

print('\nAll figures done.')
