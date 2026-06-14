#!/usr/bin/env python3
"""
rc4_hygiene_figures.py

Figures for the TLS Hygiene Index analysis (built on top of
rc4_hygiene_index.py outputs in rc4/hygiene/).

Usage:
  source venv/bin/activate
  python3 rc4_hygiene_figures.py --indir rc4/hygiene --outdir rc4_hygiene_charts
"""

import argparse
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--indir', default='rc4/hygiene')
parser.add_argument('--outdir', default='rc4_hygiene_charts')
args = parser.parse_args()
os.makedirs(args.outdir, exist_ok=True)

with open(os.path.join(args.indir, 'hygiene_summary.json')) as f:
    summary = json.load(f)
with open(os.path.join(args.indir, 'cluster_hygiene.json')) as f:
    clusters = json.load(f)

RED = '#e74c3c'
BLUE = '#3498db'
GREY = '#bdc3c7'
GREEN = '#27ae60'


def clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def label_bar(ax, bar, val, fmt=None, offset=0.02, va='bottom'):
    s = fmt if fmt else str(val)
    y = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, y + offset, s,
            ha='center', va=va, fontsize=10, fontweight='bold')


def label_hbar(ax, bar, val, fmt=None, offset=0.02):
    s = fmt if fmt else str(val)
    ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2, s,
            ha='left', va='center', fontsize=9, fontweight='bold')


def save(fig, name):
    path = os.path.join(args.outdir, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


# ══════════════════════════════════════════════════════════════════════════
# Figure 1 — Population score distribution
# ══════════════════════════════════════════════════════════════════════════
print('[1] Hygiene score distribution...')

score_dist = {int(k): v for k, v in summary['score_distribution'].items()}
scores = sorted(score_dist)
counts = [score_dist[s] for s in scores]
total = sum(counts)

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(scores, counts, color=BLUE, edgecolor='white', width=0.6)
for bar, c in zip(bars, counts):
    label_bar(ax, bar, c, fmt=f'{c}\n({c/total:.1%})', offset=total * 0.005)

ax.set_xlabel('TLS Hygiene Index score (0 = clean, 6 = all indicators present)')
ax.set_ylabel('Number of hosts')
ax.set_title(f'Distribution of TLS Hygiene Index scores\n'
              f'across {total:,} hosts with a usable TLS handshake')
ax.set_xticks(scores)
clean(ax)
save(fig, 'fig1_score_distribution.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 2 — RC4 hosts vs population (validation of the index)
# ══════════════════════════════════════════════════════════════════════════
print('[2] RC4 vs population...')

rc4 = summary['rc4']
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle('RC4 hosts show systematically worse TLS hygiene\n'
              'than the rest of the scanned population',
              fontsize=13, fontweight='bold', y=1.03)

# Left: mean "other neglect" score (excludes the RC4 flag itself)
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
             transform=ax1.transAxes, ha='center', va='top', fontsize=10,
             style='italic')
clean(ax1)

# Right: distribution comparison (normalised) for scores 0-5 (other-neglect, 0-5 scale)
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


# ══════════════════════════════════════════════════════════════════════════
# Figure 3 — Indicator prevalence across population
# ══════════════════════════════════════════════════════════════════════════
print('[3] Indicator prevalence...')

LABELS = {
    'untrusted_chain': 'Untrusted\ncertificate chain',
    'self_signed': 'Self-signed\ncertificate',
    'expired_cert': 'Expired\ncertificate',
    'no_fwd_secrecy': 'No forward\nsecrecy',
    'rc4': 'RC4 cipher\nin use',
    'legacy_tls': 'Legacy TLS\n(<=1.1)',
}
order = ['untrusted_chain', 'self_signed', 'expired_cert', 'no_fwd_secrecy', 'rc4', 'legacy_tls']
rates = [summary['flag_rates'].get(k, 0) for k in order]
labels = [LABELS[k] for k in order]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(labels, [r * 100 for r in rates], color=BLUE, edgecolor='white')
for bar, r in zip(bars, rates):
    label_bar(ax, bar, r, fmt=f'{r:.1%}', offset=0.5)
ax.set_ylabel('Percentage of TLS hosts (%)')
ax.set_title(f'Prevalence of TLS Hygiene Index indicators\n'
              f'across {total:,} hosts with a usable TLS handshake')
clean(ax)
save(fig, 'fig3_indicator_prevalence.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 4 — ASN ranking: best vs worst hygiene
# ══════════════════════════════════════════════════════════════════════════
print('[4] ASN ranking...')

worst = summary['asn_top20_worst'][:10]
best = summary['asn_top20_best'][:10]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
fig.subplots_adjust(wspace=0.6)
fig.suptitle('ASN/provider ranking by mean TLS Hygiene Index score\n'
              '(providers with >=5 scanned hosts)',
              fontsize=13, fontweight='bold', y=1.02)

for ax, data, color, title in [
    (ax1, worst, RED, 'Worst 10 providers'),
    (ax2, best, GREEN, 'Best 10 providers'),
]:
    orgs = [f"{d['org']} (n={d['n_hosts']})" for d in data][::-1]
    means = [d['mean_score'] for d in data][::-1]
    bars = ax.barh(orgs, means, color=color, edgecolor='white')
    for bar, v in zip(bars, means):
        label_hbar(ax, bar, f'{v:.2f}', offset=0.03)
    ax.set_xlabel('Mean TLS Hygiene Index score')
    ax.set_title(title)
    ax.set_xlim(0, max(max(worst, key=lambda d: d['mean_score'])['mean_score'], 1) * 1.25)
    clean(ax)

save(fig, 'fig4_asn_ranking.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 5 — Key-reuse cluster hygiene vs cluster size
# ══════════════════════════════════════════════════════════════════════════
print('[5] Cluster hygiene vs size...')

big = [c for c in clusters if c['csize'] >= 5]
small = [c for c in clusters if c['csize'] < 5]
big_mean = sum(c['mean_score'] for c in big) / len(big)
small_mean = sum(c['mean_score'] for c in small) / len(small)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle('Key-reuse clusters and TLS hygiene', fontsize=13, fontweight='bold', y=1.02)

# Left: scatter
sizes = [c['csize'] for c in clusters]
means = [c['mean_score'] for c in clusters]
ax1.scatter(sizes, means, alpha=0.4, color=BLUE, edgecolor='none', s=25)
ax1.set_xscale('log')
ax1.set_xlabel('Cluster size (hosts sharing a key, log scale)')
ax1.set_ylabel('Mean TLS Hygiene Index score of cluster members')
ax1.set_title('Cluster size vs mean hygiene score\n(each point = one key-reuse cluster)')
clean(ax1)

# Right: small vs large cluster mean
labels = [f'Small clusters\n(<5 members, n={len(small)})',
          f'Large clusters\n(>=5 members, n={len(big)})']
bars = ax2.bar(labels, [small_mean, big_mean], color=[GREY, BLUE], edgecolor='white', width=0.5)
for bar, v in zip(bars, [small_mean, big_mean]):
    label_bar(ax2, bar, v, fmt=f'{v:.2f}', offset=0.01)
ax2.set_ylabel('Mean TLS Hygiene Index score')
ax2.set_title('Large key-reuse clusters skew toward\nworse TLS hygiene')
clean(ax2)

save(fig, 'fig5_cluster_hygiene.png')

print('\nDone.')
