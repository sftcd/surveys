#!/usr/bin/env python3
"""
rc4_hygiene_advanced_figures.py

Figures for the data-driven weighting (logistic regression) and ASN
typology (k-means) extensions to the TLS Hygiene Index
(rc4/hygiene_advanced/hygiene_advanced.json).

Usage:
  source venv/bin/activate
  python3 rc4_hygiene_advanced_figures.py --indir rc4/hygiene_advanced --outdir rc4_hygiene_charts
"""

import argparse
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--indir', default='rc4/hygiene_advanced')
parser.add_argument('--outdir', default='rc4_hygiene_charts')
args = parser.parse_args()
os.makedirs(args.outdir, exist_ok=True)

with open(os.path.join(args.indir, 'hygiene_advanced.json')) as f:
    data = json.load(f)

RED = '#e74c3c'
BLUE = '#3498db'
GREY = '#bdc3c7'
GREEN = '#27ae60'

LABELS = {
    'rc4': 'RC4 cipher\nin use',
    'legacy_tls': 'Legacy TLS\n(<=1.1)',
    'expired_cert': 'Expired\ncertificate',
    'self_signed': 'Self-signed\ncertificate',
    'no_fwd_secrecy': 'No forward\nsecrecy',
    'untrusted_chain': 'Untrusted\ncert chain',
}
ALL_INDICATORS = ['rc4', 'legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']
INDICATORS = ['legacy_tls', 'expired_cert', 'self_signed', 'no_fwd_secrecy', 'untrusted_chain']


def clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def save(fig, name):
    path = os.path.join(args.outdir, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


# ══════════════════════════════════════════════════════════════════════════
# Figure 9 — Data-driven indicator weighting (logistic regression)
# ══════════════════════════════════════════════════════════════════════════
print('[9] Logistic regression weighting...')

w = data['weighting']['logistic_regression']
order = sorted(INDICATORS, key=lambda k: w['odds_ratios'][k], reverse=True)
odds = [w['odds_ratios'][k] for k in order]
labels = [LABELS[k] for k in order]
colors = [RED if o > 1 else BLUE for o in odds]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
fig.subplots_adjust(wspace=0.35)
fig.suptitle('Data-driven indicator weighting via logistic regression\n'
              '(predicting RC4 presence from the other 5 hygiene indicators)',
              fontsize=13, fontweight='bold', y=1.04)

bars = ax1.bar(labels, odds, color=colors, edgecolor='white')
ax1.axhline(1.0, color='black', linewidth=1, linestyle='--')
ax1.set_yscale('log')
for bar, o in zip(bars, odds):
    ax1.text(bar.get_x() + bar.get_width()/2, o * 1.15, f'{o:.2f}',
             ha='center', fontsize=10, fontweight='bold')
ax1.set_ylabel('Odds ratio for RC4 presence (log scale)')
ax1.set_title('Odds ratio per indicator\n(>1 = co-occurs more with RC4, <1 = less)')
clean(ax1)

# Right: weighted vs naive score comparison
comp = data['weighting']['weighted_score_comparison']
naive = comp['naive_equal_weight_for_reference']
groups = ['Naive\n(equal weight, 0-5)', 'Data-driven\n(logistic-weighted)']
rc4_vals = [naive['rc4_mean'], comp['rc4_mean_weighted_score']]
non_rc4_vals = [naive['non_rc4_mean'], comp['non_rc4_mean_weighted_score']]

x = np.arange(len(groups))
wbar = 0.35
b1 = ax2.bar(x - wbar/2, non_rc4_vals, wbar, label='Non-RC4 hosts', color=GREY, edgecolor='white')
b2 = ax2.bar(x + wbar/2, rc4_vals, wbar, label='RC4 hosts', color=RED, edgecolor='white')
for bar, v in zip(list(b1) + list(b2), non_rc4_vals + rc4_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.03, f'{v:.2f}',
             ha='center', fontsize=10, fontweight='bold')
ax2.set_xticks(x)
ax2.set_xticklabels(groups)
ax2.set_ylabel('Mean "other neglect" score')
ax2.set_title('Naive vs data-driven scoring:\nseparation between RC4 and non-RC4 hosts')
ax2.legend()
clean(ax2)

save(fig, 'fig9_logistic_weighting.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 10 — ASN typology (k-means cluster heatmap)
# ══════════════════════════════════════════════════════════════════════════
print('[10] ASN typology heatmap...')

typ = data['asn_typology']
clusters = typ['clusters']

matrix = np.array([[c['mean_rates'][k] for k in ALL_INDICATORS] for c in clusters])
row_labels = [f"Cluster {c['cluster_id']}\n({c['n_asns']} ASNs)\ne.g. {c['members'][0]['org']}" for c in clusters]
col_labels = [LABELS[k] for k in ALL_INDICATORS]

fig, ax = plt.subplots(figsize=(10, 1.2 * len(clusters) + 2))
im = ax.imshow(matrix, cmap='Reds', vmin=0, vmax=1, aspect='auto')

ax.set_xticks(range(len(col_labels)))
ax.set_xticklabels(col_labels, fontsize=9)
ax.set_yticks(range(len(row_labels)))
ax.set_yticklabels(row_labels, fontsize=9)

for i in range(matrix.shape[0]):
    for j in range(matrix.shape[1]):
        val = matrix[i, j]
        ax.text(j, i, f'{val:.0%}', ha='center', va='center',
                color='white' if val > 0.5 else 'black', fontsize=10, fontweight='bold')

ax.set_title(f'ASN typology via k-means clustering (k={typ["k"]})\n'
              f'Mean indicator prevalence per cluster, {typ["n_asns_clustered"]} ASNs '
              f'with >={typ["min_hosts_threshold"]} scanned hosts')
fig.colorbar(im, ax=ax, label='Mean prevalence within cluster', shrink=0.8)

save(fig, 'fig10_asn_typology_heatmap.png')

print('\nDone.')
