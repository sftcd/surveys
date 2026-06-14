#!/usr/bin/env python3
"""
rc4_anomaly_report_figures.py

Figure for the RC4 remediation outreach report
(rc4/anomaly_report/rc4_anomaly_report.json).

Shows the total number of RC4 hosts attributable to each ASN/provider,
split into "in key-reuse cluster" vs "isolated", so the highest-impact
outreach targets are visually obvious.

Usage:
  source venv/bin/activate
  python3 rc4_anomaly_report_figures.py --indir rc4/anomaly_report --outdir rc4_hygiene_charts
"""

import argparse
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser()
parser.add_argument('--indir', default='rc4/anomaly_report')
parser.add_argument('--outdir', default='rc4_hygiene_charts')
args = parser.parse_args()
os.makedirs(args.outdir, exist_ok=True)

with open(os.path.join(args.indir, 'rc4_anomaly_report.json')) as f:
    data = json.load(f)

RED = '#e74c3c'
BLUE = '#3498db'


def clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def save(fig, name):
    path = os.path.join(args.outdir, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


# ══════════════════════════════════════════════════════════════════════════
# Figure 11 — RC4 hosts by ASN/provider (clustered vs isolated)
# ══════════════════════════════════════════════════════════════════════════
print('[11] RC4 hosts by provider...')

clustered = defaultdict(int)
for c in data['cluster_reports']:
    for m in c['members']:
        if m['is_rc4']:
            clustered[m['asn']] += 1

isolated = {grp['asn']: grp['n_hosts'] for grp in data['isolated_rc4_by_asn']}

providers = set(clustered) | set(isolated)
totals = {p: clustered.get(p, 0) + isolated.get(p, 0) for p in providers}
ordered = sorted(providers, key=lambda p: totals[p], reverse=True)

names = ordered[::-1]
clustered_vals = [clustered.get(p, 0) for p in names]
isolated_vals = [isolated.get(p, 0) for p in names]

fig, ax = plt.subplots(figsize=(9, 0.4 * len(names) + 2))
b1 = ax.barh(names, clustered_vals, color=RED, edgecolor='white', label='In key-reuse cluster')
b2 = ax.barh(names, isolated_vals, left=clustered_vals, color=BLUE, edgecolor='white', label='Isolated')

for i, p in enumerate(names):
    total = totals[p]
    ax.text(total + 0.5, i, str(total), va='center', fontsize=9, fontweight='bold')

ax.set_xlabel('Number of RC4 hosts')
ax.set_title('RC4 hosts by ASN/provider\n(remediation outreach priority — split by key-reuse status)')
ax.legend()
clean(ax)
save(fig, 'fig11_rc4_by_provider.png')

print('\nDone.')
