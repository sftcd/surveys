#!/usr/bin/env python3
"""
rc4_software_hygiene_figures.py

Figures for the software/deployment-model vs TLS Hygiene Index analysis
(rc4/software_hygiene/software_hygiene_summary.json).

Usage:
  source venv/bin/activate
  python3 rc4_software_hygiene_figures.py --indir rc4/software_hygiene --outdir rc4_hygiene_charts
"""

import argparse
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--indir', default='rc4/software_hygiene')
parser.add_argument('--outdir', default='rc4_hygiene_charts')
args = parser.parse_args()
os.makedirs(args.outdir, exist_ok=True)

with open(os.path.join(args.indir, 'software_hygiene_summary.json')) as f:
    summary = json.load(f)

RED = '#e74c3c'
BLUE = '#3498db'
GREY = '#bdc3c7'
GREEN = '#27ae60'
ORANGE = '#f39c12'


def clean(ax):
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def label_hbar(ax, bar, val, fmt=None, offset=0.02):
    s = fmt if fmt else str(val)
    ax.text(bar.get_width() + offset, bar.get_y() + bar.get_height() / 2, s,
            ha='left', va='center', fontsize=9, fontweight='bold')


def label_bar(ax, bar, val, fmt=None, offset=0.02):
    s = fmt if fmt else str(val)
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + offset, s,
            ha='center', va='bottom', fontsize=10, fontweight='bold')


def save(fig, name):
    path = os.path.join(args.outdir, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  Saved: {path}')


# ══════════════════════════════════════════════════════════════════════════
# Figure 6 — Mean hygiene score by mail server software
# ══════════════════════════════════════════════════════════════════════════
print('[6] Hygiene score by software...')

sw = sorted(summary['software_hygiene'], key=lambda x: x['mean_hygiene_score'], reverse=True)
names = [f"{s['name']} (n={s['n_hosts_with_tls']})" for s in sw][::-1]
scores = [s['mean_hygiene_score'] for s in sw][::-1]
colors = [RED if s['mean_hygiene_score'] >= 1.5 else (ORANGE if s['mean_hygiene_score'] >= 0.7 else GREEN)
          for s in sw][::-1]

fig, ax = plt.subplots(figsize=(9, 7))
bars = ax.barh(names, scores, color=colors, edgecolor='white')
for bar, v in zip(bars, scores):
    label_hbar(ax, bar, f'{v:.2f}', offset=0.03)
ax.set_xlabel('Mean TLS Hygiene Index score')
ax.set_title('Mean TLS Hygiene Index score by mail server software\n'
              '(identified via SMTP banner, n>=10 hosts with TLS)')
ax.set_xlim(0, max(scores) * 1.15)
clean(ax)
save(fig, 'fig6_software_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 7 — Mean hygiene score by deployment model
# ══════════════════════════════════════════════════════════════════════════
print('[7] Hygiene score by deployment model...')

dep = sorted(summary['deployment_hygiene'], key=lambda x: x['mean_hygiene_score'], reverse=True)
names = [f"{d['name']}\n(n={d['n_hosts_with_tls']})" for d in dep]
scores = [d['mean_hygiene_score'] for d in dep]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.bar(names, scores, color=BLUE, edgecolor='white', width=0.55)
for bar, v in zip(bars, scores):
    label_bar(ax, bar, v, fmt=f'{v:.2f}', offset=0.02)
ax.set_ylabel('Mean TLS Hygiene Index score')
ax.set_title('TLS hygiene by deployment model\n'
              'Managed cloud mail platforms vs self-managed infrastructure')
clean(ax)
save(fig, 'fig7_deployment_hygiene.png')


# ══════════════════════════════════════════════════════════════════════════
# Figure 8 — Exim EOL vs supported version hygiene
# ══════════════════════════════════════════════════════════════════════════
print('[8] Exim EOL vs supported...')

ex = summary['exim_version_analysis']
labels = [f"EOL Exim (<4.92)\nCVE-2019-10149\n(n={ex['n_eol']})",
          f"Supported Exim (>=4.92)\n(n={ex['n_supported']})"]
means = [ex['mean_score_eol'], ex['mean_score_supported']]

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(labels, means, color=[RED, GREY], edgecolor='white', width=0.45)
for bar, v in zip(bars, means):
    label_bar(ax, bar, v, fmt=f'{v:.2f}', offset=0.02)
ax.set_ylabel('Mean TLS Hygiene Index score')
ax.set_title('TLS hygiene of Exim deployments\nrunning end-of-life vs supported versions')
ax.set_ylim(0, max(means) * 1.3)
clean(ax)
save(fig, 'fig8_exim_eol_hygiene.png')

print('\nDone.')
