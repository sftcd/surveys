#!/usr/bin/env python3
"""
rc4_cluster43_deepdive.py

Deep-dive figure for Cluster 43 — the single Priority-1 cross-ASN
key-reuse anomaly identified in rc4/anomaly_report/.

23 hosts (mostly Blacknight Internet Solutions, plus 3 Iomart Cloud
Services / bluemonkeyweb.co.uk hosts) all share the same TLS private
key/certificate fingerprint on their mail ports (p25/p110/p143/p993).
One host — 46.22.131.131 (131-131.colo.sta.blacknight.ie) — is the
only member negotiating RC4 on those ports, and also has the worst
TLS Hygiene Index score (6/6) in the cluster.

This figure shows the negotiated cipher "family" per mail port for
every cluster member, making the anomalous host visually obvious:
every other host negotiates an ECDHE (forward-secrecy) cipher on
p25/p110/p143/p993, while this one host negotiates RC4 (no forward
secrecy, broken cipher) despite sharing the same certificate/key as
its siblings.

Inputs:
  - results/IE-20260317-171424/cluster43.json
  - rc4/hygiene/host_scores.json

Usage:
  source venv/bin/activate
  python3 rc4_cluster43_deepdive.py --outdir rc4_hygiene_charts
"""

import argparse
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--cluster', default='results/IE-20260317-171424/cluster43.json')
parser.add_argument('--hygiene', default='rc4/hygiene/host_scores.json')
parser.add_argument('--outdir', default='rc4_hygiene_charts')
args = parser.parse_args()
os.makedirs(args.outdir, exist_ok=True)

with open(args.cluster) as f:
    members = json.load(f)
with open(args.hygiene) as f:
    hyg = json.load(f)

PORTS = ['p25', 'p110', 'p143', 'p443', 'p587', 'p993']

# Cipher suite ID -> (short label, category code)
# category: 0 = none/no service, 1 = RC4 (broken, no FS), 2 = AES-CBC RSA (no FS),
#           3 = ECDHE-CBC (FS), 4 = ECDHE-GCM (FS, best)
CIPHER_INFO = {
    None: ('-', 0),
    5: ('RC4', 1),
    53: ('AES256-CBC\n(RSA)', 2),
    47: ('AES128-CBC\n(RSA)', 2),
    49171: ('ECDHE-AES128\nCBC', 3),
    49172: ('ECDHE-AES256\nCBC', 3),
    49199: ('ECDHE-AES128\nGCM', 4),
}

CAT_COLORS = {
    0: '#f5f5f5',   # no service - light grey
    1: '#e74c3c',   # RC4 - red
    2: '#f39c12',   # AES-CBC, no FS - orange
    3: '#85c1e9',   # ECDHE-CBC - light blue
    4: '#3498db',   # ECDHE-GCM - blue
}
CAT_LABELS = {
    0: 'No TLS on this port',
    1: 'RC4 (broken cipher, no forward secrecy)',
    2: 'AES-CBC / RSA key exchange (no forward secrecy)',
    3: 'ECDHE + AES-CBC (forward secrecy)',
    4: 'ECDHE + AES-GCM (forward secrecy, modern)',
}

# Sort: anomalous host first, then by ASN, then IP
RC4_IP = '46.22.131.131'


def sort_key(m):
    return (m['ip'] != RC4_IP, m['asn'], m['ip'])


members_sorted = sorted(members, key=sort_key)

cat_matrix = np.zeros((len(members_sorted), len(PORTS)), dtype=int)
text_matrix = []
row_labels = []

for i, m in enumerate(members_sorted):
    a = m['analysis']
    row_text = []
    for j, p in enumerate(PORTS):
        cipher = a.get(p, {}).get('cipher_suite')
        label, cat = CIPHER_INFO.get(cipher, (f'#{cipher}', 1))
        cat_matrix[i, j] = cat
        row_text.append(label)
    text_matrix.append(row_text)

    score = hyg.get(m['ip'], {}).get('score')
    score_str = str(score) if score is not None else '-'
    short_asn = 'Blacknight' if 'Blacknight' in m['asn'] else 'Iomart/bluemonkeyweb'
    flag = '  <-- RC4 OUTLIER' if m['ip'] == RC4_IP else ''
    row_labels.append(f"{m['ip']}  ({short_asn}, hygiene={score_str}){flag}")

# Build colormap from category codes
cmap = mcolors.ListedColormap([CAT_COLORS[c] for c in range(5)])
bounds = [-0.5, 0.5, 1.5, 2.5, 3.5, 4.5]
norm = mcolors.BoundaryNorm(bounds, cmap.N)

fig, ax = plt.subplots(figsize=(10, 0.45 * len(members_sorted) + 2))
im = ax.imshow(cat_matrix, cmap=cmap, norm=norm, aspect='auto')

ax.set_xticks(range(len(PORTS)))
ax.set_xticklabels([p.replace('p', 'Port ') for p in PORTS], fontsize=10)
ax.set_yticks(range(len(members_sorted)))
ax.set_yticklabels(row_labels, fontsize=8)

for i in range(cat_matrix.shape[0]):
    for j in range(cat_matrix.shape[1]):
        ax.text(j, i, text_matrix[i][j], ha='center', va='center', fontsize=6.5)

# Highlight the anomalous row with a bright box
ax.add_patch(plt.Rectangle((-0.5, -0.5), len(PORTS), 1, fill=False,
                            edgecolor='lime', linewidth=3.5, zorder=5))

ax.set_title(
    'Cluster 43 — cross-ASN key-reuse cluster (23 hosts share the same TLS certificate)\n'
    'Negotiated cipher per mail port — one host (top row) is the only member using RC4',
    fontsize=11, fontweight='bold')

# Legend
handles = [plt.Rectangle((0, 0), 1, 1, color=CAT_COLORS[c]) for c in range(5)]
ax.legend(handles, [CAT_LABELS[c] for c in range(5)],
          loc='upper center', bbox_to_anchor=(0.5, -0.04 - 0.012 * len(members_sorted)),
          ncol=2, fontsize=8, frameon=False)

fig.tight_layout()
path = os.path.join(args.outdir, 'fig12_cluster43_deepdive.png')
fig.savefig(path, dpi=150, bbox_inches='tight')
plt.close(fig)
print(f'Saved: {path}')
