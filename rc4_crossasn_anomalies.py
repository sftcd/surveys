#!/usr/bin/python3

# RC4 Cross-ASN Cluster Anomaly Analysis
# Identifies anomalous RC4 servers within key-reuse clusters, with focus on
# cross-ASN cases and entities worth contacting for remediation follow-up.
#
# Anomalies found:
#   A1 — Cluster 43:  Cross-ASN key reuse (Blacknight+Iomart), 1 member uses RC4
#                     while 22 peers use modern TLS — single degraded outlier
#   A2 — Cluster 141: Mass RC4 deployment on Amazon (26/27 members), same key,
#                     suggests a shared AMI/image with RC4 baked in
#   A3 — Cluster 241: ECDHE+RC4 paradox at Digiweb — forward secrecy enabled
#                     but RC4 stream cipher never removed (cipher 49169)
#   A4 — Cluster 305: Port-selective RC4 — SMTP uses AES, IMAP uses RC4
#                     on a key shared with two fully-clean cluster peers
#
# Usage:
#   python3 rc4_crossasn_anomalies.py \
#       --results results/IE-20260317-171424 \
#       --rc4     rc4/rc4_analysis.json \
#       --outdir  rc4_charts

import json, os, glob, argparse, collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument('--results', default='results/IE-20260317-171424')
parser.add_argument('--rc4',     default='rc4/rc4_analysis.json')
parser.add_argument('--outdir',  default='rc4_charts')
args = parser.parse_args()

os.makedirs(args.outdir, exist_ok=True)

with open(args.rc4) as f:
    rc4_data = json.load(f)
rc4_ips = set(e['ip'] for e in rc4_data['rc4_ip_list'])

cluster_files = sorted(glob.glob(os.path.join(args.results, 'cluster*.json')))
all_clusters = {}
for cf in cluster_files:
    with open(cf) as f:
        members = json.load(f)
    for m in members:
        cnum = m['clusternum']
        if cnum not in all_clusters:
            all_clusters[cnum] = []
        all_clusters[cnum].append(m)

CIPHER_NAMES = {
    5:     'RC4-SHA\n(TLS_RSA_WITH_RC4_128_SHA)',
    49169: 'ECDHE-RC4\n(TLS_ECDHE_RSA_WITH_RC4_128_SHA)',
    49199: 'ECDHE-AES256-GCM\n(modern)',
    53:    'AES256-CBC-SHA\n(TLS_RSA_WITH_AES_256_CBC_SHA)',
    49195: 'ECDHE-ECDSA-AES128-GCM\n(modern)',
}
RC4_CIPHERS = {5, 49169}

chart_num = 16  # charts 1-16 already exist

def save(fig, name):
    global chart_num
    chart_num += 1
    path = os.path.join(args.outdir, f'{chart_num:02d}_{name}.png')
    fig.savefig(path, dpi=200, bbox_inches='tight')
    plt.close(fig)
    print(f"  [{chart_num:02d}] {path}")


# ══════════════════════════════════════════════════════════════════════════════
# Chart 17 — Overview: RC4 clusters and their anomaly types
# ══════════════════════════════════════════════════════════════════════════════
print("\n[17] RC4 cluster anomaly overview...")

rc4_cluster_nums = set()
for cnum, members in all_clusters.items():
    if any(m['ip'] in rc4_ips for m in members):
        rc4_cluster_nums.add(cnum)

# Classify each RC4-containing cluster
cluster_types = {
    'cross_asn_rc4': [],
    'mass_rc4': [],       # >50% members use RC4
    'paradox': [],        # ECDHE+RC4 cipher
    'port_selective': [], # RC4 on some ports, AES on others
    'standard': [],
}

for cnum in sorted(rc4_cluster_nums):
    members = all_clusters[cnum]
    rc4_members = [m for m in members if m['ip'] in rc4_ips]
    asns = set(m['asn'] for m in members)
    rc4_ratio = len(rc4_members) / len(members)

    # Check cipher types
    has_paradox = any(
        m['analysis'].get('p25', {}).get('cipher_suite') == 49169
        for m in rc4_members
    )
    # Port-selective: RC4 IP but p25 cipher is NOT RC4
    has_port_selective = any(
        m['analysis'].get('p25', {}).get('cipher_suite') not in RC4_CIPHERS
        and m['analysis'].get('p25', {}).get('cipher_suite') is not None
        for m in rc4_members
    )

    info = {
        'cnum': cnum,
        'size': len(members),
        'rc4_count': len(rc4_members),
        'rc4_ratio': rc4_ratio,
        'asns': asns,
        'asn_count': len(asns),
        'rc4_ips': [m['ip'] for m in rc4_members],
    }

    if len(asns) > 1:
        cluster_types['cross_asn_rc4'].append(info)
    elif has_paradox:
        cluster_types['paradox'].append(info)
    elif has_port_selective:
        cluster_types['port_selective'].append(info)
    elif rc4_ratio > 0.5:
        cluster_types['mass_rc4'].append(info)
    else:
        cluster_types['standard'].append(info)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle(
    'RC4 Servers Within Key-Reuse Clusters: Anomaly Classification\n'
    f'21 of 712 clusters contain at least one RC4 server — 4 distinct anomaly types identified',
    fontsize=12, fontweight='bold', y=1.01
)

# Left: stacked bar showing cluster composition per anomaly type
ax = axes[0]
type_labels = ['Cross-ASN\nRC4 outlier', 'Mass RC4\ndeployment', 'ECDHE+RC4\nparadox', 'Port-selective\nRC4', 'Other RC4\nclusters']
type_keys   = ['cross_asn_rc4', 'mass_rc4', 'paradox', 'port_selective', 'standard']
type_colors = ['#8e44ad', '#c0392b', '#e67e22', '#f39c12', '#95a5a6']

cluster_counts = [len(cluster_types[k]) for k in type_keys]
rc4_counts     = [sum(i['rc4_count'] for i in cluster_types[k]) for k in type_keys]
total_members  = [sum(i['size']      for i in cluster_types[k]) for k in type_keys]
non_rc4_counts = [t - r for t, r in zip(total_members, rc4_counts)]

x = np.arange(len(type_labels))
w = 0.4
b1 = ax.bar(x, rc4_counts, w, label='RC4 servers', color=type_colors, edgecolor='white')
b2 = ax.bar(x, non_rc4_counts, w, bottom=rc4_counts,
            label='Non-RC4 peers (same key)', color=[c+'44' for c in type_colors],
            edgecolor='white')

for i, (rc4c, nonc, n_clusters) in enumerate(zip(rc4_counts, non_rc4_counts, cluster_counts)):
    ax.text(i, rc4c + nonc + 0.5, f'{n_clusters} cluster{"s" if n_clusters!=1 else ""}',
            ha='center', fontsize=9, color=type_colors[i], fontweight='bold')

ax.set_xticks(x)
ax.set_xticklabels(type_labels, fontsize=9)
ax.set_ylabel('Number of Servers in Cluster(s)')
ax.set_title('RC4 Cluster Members by Anomaly Type\n(solid = RC4, faded = non-RC4 peers sharing same key)')
ax.legend(fontsize=9)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

# Right: risk matrix
ax2 = axes[1]
ax2.set_xlim(0, 3); ax2.set_ylim(0, 3)
ax2.set_xticks([0.5, 1.5, 2.5])
ax2.set_xticklabels(['Low', 'Medium', 'High'], fontsize=10)
ax2.set_yticks([0.5, 1.5, 2.5])
ax2.set_yticklabels(['Low', 'Medium', 'High'], fontsize=10)
ax2.set_xlabel('Remediation Urgency', fontsize=10)
ax2.set_ylabel('Cryptographic Risk', fontsize=10)
ax2.set_title('Anomaly Risk vs Remediation Urgency', fontsize=10)

# Background gradient
for row in range(3):
    for col in range(3):
        level = (row + col) / 4
        color = plt.cm.RdYlGn_r(0.2 + level * 0.6)
        ax2.add_patch(mpatches.Rectangle((col, row), 1, 1, facecolor=color, alpha=0.25, edgecolor='white', lw=2))

anomaly_positions = [
    ('A1: Cross-ASN\nRC4 outlier\n(Cluster 43)', 2.5, 2.5, '#8e44ad'),
    ('A2: Mass RC4\ndeployment\n(Cluster 141)', 1.5, 2.5, '#c0392b'),
    ('A3: ECDHE+RC4\nparadox\n(Cluster 241)', 2.3, 1.5, '#e67e22'),
    ('A4: Port-selective\nRC4\n(Cluster 305)', 1.5, 1.0, '#f39c12'),
]
for label, rx, ry, color in anomaly_positions:
    ax2.scatter(rx, ry, s=200, color=color, zorder=5, edgecolor='white', lw=2)
    ax2.text(rx + 0.08, ry, label, fontsize=8, color=color, fontweight='bold',
             va='center', zorder=5)

ax2.spines['top'].set_visible(False)
ax2.spines['right'].set_visible(False)

plt.tight_layout()
save(fig, 'rc4_cluster_anomaly_overview')


# ══════════════════════════════════════════════════════════════════════════════
# Chart 18 — Anomaly A1: Cluster 43 cross-ASN RC4 outlier (deep dive)
# ══════════════════════════════════════════════════════════════════════════════
print("\n[18] Anomaly A1 — Cluster 43 cross-ASN deep dive...")

c43 = all_clusters[43]

fig, axes = plt.subplots(1, 2, figsize=(14, 7))
fig.suptitle(
    'Anomaly A1: Cross-ASN Key Reuse with RC4 Outlier — Cluster 43\n'
    '23 servers across 2 ASNs share one TLS private key; 1 server uses RC4 while 22 use modern TLS',
    fontsize=12, fontweight='bold', y=1.02
)

# Left: per-member cipher breakdown
ax = axes[0]
iomart = [m for m in c43 if 'Iomart' in m['asn']]
blacknight = [m for m in c43 if 'Blacknight' in m['asn']]
rc4_member = next(m for m in c43 if m['ip'] in rc4_ips)

# Show cipher distribution
cipher_groups = collections.Counter()
for m in c43:
    c = m['analysis'].get('p25', {}).get('cipher_suite')
    if c:
        cipher_groups[c] += 1

labels = [CIPHER_NAMES.get(c, str(c)) for c in cipher_groups]
counts = list(cipher_groups.values())
colors_pie = ['#e74c3c' if c in RC4_CIPHERS else '#27ae60' for c in cipher_groups]

wedges, texts, autotexts = ax.pie(
    counts, labels=labels, colors=colors_pie,
    autopct='%1.0f%%', startangle=90,
    wedgeprops=dict(edgecolor='white', linewidth=2)
)
for at in autotexts:
    at.set_fontsize(11)
    at.set_fontweight('bold')

ax.set_title(f'Cipher Suite Distribution in Cluster 43\n(n=23 servers, {len(iomart)} Iomart + {len(blacknight)} Blacknight)',
             fontsize=10)

red_patch = mpatches.Patch(color='#e74c3c', label='RC4 cipher (broken)')
green_patch = mpatches.Patch(color='#27ae60', label='Modern cipher (safe)')
ax.legend(handles=[red_patch, green_patch], loc='lower left', fontsize=9)

# Right: network diagram of cluster 43
ax2 = axes[1]
ax2.set_xlim(-1.5, 1.5); ax2.set_ylim(-1.5, 1.5)
ax2.set_aspect('equal')
ax2.axis('off')
ax2.set_title('Cluster 43: Shared Key Network\n(all nodes share the same TLS private key)',
              fontsize=10)

# Central key node
key_circle = plt.Circle((0, 0), 0.18, color='#f39c12', alpha=0.9, zorder=3)
ax2.add_patch(key_circle)
ax2.text(0, 0, 'Shared\nPrivate\nKey', ha='center', va='center',
         fontsize=8, fontweight='bold', color='white', zorder=4)

# Place Blacknight servers in an arc on the left
import math
bk_non_rc4 = [m for m in blacknight if m['ip'] not in rc4_ips]
n_bk = len(bk_non_rc4)

for i, m in enumerate(bk_non_rc4):
    angle = math.pi * 0.1 + (math.pi * 0.8 * i / max(n_bk - 1, 1))
    r = 1.1
    x_pos = -r * math.cos(angle * 0.5)
    y_pos = r * math.sin(angle) - 0.3
    ax2.plot([0, x_pos], [0, y_pos], color='#27ae60', lw=0.8, alpha=0.5, zorder=1)
    c = plt.Circle((x_pos, y_pos), 0.07, color='#27ae60', alpha=0.8, zorder=3)
    ax2.add_patch(c)

# Blacknight RC4 server — highlighted red
rc4_x, rc4_y = -1.1, -0.8
ax2.plot([0, rc4_x], [0, rc4_y], color='#e74c3c', lw=2.5, zorder=2)
rc4_circ = plt.Circle((rc4_x, rc4_y), 0.11, color='#e74c3c', alpha=1.0, zorder=4,
                       edgecolor='#922b21', linewidth=2)
ax2.add_patch(rc4_circ)
ax2.text(rc4_x, rc4_y, 'RC4\n!', ha='center', va='center',
         fontsize=9, fontweight='bold', color='white', zorder=5)
ax2.text(rc4_x - 0.15, rc4_y - 0.22,
         f'46.22.131.131\n(Blacknight)\nCipher: RC4-SHA',
         ha='center', fontsize=7.5, color='#c0392b', fontweight='bold')

# Iomart servers on the right
for i, m in enumerate(iomart):
    angle = -math.pi * 0.3 + (math.pi * 0.6 * i / max(len(iomart) - 1, 1))
    r = 1.15
    x_pos = r * math.cos(angle * 0.4)
    y_pos = r * math.sin(angle)
    ax2.plot([0, x_pos], [0, y_pos], color='#3498db', lw=0.8, alpha=0.6, zorder=1)
    c = plt.Circle((x_pos, y_pos), 0.07, color='#3498db', alpha=0.8, zorder=3)
    ax2.add_patch(c)

ax2.text(-0.6, 1.3, 'Blacknight\n(20 servers)', ha='center', fontsize=9,
         color='#27ae60', fontweight='bold')
ax2.text(-0.6, 1.1, '19 use modern TLS', ha='center', fontsize=8, color='#27ae60')
ax2.text(1.0, 0.4, 'Iomart\n(3 servers)', ha='center', fontsize=9,
         color='#3498db', fontweight='bold')
ax2.text(1.0, 0.2, '3 use modern TLS', ha='center', fontsize=8, color='#3498db')

ax2.text(0, -1.45,
         '⚠ The RC4 server shares its private key with 22 other servers across 2 ISPs.\n'
         'A successful RC4 attack on this one server could expose all 23 servers.',
         ha='center', fontsize=9, color='#922b21', fontweight='bold',
         bbox=dict(boxstyle='round,pad=0.4', facecolor='#fdedec', edgecolor='#e74c3c'))

plt.tight_layout()
save(fig, 'rc4_anomaly_A1_cross_asn_cluster43')


# ══════════════════════════════════════════════════════════════════════════════
# Chart 19 — Anomalies A2, A3, A4 side by side
# ══════════════════════════════════════════════════════════════════════════════
print("\n[19] Anomalies A2/A3/A4 combined panel...")

fig, axes = plt.subplots(1, 3, figsize=(16, 6))
fig.suptitle(
    'RC4 Cluster Anomalies A2, A3, A4 — Three Additional Patterns Requiring Remediation',
    fontsize=12, fontweight='bold', y=1.01
)

# ── A2: Cluster 141 — Mass RC4 deployment ─────────────────────────────────
ax = axes[0]
c141 = all_clusters[141]
rc4_c141 = sum(1 for m in c141 if m['ip'] in rc4_ips)
non_rc4_c141 = len(c141) - rc4_c141

ax.pie([rc4_c141, non_rc4_c141],
       labels=[f'RC4 servers\n(n={rc4_c141})', f'Non-RC4\n(n={non_rc4_c141})'],
       colors=['#e74c3c', '#27ae60'],
       autopct='%1.0f%%', startangle=90,
       wedgeprops=dict(edgecolor='white', lw=2))
ax.set_title('A2: Cluster 141 — Mass RC4 Deployment\n'
             '27 Amazon servers, same key, 26/27 use RC4\n'
             '→ Shared AMI/image with RC4 baked in\n'
             '→ Contact: Amazon customer (bulk fixer)',
             fontsize=9)

# ── A3: Cluster 241 — ECDHE+RC4 paradox ──────────────────────────────────
ax2 = axes[1]
paradox_data = [
    ('Forward\nSecrecy\n(ECDHE)\n✓ present', 1, '#27ae60'),
    ('Stream\nCipher\n(RC4)\n✗ broken', 1, '#e74c3c'),
]
labels_p = [d[0] for d in paradox_data]
sizes_p  = [d[1] for d in paradox_data]
colors_p = [d[2] for d in paradox_data]

wedges, texts = ax2.pie(sizes_p, labels=labels_p, colors=colors_p,
                        startangle=90, wedgeprops=dict(edgecolor='white', lw=2))
for t in texts:
    t.set_fontsize(10)

ax2.set_title('A3: Cluster 241 — ECDHE+RC4 Paradox\n'
              '2 Digiweb servers (84.203.136.181, .182)\n'
              'Cipher 49169: forward secrecy ON, RC4 ON\n'
              '→ Someone hardened TLS but forgot RC4\n'
              '→ Contact: Digiweb (deliberate misconfiguration)',
              fontsize=9)

# ── A4: Cluster 305 — Port-selective RC4 ─────────────────────────────────
ax3 = axes[2]
ports  = ['P25\nSMTP', 'P143\nIMAP']
ciphers = ['AES-256-CBC\n(secure)', 'RC4-SHA\n(broken)']
bar_colors = ['#27ae60', '#e74c3c']

bars = ax3.bar(ports, [1, 1], color=bar_colors, edgecolor='white', width=0.4)
ax3.set_ylim(0, 1.8)
ax3.set_yticks([])
ax3.text(0, 1.1, ciphers[0], ha='center', fontsize=10, color='#27ae60', fontweight='bold')
ax3.text(1, 1.1, ciphers[1], ha='center', fontsize=10, color='#e74c3c', fontweight='bold')
ax3.text(0.5, 1.55,
         'Same server (52.50.47.206)',
         ha='center', fontsize=9, color='#2c3e50', fontweight='bold')
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)
ax3.spines['left'].set_visible(False)
ax3.set_title('A4: Cluster 305 — Port-Selective RC4\n'
              '52.50.47.206 (Amazon): p25=AES, p143=RC4\n'
              'SMTP was fixed; IMAP was left broken\n'
              'Peers in cluster use modern TLS on all ports\n'
              '→ Contact: Amazon customer (partial fix)',
              fontsize=9)

plt.tight_layout()
save(fig, 'rc4_anomalies_A2_A3_A4')


# ══════════════════════════════════════════════════════════════════════════════
# Print contact/remediation summary
# ══════════════════════════════════════════════════════════════════════════════
print()
print('=' * 65)
print('ENTITIES TO CONTACT (for dissertation remediation section)')
print('=' * 65)
print()
print('A1 — Blacknight Internet Solutions Limited')
print('     IP:      46.22.131.131')
print('     Issue:   Only RC4 server in a 23-member cross-ASN cluster')
print('              sharing a private key with Iomart servers')
print('     Risk:    RC4 attack exposes key used by 22 additional servers')
print('     Contact: https://www.blacknight.com  / abuse@blacknight.com')
print()
print('A2 — Amazon customer (bulk deployment)')
print('     Cluster: 141 (26 RC4 servers sharing one key)')
print('     Issue:   EC2 AMI or SES template with RC4 hardcoded')
print('     Contact: AWS Trust & Safety — report the cluster of IPs')
print()
print('A3 — Digiweb ltd')
print('     IPs:     84.203.136.181, 84.203.136.182')
print('     Issue:   ECDHE+RC4 paradox — partial hardening, RC4 not removed')
print('     Contact: https://www.digiweb.ie  / support@digiweb.ie')
print()
print('A4 — Amazon customer (partial fix)')
print('     IP:      52.50.47.206')
print('     Issue:   SMTP fixed, IMAP left with RC4')
print('     Contact: AWS Trust & Safety')
