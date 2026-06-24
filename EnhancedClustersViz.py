#!/usr/bin/env python3
"""
EnhanceGraphs.py
Post-processes DOT files from ReportReuse.py with analytics overlays.

Usage:
    python3 EnhanceGraphs.py -i results/IE-20260317-171424/ -o enhanced_graphs/
    python3 EnhanceGraphs.py -i results/IE-20260317-171424/ -o enhanced_graphs/ --clusters 19 70 477 716
    python3 EnhanceGraphs.py -i results/IE-20260317-171424/ -o enhanced_graphs/ --summary
"""

import argparse, os, re, sys, time
from collections import Counter, defaultdict
import networkx as nx

try:
    import graphviz as gv
except ImportError:
    print("ERROR: pip install graphviz", file=sys.stderr); sys.exit(1)

def log(msg):
    print(msg, file=sys.stderr, flush=True)


# =============================================================================
# Parse DOT file (matches ReportReuse.py output format)
# =============================================================================
def parse_dot(dot_path):
    """
    Parse ReportReuse.py DOT format:
        8754 [color="#00407D" style=filled]
        8754 -- 8755 [color=orange]
    """
    G = nx.Graph()

    with open(dot_path, 'r') as f:
        content = f.read()

    # Nodes: ID [color="..." style=filled] or ID [color=name style=filled]
    # Handles both quoted hex (#00407D) and unquoted named colors (blue)
    node_pat = re.compile(
        r'^\s+(\S+)\s+\[color="?([^"\]\s]+)"?\s+style=filled\]',
        re.MULTILINE
    )
    for m in node_pat.finditer(content):
        node_id = m.group(1).strip('"')
        color = m.group(2)
        G.add_node(node_id, color=color)

    # Edges: ID -- ID [color=xxx]
    edge_pat = re.compile(
        r'^\s+(\S+)\s+--\s+(\S+)\s+\[color="?([^"\]\s]+)"?\]',
        re.MULTILINE
    )
    for m in edge_pat.finditer(content):
        u = m.group(1).strip('"')
        v = m.group(2).strip('"')
        color = m.group(3)
        G.add_edge(u, v, color=color)
        if u not in G.nodes(): G.add_node(u, color='gray')
        if v not in G.nodes(): G.add_node(v, color='gray')

    # Extract legend labels (port-pair names)
    # Pattern: "p443-p443" [label="p443-p443" color=orange]
    legend_pat = re.compile(r'"([^"]+)"\s+\[label="([^"]+)"\s+color="?([^"\]\s]+)"?\]')
    legend = {}
    for m in legend_pat.finditer(content):
        label = m.group(2)
        color = m.group(3)
        legend[color] = label

    # Also check for simplified labels like "mail", "web", "ssh"
    simple_pat = re.compile(r'"(mail|web|ssh)"\s+\[label="(mail|web|ssh)"\s+color="?([^"\]\s]+)"?\]')
    for m in simple_pat.finditer(content):
        label = m.group(2)
        color = m.group(3)
        legend[color] = label

    return G, legend


def extract_cluster_num(filename):
    m = re.search(r'graph(\d+)', filename)
    return int(m.group(1)) if m else -1


# =============================================================================
# Analytics
# =============================================================================
def compute_analytics(G):
    n = len(G.nodes()); e = len(G.edges())
    if n < 2:
        return {'nodes': n, 'edges': e, 'density': 0, 'avg_degree': 0,
                'clustering': 0, 'components': 1, 'hub': None, 'hub_degree': 0,
                'bridges': [], 'degrees': {}, 'cross_asn': 0, 'cross_pct': 0}

    degrees = dict(G.degree())
    hub = max(degrees, key=degrees.get)

    bridges = []
    if n <= 60:
        try:
            bc = nx.betweenness_centrality(G)
            top = sorted(bc.items(), key=lambda x: x[1], reverse=True)[:3]
            bridges = [ip for ip, s in top if s > 0]
        except: pass

    try: clust = round(nx.average_clustering(G), 3)
    except: clust = 0.0

    # Cross-ASN = different node colors
    cross = sum(1 for u, v in G.edges()
                if G.nodes[u].get('color', '') != G.nodes[v].get('color', ''))
    cross_pct = round(cross / max(e, 1) * 100, 1)

    return {'nodes': n, 'edges': e, 'density': round(nx.density(G), 3),
            'avg_degree': round(sum(degrees.values()) / n, 1),
            'clustering': clust,
            'components': nx.number_connected_components(G),
            'hub': hub, 'hub_degree': degrees[hub],
            'bridges': bridges, 'degrees': degrees,
            'cross_asn': cross, 'cross_pct': cross_pct}


# =============================================================================
# Generate enhanced graph
# =============================================================================
def generate_enhanced(dot_path, cnum, outdir, legend_map, the_format='svg', the_engine='sfdp', max_edges=20000):
    t0 = time.time()
    G, dot_legend = parse_dot(dot_path)

    if len(G.nodes()) == 0:
        log(f"    Cluster {cnum}: empty, skipping"); return None
    if len(G.edges()) > max_edges:
        log(f"    Cluster {cnum}: {len(G.edges())} edges, skipping"); return None

    log(f"    Cluster {cnum}: {len(G.nodes())} nodes, {len(G.edges())} edges — computing analytics...")
    analytics = compute_analytics(G)
    degrees = analytics['degrees']
    max_deg = max(degrees.values()) if degrees else 1
    hub = analytics['hub']
    bridges = analytics['bridges']

    # Build enhanced graph
    g = gv.Graph(format=the_format, engine=the_engine)
    g.attr('graph', splines='true', overlap='false', bgcolor='white',
           fontname='Helvetica', pad='0.5', sep='+5')

    # --- Nodes: sized by degree, hub/bridge highlighted ---
    for node in G.nodes():
        color = G.nodes[node].get('color', 'gray')
        deg = degrees.get(node, 1)

        # Scale: small clusters get bigger base, large clusters get smaller base
        n = len(G.nodes())
        if n <= 5:
            base, scale = 0.6, 0.8
        elif n <= 20:
            base, scale = 0.4, 0.6
        else:
            base, scale = 0.25, 0.45

        w = round(base + (deg / max(max_deg, 1)) * scale, 2)
        font_size = str(max(8, min(14, int(8 + deg * 1.5))))

        attrs = {
            'color': color, 'style': 'filled', 'fillcolor': color,
            'fontcolor': 'white', 'fontname': 'Helvetica Bold',
            'fontsize': font_size,
            'width': str(w), 'height': str(w), 'fixedsize': 'true',
        }

        # Hub: gold ring
        if node == hub and len(G.nodes()) > 1:
            attrs['penwidth'] = '4'
            attrs['color'] = 'gold'  # border color
            attrs['fillcolor'] = G.nodes[node].get('color', 'gray')

        # Bridge: pink ring
        elif node in bridges:
            attrs['penwidth'] = '3'
            attrs['color'] = 'deeppink'
            attrs['fillcolor'] = G.nodes[node].get('color', 'gray')

        g.node(node, **attrs)

    # --- Edges: dashed if cross-ASN ---
    seen = set()
    for u, v, d in G.edges(data=True):
        key = tuple(sorted([u, v]))
        if key in seen: continue
        seen.add(key)

        edge_color = d.get('color', 'gray')
        c1 = G.nodes[u].get('color', '')
        c2 = G.nodes[v].get('color', '')

        attrs = {'color': edge_color}
        if c1 and c2 and c1 != c2:
            attrs['style'] = 'dashed'
            attrs['penwidth'] = '2.0'
        else:
            attrs['penwidth'] = '1.2'

        g.edge(u, v, **attrs)

    # --- Analytics box ---
    a = analytics
    stats = (
        f"Nodes: {a['nodes']}  |  Edges: {a['edges']}\\n"
        f"Density: {a['density']}\\n"
        f"Avg Degree: {a['avg_degree']}\\n"
        f"Clustering Coeff: {a['clustering']}\\n"
        f"Components: {a['components']}\\n"
        f"Cross-ASN edges: {a['cross_pct']}%\\n"
        f"Hub: {hub} (degree {a['hub_degree']})"
    )

    with g.subgraph(name='cluster_stats') as sg:
        sg.attr('graph', rank='sink')
        sg.node('_stats', label=stats, shape='note',
                style='filled', fillcolor='#FFFDE7',
                fontsize='10', fontname='Courier',
                fontcolor='#333333', penwidth='1', color='#999999')

    # --- Legend (from original DOT + our additions) ---
    with g.subgraph(name='cluster_legend') as lg:
        lg.attr('graph', rank='source')
        lg.node(f'Cluster {cnum}', shape='box', style='bold',
                fontsize='14', fontname='Helvetica Bold', fontcolor='#333333')

        # Port-pair labels from original DOT legend
        for color, label in dot_legend.items():
            lg.node(label, shape='box', style='filled', fillcolor='white',
                    color=color, fontsize='9', fontcolor=color, penwidth='2.5',
                    fontname='Courier Bold')

        # Enhancement legend
        lg.node('★ hub (highest degree)', shape='plaintext',
                fontsize='9', fontcolor='#B8860B', fontname='Courier')
        lg.node('● bridge (high betweenness)', shape='plaintext',
                fontsize='9', fontcolor='deeppink', fontname='Courier')
        lg.node('╌╌ dashed = cross-ASN reuse', shape='plaintext',
                fontsize='9', fontcolor='#666666', fontname='Courier')

    # Render
    outpath = os.path.join(outdir, f'enhanced_graph{cnum}.dot')
    try:
        g.render(outpath, cleanup=False)
        elapsed = time.time() - t0
        log(f"    ✓ {elapsed:.1f}s → enhanced_graph{cnum}.dot.{the_format}")
        return outpath + '.' + the_format
    except Exception as e:
        g.save(outpath)
        log(f"    ⚠ render failed ({e}), DOT saved")
        return outpath


# =============================================================================
# Summary table
# =============================================================================
def generate_summary(dot_dir, outdir, the_format='svg'):
    log("  Building summary table...")
    dots = sorted([f for f in os.listdir(dot_dir)
                   if re.match(r'graph\d+\.dot$', f)],
                  key=lambda f: extract_cluster_num(f))

    rows = []
    for i, df in enumerate(dots):
        cnum = extract_cluster_num(df)
        if cnum < 0: continue
        G, _ = parse_dot(os.path.join(dot_dir, df))
        if len(G.nodes()) < 2: continue
        if len(G.edges()) > 20000:
            rows.append((cnum, len(G.nodes()), len(G.edges()), '-', '-', '-', '-', '-'))
            continue
        a = compute_analytics(G)
        rows.append((cnum, a['nodes'], a['edges'], a['density'],
                     a['avg_degree'], a['clustering'],
                     f"{a['cross_pct']}%",
                     f"{a['hub']} (d={a['hub_degree']})" if a['hub'] else '-'))
        if (i + 1) % 50 == 0:
            log(f"    processed {i+1}/{len(dots)}...")

    if not rows:
        log("    No clusters for summary"); return

    g = gv.Digraph(format=the_format, engine='dot')
    g.attr('graph', rankdir='TB', bgcolor='white', fontname='Courier', pad='0.3')

    html = ('<<TABLE BORDER="1" CELLBORDER="1" CELLSPACING="0" CELLPADDING="5">'
            '<TR>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Cluster</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Nodes</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Edges</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Density</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Avg Deg</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Clustering</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Cross-ASN</B></FONT></TD>'
            '<TD BGCOLOR="#4A90D9"><FONT COLOR="white"><B>Hub Node</B></FONT></TD>'
            '</TR>')

    for i, r in enumerate(rows[:100]):
        bg = '#F5F5F5' if i % 2 == 0 else '#FFFFFF'
        html += (f'<TR>'
                 f'<TD BGCOLOR="{bg}"><B>{r[0]}</B></TD>'
                 f'<TD BGCOLOR="{bg}">{r[1]}</TD>'
                 f'<TD BGCOLOR="{bg}">{r[2]}</TD>'
                 f'<TD BGCOLOR="{bg}">{r[3]}</TD>'
                 f'<TD BGCOLOR="{bg}">{r[4]}</TD>'
                 f'<TD BGCOLOR="{bg}">{r[5]}</TD>'
                 f'<TD BGCOLOR="{bg}">{r[6]}</TD>'
                 f'<TD BGCOLOR="{bg}" ALIGN="LEFT"><FONT POINT-SIZE="8">{r[7]}</FONT></TD>'
                 f'</TR>')
    html += '</TABLE>>'

    g.node('summary', label=html, shape='none')
    outpath = os.path.join(outdir, 'enhanced_summary.dot')
    try:
        g.render(outpath, cleanup=False)
        log(f"  ✓ enhanced_summary.dot.{the_format}")
    except Exception as e:
        g.save(outpath)
        log(f"  ⚠ summary render failed: {e}")


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_dir', required=True,
                        help='Directory with graph{N}.dot files')
    parser.add_argument('-o', '--output_dir', default='enhanced_graphs',
                        help='Output directory')
    parser.add_argument('--clusters', nargs='+', type=int, default=None)
    parser.add_argument('--summary', action='store_true')
    parser.add_argument('--format', default='svg', choices=['svg', 'pdf', 'png'])
    parser.add_argument('--engine', default='sfdp', choices=['sfdp', 'neato', 'dot', 'fdp', 'circo'])
    parser.add_argument('--max-edges', type=int, default=20000)
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Find DOT files
    dots = [f for f in os.listdir(args.input_dir)
            if re.match(r'graph\d+\.dot$', f)]

    if not dots:
        log(f"No graph*.dot files in {args.input_dir}")
        sys.exit(1)

    log(f"Found {len(dots)} DOT files in {args.input_dir}")

    if args.clusters:
        target = set(args.clusters)
        dots = [f for f in dots if extract_cluster_num(f) in target]
        log(f"Filtered to {len(dots)} clusters")

    dots.sort(key=lambda f: extract_cluster_num(f))

    log(f"\nEnhancing {len(dots)} clusters...")
    ok, skip = 0, 0
    for i, df in enumerate(dots):
        cnum = extract_cluster_num(df)
        path = os.path.join(args.input_dir, df)
        log(f"  [{i+1}/{len(dots)}] Cluster {cnum}...")
        result = generate_enhanced(path, cnum, args.output_dir,
                                   {}, args.format, args.engine, args.max_edges)
        if result: ok += 1
        else: skip += 1

    if args.summary:
        log("\nGenerating summary table...")
        generate_summary(args.input_dir, args.output_dir, args.format)

    log(f"\n{'='*50}")
    log(f"Done: {ok} enhanced, {skip} skipped")
    log(f"Output: {args.output_dir}/")
    for f in sorted(os.listdir(args.output_dir)):
        sz = os.path.getsize(os.path.join(args.output_dir, f))
        log(f"  {f:45s} {sz/1024:.0f} KB")

if __name__ == '__main__':
    main()