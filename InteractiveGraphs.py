#!/usr/bin/python3

# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE

import argparse
import sys
import os
import json
import glob
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import networkx as nx
import json
import random

clustersDirectory = None
argparser=argparse.ArgumentParser(description='Gnerate interactive graphs for clusters')
argparser.add_argument('-d','--dir',     
                    dest='clustersDirectory',
                    help='directory containing clusterX.json files')
args=argparser.parse_args()

if args.clustersDirectory is None:
    print("You need to specify a directory containing clusterX.json files")
    sys.exit(1)
 
clustersDirectory = args.clustersDirectory

colors = [
        "aliceblue", "antiquewhite", "aqua", "aquamarine", "azure",
        "beige", "bisque", "black", "blanchedalmond", "blue",
        "blueviolet", "brown", "burlywood", "cadetblue",
        "chartreuse", "chocolate", "coral", "cornflowerblue",
        "cornsilk", "crimson", "cyan", "darkblue", "darkcyan",
        "darkgoldenrod", "darkgray", "darkgrey", "darkgreen",
        "darkkhaki", "darkmagenta", "darkolivegreen", "darkorange",
        "darkorchid", "darkred", "darksalmon", "darkseagreen",
        "darkslateblue", "darkslategray", "darkslategrey",
        "darkturquoise", "darkviolet", "deeppink", "deepskyblue",
        "dimgray", "dimgrey", "dodgerblue", "firebrick",
        "floralwhite", "forestgreen", "fuchsia", "gainsboro",
        "ghostwhite", "gold", "goldenrod", "gray", "grey", "green",
        "greenyellow", "honeydew", "hotpink", "indianred", "indigo",
        "ivory", "khaki", "lavender", "lavenderblush", "lawngreen",
        "lemonchiffon", "lightblue", "lightcoral", "lightcyan",
        "lightgoldenrodyellow", "lightgray", "lightgrey",
        "lightgreen", "lightpink", "lightsalmon", "lightseagreen",
        "lightskyblue", "lightslategray", "lightslategrey",
        "lightsteelblue", "lightyellow", "lime", "limegreen",
        "linen", "magenta", "maroon", "mediumaquamarine",
        "mediumblue", "mediumorchid", "mediumpurple",
        "mediumseagreen", "mediumslateblue", "mediumspringgreen",
        "mediumturquoise", "mediumvioletred", "midnightblue",
        "mintcream", "mistyrose", "moccasin", "navajowhite", "navy",
        "oldlace", "olive", "olivedrab", "orange", "orangered",
        "orchid", "palegoldenrod", "palegreen", "paleturquoise",
        "palevioletred", "papayawhip", "peachpuff", "peru", "pink",
        "plum", "powderblue", "purple", "red", "rosybrown",
        "royalblue", "rebeccapurple", "saddlebrown", "salmon",
        "sandybrown", "seagreen", "seashell", "sienna", "silver",
        "skyblue", "slateblue", "slategray", "slategrey", "snow",
        "springgreen", "steelblue", "tan", "teal", "thistle", "tomato",
        "turquoise", "violet", "wheat", "white", "whitesmoke",
        "yellow", "yellowgreen"
    ]

def createGraph(data, name, outdirectory):
    G = nx.Graph()

    for i in data:
        i["collisions"] = {}

    for i in data:
        for j in i["fprints"]:
            for k in data:
                if i != k:
                    for l in k["fprints"]:
                        if j == l:
                            rdns = k["ip"]
                            if rdns not in i["collisions"]:
                                i["collisions"][rdns] = []
                            i["collisions"][rdns].append(j)
                        

            

    groups = {}
    for i in data:
        asn = i["asn"]
        if asn not in groups:
            groups[asn] = []
        groups[asn].append(i)



    for i in groups:
        color = random.choice(colors)
        colors.remove(color)
        for j in groups[i]:
            G.add_nodes_from([(j["ip"], {"asn": j["asn"], "rdns":j["rdns"], "fprints":j["fprints"], "collisions":j["collisions"],"ip":j["ip"], "color":color})])




    # Add edges
    for i in data:
        for j in data:
            if i != j:
                done = False
                if G.has_edge(i["ip"], j["ip"]):
                    done = True
                for k in i["fprints"]:
                    if done:
                        break
                    for l in j["fprints"]:
                        if done:
                            break
                        if k == l:
                            done = True
                            G.add_edge(i["ip"], j["ip"], attr={"port":"p25"})


    layout = go.Layout(
        title=name,
        showlegend=True,
        xaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
        ),
        yaxis=dict(
            showgrid=False,
            zeroline=False,
            showticklabels=False,
        )
    )

    fig = go.Figure(layout=layout)

    pos = nx.spring_layout(G)
    for node in G.nodes:
        x, y = pos[node]
        # get asn
        asn = G.nodes[node]["asn"]
        ip = G.nodes[node]["ip"]
        nodeColor = G.nodes[node]["color"]
        rnds = G.nodes[node]["rdns"]
        fprints = G.nodes[node]["fprints"]
        collisions = G.nodes[node]["collisions"]

        textString = f"IP: {ip}<br>ASN: {asn}<br>RDNS: {rnds}<br>Fingerprints:<br>"
        indent = 0
        for i in fprints:
            if len(i) > indent:
                indent = len(i)
                indent += 1
        for i in fprints:
            # pad string
            start = f"{i}:"
            for j in range(indent - len(i)):
                start += " "
            textString += f"{start} {fprints[i]}<br>"
        
    
        textString += "Collisions:<br>"
        for i in G.nodes[node]["collisions"]:
            textString += f"{i}:<br>"
            for j in G.nodes[node]["collisions"][i]:
                textString += f"{j} "
            textString += "<br>"

        fig.add_trace(go.Scatter(x=[x], y=[y], mode="markers+text", text=node, textposition="bottom center",hovertext=textString, hoverinfo="text", marker=dict(size=50, color=nodeColor)))

    for edge in G.edges:
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", line=dict(color="black")))

    fig.write_html(outdirectory + "/"+ name+".html", auto_open=False)

# read all files that match cluster*.json in the directory
def readClusterFiles(directory):
    clusters = []
    for filename in glob.glob(directory + "/cluster*.json"):
        with open(filename) as f:
            filename = os.path.basename(filename)
            sanFileName = filename.split(".")[0]
            data = json.load(f)
            outdata = []
            for i in data:
                rdns = "N\A"
                try:
                    rdns = i["analysis"]["nameset"]["rdns"]
                except:
                    pass
                outdata.append({"ip": i["ip"], "asn": i["asn"], "fprints": i["fprints"], "rdns": rdns})
            createGraph(outdata, sanFileName, directory)
            print("Finished "+filename)
            

readClusterFiles(clustersDirectory)
