#!/usr/bin/python
import pickle
import sys
import matplotlib.pyplot as plt   
import networkx as nx

try:
    # gpickle route
    graph = nx.read_gpickle(sys.argv[1])
    nx.draw(graph)
    #ax = pickle.load(open(sys.argv[1], "rb"))
    #plt.show()
    plt.savefig(sys.argv[1]+".png", format="PNG")
except Exception as e: 
    print "exception: " + str(e)

