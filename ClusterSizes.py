#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# figure out if we can get port 587 ever - looks like not, for now anyway

import sys
import json
import gc

def readfprints(fname):
    f=open(fname,'r')
    fp=json.load(f)
    f.close()
    return fp

# read in e.g. collisions.json from a run of SameKeys.py
fingerprints=readfprints(sys.argv[1])

# sizes of clusters
clustersizes=[]

this_clusternum=0
clusternum=0
checkcount=0

for f in fingerprints:
    try:
        this_clusternum=f['clusternum']
        if this_clusternum > clusternum:
            clusternum=this_clusternum
    except:
        continue
        
    if f['clusternum']>=0 and f['nrcs']>0:
        # process cluster
        try:
            cset=clustersizes[f['clusternum']]
        except:
            cset=set()
            clustersizes.insert(f['clusternum'],cset)
        cset.add(f['nrcs']+1)

    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " saw " + str(clusternum) + " clusters"

cf="clustersizes.csv"
cf_p=open(cf,"w")

print >> cf_p, "#clusternum,size"
for i in range(1,clusternum+1):
    if len(clustersizes[i]) == 1:
        csize=clustersizes[i].pop()
        print "Clusternum: " + str(i) + " has " + str(csize) + " members"
        print >> cf_p, str(i) + "," + str(csize)
    else:
        print "ODDBALL Clusternum: " + str(i) + " has " + str(clustersizes[i]) + " members"
cf_p.close()

print >> sys.stderr, "collisions: " + str(len(fingerprints)) + "\n\t" + \
        "total clusters: " + str(clusternum)

del fingerprints
