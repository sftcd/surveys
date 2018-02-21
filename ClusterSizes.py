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

totalfps=len(fingerprints)

# ips in clusters
clusterips={}

this_clusternum=0
clustercount=0
checkcount=0

for f in fingerprints:
    if not (f['clusternum']>0 and f['nrcs']>0):
        continue

    cnum=f['clusternum']
    for rec in f['rcs']:
        theip=f['rcs'][rec]['ip']
        if cnum not in clusterips:
            clusterips[cnum]=[]
            clustercount+=1
        #print clusterips[cnum]
        if theip not in clusterips[cnum]:
            clusterips[cnum].append(theip)

    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Did: " + str(checkcount) + " of " + str(totalfps)

cf="clustersizes.csv"
cf_p=open(cf,"w")

print >> cf_p, "#clusternum,size"
for cnum in clusterips:
    csize=len(clusterips[cnum])
    print "Clusternum: " + str(cnum) + " has " + str(csize) + " members"
    print >> cf_p, str(cnum) + "," + str(csize)
cf_p.close()

print >> sys.stderr, "collisions: " + str(totalfps) + "\n\t" + \
        "total clusters: " + str(clustercount)

del fingerprints
