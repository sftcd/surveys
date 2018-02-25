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

# ips in clusters
clusterips={}

this_clusternum=0
clustercount=0
checkcount=0

def getnextfprint(fp):
    # read the next fingerprint from the file pointer
    # fprint is a json structure, pretty-printed, so we'll
    # read to the first line that's just an "{" until
    # the next line that's just a "}"
    line=fp.readline()
    while line:
        if line=="{\n":
            break
        line=fp.readline()
    jstr=""
    while line:
        jstr += line
        if line=="}\n":
            break
        line=fp.readline()
    if line:
        jthing=json.loads(jstr)
        return jthing
    else:
        return line

fp=open(sys.argv[1],"r")

f=getnextfprint(fp)
while f:
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
        print >> sys.stderr, "Did: " + str(checkcount) 
    f=getnextfprint(fp)

fp.close()

cf="clustersizes.csv"
cf_p=open(cf,"w")

print >> cf_p, "#clusternum,size"
for cnum in clusterips:
    csize=len(clusterips[cnum])
    print "Clusternum: " + str(cnum) + " has " + str(csize) + " members"
    print >> cf_p, str(cnum) + "," + str(csize)
cf_p.close()

print >> sys.stderr, "collisions: " + str(checkcount) + "\n\t" + \
        "total clusters: " + str(clustercount)

