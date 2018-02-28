#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# reduce memory footprint - just read one collision at a time from file

# figure out if we can get port 587 ever - looks like not, for now anyway

import sys
import os
import tempfile
import gc
import copy
import argparse

from SurveyFuncs import *

# install via  "$ sudo pip install -U jsonpickle"
#import jsonpickle

# direct to graphviz ...
import graphviz as gv

# deffault output directory
outdir="graphs"

# note - had to rebuild graphviz locally for sfdp to work (and that had
# *loads* of compiler warnings and seems to crash on some graphs) if
# running on ubuntu version dot ok-ish works here but not sfdp
# graphing globals
#the_engine='circo'
#the_engine='dot'
#the_engine='neato'
the_engine='sfdp'
the_format='svg'
#the_format='png'
#the_format='dot'

# command line arg handling 
parser=argparse.ArgumentParser(description='Graph the collisions found by SameKeys.py')
parser.add_argument('-f','--file',     
                    dest='fname',
                    help='json file containing key fingerprint collisions')
parser.add_argument('-o','--output_dir',     
                    dest='outdir',
                    help='directory in which to put (maybe many) graph files')
parser.add_argument('-l','--legend',
                    help='include a legend on each graph, or just create ./legend.dot.svg if no other args',
                    action='store_true')
parser.add_argument('-n','--neato',
                    help='switch to neato graphviz thing (default=sfdp)',
                    action='store_true')
args=parser.parse_args()


# if this then just print legend
if args.fname=='' and args.legend:
    print args
    printlegend()
    sys.exit(0)

if args.outdir:
    outdir=args.outdir

if args.neato:
    the_engine='neato'

# checks - can we write to outdir...
try:
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    testfile = tempfile.TemporaryFile(dir = outdir)
    testfile.close()
except Exception as e:
    print >> sys.stderr, "Can't create output directory " + outdir + " - exiting:" + str(e)
    sys.exit(1)

if not os.access(outdir,os.W_OK):
    print >> sys.stderr, "Can't write to output directory " + outdir + " - exiting"
    sys.exit(1)

# main line processing ...

# we need to pass over all the fingerprints to make a graph for each
# cluster, note that due to cluster merging (in SameKeys.py) we may
# not see all cluster members as peers of the first cluster member

# ipdone and edgedone are ok to be global as each ip is only in one
# cluster and hence same with edges
# need to be careful with memory for the edges - on EE data those
# seem to explode
ipdone=set()
edgedone=set()

checkcount=0
grr={}
dynlegs={}
actualcnums=[]

# max size of dot file we try to render
maxglen=500000

# open file
fp=open(args.fname,"r")

f=getnextfprint(fp)
while f:
    dynleg=set()
    if f['clusternum']>=0 and f['nrcs']>0:
        # remember clusternum for later
        newgraph=False
        if f['clusternum'] not in actualcnums:
            newgraph=True
            actualcnums.append(f['clusternum'])
            gvgraph=gv.Graph(format=the_format,engine=the_engine)
            gvgraph.attr('graph',splines='true')
            gvgraph.attr('graph',overlap='false')
            grr[f['clusternum']]=gvgraph
            if args.legend:
                dynlegs[f['clusternum']]=dynleg
        else:
            gvgraph=grr[f['clusternum']]
            if args.legend:
                dynleg=dynlegs[f['clusternum']]

        # figure colour for node for this fingerprint based on ASN
        asncol=asn2colour(f['asndec'])

        # have we processed this node already?
        if f['ip'] not in ipdone:
            gvgraph.node(f['ip'],color=asncol,style="filled")
            ipdone.add(f['ip'])

        # process peers ("key sharers") for this node
        for recn in f['rcs']:
            cip=f['rcs'][recn]['ip']
            if cip not in ipdone:
                try:
                    ccol=asn2colour(f['rcs'][recn]['asndec'])
                    gvgraph.node(cip,color=ccol,style="filled")
                except:
                    gvgraph.node(cip,color=asncol,style="filled")
                ipdone.add(cip)

            # add edge for that to this
            ename=edgename(f['ip'],cip)
            backename=edgename(cip,f['ip'])
            if ename not in edgedone and backename not in edgedone:
                colours=[]
                mask2colours(f['rcs'][recn]['ports'],colours,dynleg)
                for col in colours:
                    gvgraph.edge(f['ip'],cip,color=col)
                del colours
                edgedone.add(ename)

    if not args.legend:
        del dynleg

    # print something now and then to keep operator amused
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " most recent cluster " + str(f['clusternum']) + \
                    " IPs: " + str(len(ipdone)) + " edges: " + str(len(edgedone)) + " #clusters: " + str(len(actualcnums))
    if checkcount % 1000 == 0:
        gc.collect()

    # read next fp
    del f
    f=getnextfprint(fp)

# close file
fp.close()

# make a list of graphs we didn't end up rendering
notrendered=[]
clustercount=0

for i in actualcnums:
    try:
        gvgraph=grr[i]
    except:
        print "Cluster " + str(i) + " must have been merged - skipping"
        continue
    clustercount += 1
    print "Graphing cluster: " + str(i)
    # optional legend...
    try:
        if args.legend:
            lgr=gv.Graph(name="legend",node_attr={'shape': 'box'})
            lgr.attr('graph',rank="source")
            lgr.node("Cluster " + str(i))
            dynleg=dynlegs[i]
            for leg in dynleg:
                ss=leg.split()
                lgr.node(ss[0],label=ss[0],color=ss[1])
            #gvgraph.subgraph(lgr,name="legend"
            gvgraph.subgraph(lgr)
            #gvgraph.attr('graph',rank="min")
    except Exception as e: 
        pass
        #print >> sys.stderr, str(e)
    # render if not too big...
    try:
        glen=len(gvgraph.source)
        if glen > maxglen:
            print "Not rendering graph for cluster "+ str(i) + " - too long: " + str(glen)
            gvgraph.save(outdir + "/graph"+str(i)+".dot")
            notrendered.append(i)
        else:
            gvgraph.render(outdir + "/graph"+str(i)+".dot")
    except Exception as e: 
        notrendered.append(i)
        print >> sys.stderr, "Ecxeption rendering cluster: " + str(i) 
        print >> sys.stderr, "Exception: " + str(e)
        print >> sys.stderr, "Maybe you got bored and killed a process?"
            
del grr

summary_fp=open(outdir+"/summary.txt","a+")
print >> summary_fp, "collisions: " + str(checkcount) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
        "graphs not rendered: " + str(notrendered)
summary_fp.close()

print >> sys.stderr, "collisions: " + str(checkcount) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
        "graphs not rendered: " + str(notrendered)

#del fingerprints 
