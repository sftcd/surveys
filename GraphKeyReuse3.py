#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# variant: just graph mail,web,ssh and not specific port combos...
# to see if the bigger clusters can be graphed that way...

# figure out if we can get port 587 ever - looks like not, for now anyway

import sys
import os
import tempfile
import json
import gc
import copy
import argparse

# install via  "$ sudo pip install -U jsonpickle"
#import jsonpickle

# direct to graphviz ...
import graphviz as gv

# output directory
outdir="graphs"

# graphing globals
#the_engine='circo'
#the_engine='dot'
#the_engine='neato'
the_engine='sfdp'
the_format='svg'
#the_format='png'
#the_format='dot'

# note - had to rebuild graphviz locally for sfdp to work (and that had
# *loads* of compiler warnings and seems to crash on some graphs) if
# running on ubuntu version dot ok-ish works here but not sfdp

# max size of dot file we try to render
maxglen=500000

# sizes of clusters
clustersizes=[]

def readfprints(fname):
    f=open(fname,'r')
    fp=json.load(f)
    f.close()
    return fp

# reverse map from bit# to string
# the above could be done better using this... but meh
portstrings=['p22','p25','p110','p143','p443','p993']

# old way
#portscols=[0x00000f,0x0000f0,0x000f00,0x00f000,0x0f0000,0xf00000]
# new way - this is manually made symmetric around the diagonal
# variant - make all the mail colours the same
merged_nportscols=[ \
        'black',     'bisque', 'yellow', 'aquamarine','darkgray',    'magenta', \
        'bisque',    'blue',   'blue',   'blue',      'violet',      'blue', \
        'yellow',    'blue',   'blue',   'blue',      'coral',       'blue', \
        'aquamarine','blue',   'blue',   'blue',      'darkkhaki',   'blue', \
        'darkgray',  'violet', 'coral',  'darkkhaki', 'orange', 'darkseagreen', \
        'magenta',    'blue',   'blue',   'blue',      'darkseagreen','blue', ] 

# new way - individual colours per port-pair  - this is manually made symmetric around the diagonal
unmerged_nportscols=[ \
        'black',     'bisque',        'yellow', 'aquamarine', 'darkgray',     'magenta', \
        'bisque',    'blue',          'blanchedalmond',  'crimson',    'violet',    'brown', \
        'yellow', 'blanchedalmond','chartreuse',      'cyan',       'coral',        'darkred', \
        'aquamarine','crimson',       'cyan',            'darkblue',   'darkkhaki',    'darksalmon', \
        'darkgray',  'violet',     'coral',           'darkkhaki',  'orange',  'darkseagreen', \
        'magenta',     'brown',         'darkred',         'darksalmon', 'darkseagreen', 'maroon', ]


# pick one of these - the first merges many mail port combos
# leading to clearer graphs, the 2nd keeps all the details
# nportscols=merged_nportscols
nportscols=unmerged_nportscols

# note that in the merged case almost all collisions on ports 25,110,
# etc will be shown as p25-p25 collisions in graph legends
 
def indexport(index):
    return portstrings[index]

def portindex(pname):
    for pind in range(0,len(portstrings)):
        if portstrings[pind]==pname:
            return pind
    print >>sys.stderr, "Error - unknown port: " + pname
    return -1

def collmask(mask,k1,k2):
    try:
        lp=portindex(k1)
        rp=portindex(k2)
        intmask=int(mask,16)
        intmask |= (1<<(rp+8*lp)) 
        newmask="0x%012x" % intmask
    except Exception as e: 
        print >> sys.stderr, "collmask exception, k1: " + k1 + " k2: " + k2 + " lp:" + str(lp) + " rp: " + str(rp) + " exception: " + str(e)  
        pass
    return newmask

def expandmask(mask):
    emask=""
    intmask=int(mask,16)
    #print "intmask: 0x%06x" % intmask
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            #print "\tcmpmask: 0x%06x" % cmpmask
            if intmask & cmpmask:

                # main line processing ...
                emask += indexport(i) + "==" + indexport(j) + ";"
    return emask


def mask2labels(mask, labels):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                labels.append(indexport(i) + "==" + indexport(j) )

# colours - return a list of logical-Or of port-specific colour settings
def mask2colours(mask, colours, dynleg):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                cnum=i*len(portstrings)+j
                colcode=nportscols[cnum]
                #colcode='#'+ "%06X" % (portscols[i]|portscols[j])
                if colcode not in colours:
                    colours.append(colcode)
                    if i>j:
                        dynleg.add(portstrings[i]+"-"+portstrings[j]+" "+colcode)
                    else:
                        dynleg.add(portstrings[j]+"-"+portstrings[i]+" "+colcode)

def printlegend():
    # make a fake graph with nodes for each port and coloured edges
    leg=gv.Graph(format=the_format,engine='neato',name="legend")
    leg.attr('graph',splines='true')
    leg.attr('graph',overlap='false')
    leg.attr('edge',overlap='false')
    portcount=len(portstrings)
    c=0
    for i in range(0,portcount):
        for j in range(0,portcount):
            #colcode='#'+ "%06X" % (portscols[i]|portscols[j])
            cnum=i*len(portstrings)+j
            colcode=nportscols[cnum]
            portpair = portstrings[i] + "-" + portstrings[j] 
            #print portstrings[i] + "-" + portstrings[j] + ": " + colcode 
            #leg.edge(portstrings[i],portstrings[j],label=str(cnum),color=colcode)
            leg.edge(portstrings[i],portstrings[j],color=colcode)
    leg.render("legend.dot")


def asn2colour(asn):
    return '#' + "%06X" % (int(asn)&0xffffff)

def edgename(ip1,ip2):
    return ip1+"|"+ip2


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

# read in e.g. collisions.json from a run of SameKeys.py
fingerprints=readfprints(args.fname)

# we need to pass over all the fingerprints to make a graph for each
# cluster, note that due to cluster merging (in SameKeys.py) we may
# not see all cluster members as peers of the first cluster member

ipdone=set()
edgedone=set()
checkcount=0
grr={}
dynlegs={}
actualcnums=[]
for f in fingerprints:
    if f['clusternum']>=0 and f['nrcs']>0:
        # remember clusternum for later
        newgraph=False
        if f['clusternum'] not in actualcnums:
            newgraph=True
            actualcnums.append(f['clusternum'])
            gvgraph=gv.Graph(format=the_format,engine=the_engine)
            gvgraph.attr('graph',splines='true')
            gvgraph.attr('graph',overlap='false')
            dynleg=set()
            grr[f['clusternum']]=gvgraph
            dynlegs[f['clusternum']]=dynleg
        else:
            gvgraph=grr[f['clusternum']]
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
            if edgename(f['ip'],cip) not in edgedone and edgename(cip,f['ip']) not in edgedone:
                colours=[]
                mask2colours(f['rcs'][recn]['ports'],colours,dynleg)
                for col in colours:
                    gvgraph.edge(f['ip'],cip,color=col)
                edgedone.add(edgename(f['ip'],cip))

    # print something now and then to keep operator amused
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " saw " + str(f['clusternum']) + " clusters"


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
    glen=len(gvgraph.source)
    if glen > maxglen:
        print "Not rendering graph for cluster "+ str(i) + " - too long: " + str(glen)
        gvgraph.save(outdir + "/graph"+str(i)+".dot")
        notrendered.append(i)
    else:
        try:
            gvgraph.render(outdir + "/graph"+str(i)+".dot")
        except Exception as e: 
            notrendered.append(i)
            print >> sys.stderr, "Ecxeption rendering cluster: " + str(i) 
            print >> sys.stderr, "Exception: " + str(e)
            print >> sys.stderr, "Maybe you got bored and killed a process?"
            
del grr

summary_fp=open(outdir+"/summary.txt","a+")
print >> summary_fp, "collisions: " + str(len(fingerprints)) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
summary_fp.close()

print >> sys.stderr, "collisions: " + str(len(fingerprints)) + "\n\t" + \
        "total clusters: " + str(clustercount) + "\n\t" + \
        "graphs not rendered: " + str(notrendered)

del fingerprints 
