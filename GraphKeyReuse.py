#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# figure out if we can get port 587 ever - looks like not, for now anyway

import sys
import json
import gc

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

# direct to graphviz ...
import graphviz as gv


def readfprints(fname):
    f=open(fname,'r')
    fp=json.load(f)
    f.close()
    return fp

# reverse map from bit# to string
# the above could be done better using this... but meh
portstrings=['p22','p25','p110','p143','p443','p993']
portscols=[0x00000f,0x0000f0,0x000f00,0x00f000,0x0f0000,0xf00000]

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

# colours - a diagonal matrix

def mask2colours(mask, colours):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                colcode='#'+ "%06X" % (portscols[i]|portscols[j])
                if colcode not in colours:
                    colours.append(colcode)

def asn2colour(asn):
    return '#' + "%06X" % (int(asn)&0xffffff)

def edgename(ip1,ip2):
    return ip1+"|"+ip2

fingerprints=readfprints(sys.argv[1])

# newer graphing
ipdone=set()
edgedone=set()
clusternum=0
checkcount=0
grr=['null']
for f in fingerprints:
    try:
        this_clusternum=f['clusternum']
        if this_clusternum > clusternum:
            clusternum=this_clusternum
    except:
        continue
        
    if f['clusternum']>=0 and f['nrcs']>0:
        # process cluster
        #the_engine='circo'
        #the_engine='dot'
        the_engine='neato'
        #the_engine='sfdp'
        the_format='svg'
        #the_format='png'
        #the_format='dot'
        try:
            gvgraph=grr[f['clusternum']]
        except:
            gvgraph=gv.Graph(format=the_format,engine=the_engine)
            gvgraph.attr('graph',splines='true')
            gvgraph.attr('graph',overlap='false')
            grr.insert(f['clusternum'],gvgraph) 
        #print "ipdone1: " + str(ipdone)
        asncol=asn2colour(f['asndec'])
        if f['ip'] not in ipdone:
            gvgraph.node(f['ip'],color=asncol,style="filled")
            ipdone.add(f['ip'])
            #print "ipdone2: " + str(ipdone)
        for recn in f['rcs']:
            cip=f['rcs'][recn]['ip']
            if cip not in ipdone:
                try:
                    ccol=asn2colour(f['rcs'][recn]['asndec'])
                    gvgraph.node(cip,color=ccol,style="filled")
                except:
                    gvgraph.node(cip,color=asncol,style="filled")
                ipdone.add(cip)
                #print "ipdone3: " + str(ipdone)
            if edgename(f['ip'],cip) not in edgedone and edgename(cip,f['ip']) not in edgedone:
                colours=[]
                mask2colours(f['rcs'][recn]['ports'],colours)
                for col in colours:
                    gvgraph.edge(f['ip'],cip,color=col)
                edgedone.add(edgename(f['ip'],cip))
        #print "gvgraph: " + str(gvgraph)
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " saw " + str(clusternum) + " clusters"

for i in range(1,clusternum+1):
    print "Graphing cluster: " + str(i)
    gvgraph=grr[i]
    gvgraph.render("graphs/graph"+str(i)+".dot")

del grr

print >> sys.stderr, "collisions: " + str(len(fingerprints)) + "\n\t" + \
        "total clusters: " + str(clusternum)

del fingerprints
