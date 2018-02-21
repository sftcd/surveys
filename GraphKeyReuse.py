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


# graphing globals
#the_engine='circo'
the_engine='dot'
#the_engine='neato'
#the_engine='sfdp'
the_format='svg'
#the_format='png'
#the_format='dot'

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
nportscols=[ \
        'black',     'bisque',        'yellow', 'aquamarine', 'darkgray',     'orange', \
        'bisque',    'blue',          'blanchedalmond',  'crimson',    'violet',    'brown', \
        'yellow', 'blanchedalmond','chartreuse',      'cyan',       'coral',        'darkred', \
        'aquamarine','crimson',       'cyan',            'darkblue',   'darkkhaki',    'darksalmon', \
        'darkgray',  'violet',     'coral',           'darkkhaki',  'darkmagenta',  'darkseagreen', \
        'orange',     'brown',         'darkred',         'darksalmon', 'darkseagreen', 'magenta', ] 

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

# main line processing ...

if sys.argv[1]=="legend":
    printlegend()
    sys.exit(0)

# read in e.g. collisions.json from a run of SameKeys.py
fingerprints=readfprints(sys.argv[1])

# newer graphing
ipdone=set()
edgedone=set()
clusternum=0
checkcount=0
grr=['null']
dynlegs=['null']
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
            gvgraph=grr[f['clusternum']]
            dynleg=dynlegs[f['clusternum']]
        except:
            gvgraph=gv.Graph(format=the_format,engine=the_engine)
            gvgraph.attr('graph',splines='true')
            gvgraph.attr('graph',overlap='false')
            grr.insert(f['clusternum'],gvgraph) 
            dynleg=set()
            dynlegs.insert(f['clusternum'],dynleg)
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
                mask2colours(f['rcs'][recn]['ports'],colours,dynleg)
                for col in colours:
                    gvgraph.edge(f['ip'],cip,color=col)
                edgedone.add(edgename(f['ip'],cip))
        #print "gvgraph: " + str(gvgraph)
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) + " saw " + str(clusternum) + " clusters"


# make a list of graphs we didn't render
notrendered=[]

for i in range(1,clusternum+1):
    print "Graphing cluster: " + str(i)
    gvgraph=grr[i]
    # optional legend...
    try:
        if sys.argv[2]=="legend":
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
        gvgraph.save("graphs/graph"+str(i)+".dot")
        notrendered.append(i)
    else:
        try:
            gvgraph.render("graphs/graph"+str(i)+".dot")
        except Exception as e: 
            notrendered.append(i)
            print >> sys.stderr, "Ecxeption rendering cluster: " + str(i) 
            print >> sys.stderr, "Exception: " + str(e)
            print >> sys.stderr, "Maybe you got bored and killed a process?"
            
del grr

print >> sys.stderr, "collisions: " + str(len(fingerprints)) + "\n\t" + \
        "total clusters: " + str(clusternum) + "\n\t" + \
        "graphs not rendered: " + str(notrendered)

del fingerprints 
