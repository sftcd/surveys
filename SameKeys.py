#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# figure out if we can get port 587 ever - looks like not, for now anyway

import sys
import json
import gc

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

# try visualising:
# first try "$ sudo -H pip install networkx"
# https://networkx.github.io/documentation/stable/install.html
# found that via a general python visualisation page:
# https://python-graph-gallery.com/
# learning from https://networkx.github.io/documentation/stable/tutorial.html
import networkx as nx
# for a pretty picture...
import matplotlib.pyplot as plt

# direct to graphviz ...
import graphviz as gv

# using a class needs way less memory than random dicts apparently
class OneFP():
    __slots__ = ['ip_record','ip','asn','asndec','amazon','fprints','nsrc','rcs']
    def __init__(self):
        self.ip_record=-1
        self.ip=''
        self.asn=''
        self.asndec=0
        self.clusternum=0
        self.amazon=False
        self.fprints={}
        self.nrcs=0
        self.rcs={}

# this is a dict to hold the set of keys we find
fingerprints=[]
bads={}

with open(sys.argv[1],'r') as f:
    overallcount=0
    badcount=0
    goodcount=0
    for line in f:
        j_content = json.loads(line)
        somekey=False
        thisone=OneFP()
        thisone.ip_record=overallcount
        thisone.ip=j_content['ip']

        # amazon is the chief susspect for key sharing, via some 
        # kind of fronting, at least in .ie
        try:
            asn=j_content['autonomous_system']['name'].lower()
            asndec=int(j_content['autonomous_system']['asn'])
            if "amazon" in asn:
                thisone.amazon=True
            thisone.asn=asn
            thisone.asndec=asndec
        except:
            thisone.asn="unknown"

        try:
            fp=j_content['p22']['ssh']['v2']['server_host_key']['fingerprint_sha256'] 
            thisone.fprints['p22']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            fp=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone.fprints['p25']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            fp=j_content['p110']['pop3']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone.fprints['p110']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            fp=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p143']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            fp=j_content['p443']['https']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p443']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            fp=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p993']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass

        if somekey:
            goodcount += 1
            fingerprints.append(thisone)
        else:
            bads[badcount]=j_content
            badcount += 1
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print >> sys.stderr, "Reading fingerprints, did: " + str(overallcount)
        del j_content
        del thisone
f.close()
gc.collect()

# encoder options
#jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
# this gets crapped on each time (for now)
keyf=open('fingerprints.json', 'w')
bstr=jsonpickle.encode(fingerprints)
#bstr=jsonpickle.encode(fingerprints,unpicklable=False)
keyf.write(bstr)
del bstr
keyf.write("\n")
keyf.close()

# this gets crapped on each time (for now)
# in this case, these are the hosts with no crypto anywhere (except
# maybe on p22)
badf=open('dodgy.json', 'w')
bstr=jsonpickle.encode(bads,unpicklable=False)
badf.write(bstr + '\n')
del bstr
badf.close()
del bads

checkcount=0
colcount=0

# to save memory we'll encode port collision information in a 
# compact form, we have six ports to consider 22,25,110,143,443 and 993
# and 25==25 is diferent from 25==143
# we use five octets, one for each local port;
# values are bitmasks, a set bit means the key on the remote
# port is the same as this one, so octet values can be:
# 0x00 no match
# 0x02 local port matches remote p25
# 0x06 local port matches remote p25 and p143
# etc


# reverse map from bit# to string
# the above could be done better using this... but meh
portstrings=['p22','p25','p110','p143','p443','p993']
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

def mask2colours(mask, colours):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                colcode='#'+ "%06X" % cmpmask
                colours.append(colcode)

def asn2colour(asn):
    return '#' + ("%06X" % int(asn))

# this gets crapped on each time (for now)
keyf=open('all-key-fingerprints.json', 'w')
keyf.write("[\n");

mostcollisions=0
biggestcollider=-1

# identify 'em
clusternum=0

fl=len(fingerprints)
for i in range(0,fl):
    r1=fingerprints[i]
    rec1=r1.ip_record
    for j in range (i+1,fl):
        r2=fingerprints[j]
        rec2=r2.ip_record
        r1r2coll=False # so we remember if there was one
        for k1 in r1.fprints:
            for k2 in r2.fprints:
                if r1.fprints[k1]==r2.fprints[k2]:
                    if rec2 not in r1.rcs:
                        r1.rcs[rec2]={}
                        r1.rcs[rec2]['ip']=r2.ip
                        if r2.asn != r1.asn:
                            r1.rcs[rec2]['asn']=r2.asn
                            r1.rcs[rec2]['asndec']=r2.asndec
                        r1.rcs[rec2]['ports']=collmask('0x0',k1,k2)
                        #print "A: " + r1.rcs[rec2]['ports']
                        if r1.clusternum==0:
                            clusternum += 1
                            r1.clusternum=clusternum
                            r2.clusternum=clusternum
                        else:
                            r2.clusternum=r1.clusternum
                        colcount += 1
                        r1r2coll=True # so we remember if there was one
                    else: 
                        r12=r1.rcs[rec2]
                        #print "B: " + r12['ports'] + " k1: " + k1 + " k2: " + k2
                        r12['ports'] = collmask(r12['ports'],k1,k2)
                        #print "C: " + r12['ports'] + " k1: " + k1 + " k2: " + k2
                        colcount += 1
                        r1r2coll=True # so we remember if there was one
                    if rec1 not in r2.rcs:
                        r2.rcs[rec1]={}
                        r2.rcs[rec1]['ip']=r1.ip
                        if r2.asn != r1.asn:
                            r2.rcs[rec1]['asn']=r1.asn
                            r2.rcs[rec1]['asndec']=r1.asndec
                        r2.rcs[rec1]['ports']=collmask('0x0',k2,k1)
                        #print "D: "+ r2.rcs[rec1]['ports']
                    else: 
                        r21=r2.rcs[rec1]
                        #print "E: " + r12['ports']
                        r21['ports'] = collmask(r21['ports'],k2,k1)
                        #print "F: " + r12['ports']
        if r1r2coll==True: # so we remember if there was one
            r1.nrcs += 1
            r2.nrcs += 1
            if r1.nrcs > mostcollisions:
                mostcollisions = r1.nrcs
                biggestcollider = r1.ip_record
            if r2.nrcs > mostcollisions:
                mostcollisions = r2.nrcs
                biggestcollider = r2.ip_record

    # print that one
    bstr=jsonpickle.encode(r1,unpicklable=False)
    keyf.write(bstr + ',\n')
    del bstr
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Checking colisions, did: " + str(checkcount) + " found: " + str(colcount) + " remote collisions"
    if checkcount % 1000 == 0:
        gc.collect()

keyf.write('\n')
keyf.close()

colcount=0
noncolcount=0
accumcount=0

colf=open('collisions.json', 'w')
colf.write('[\n')
for f in fingerprints:
    if f.nrcs!=0:
        for recn in f.rcs:
            cip=f.rcs[recn]['ip']
            f.rcs[recn]['str_colls']=expandmask(f.rcs[recn]['ports'])
        bstr=jsonpickle.encode(f,unpicklable=False)
        colf.write(bstr + ',\n')
        del bstr
        colcount += 1
    else:
        noncolcount += 1
    accumcount += 1
    if accumcount % 100 == 0:
        # exit early for debug purposes
        #break
        print >> sys.stderr, "Accumulating colissions, did: " + str(accumcount) + " found: " + str(colcount) + " IP's with remote collisions"

# this gets crapped on each time (for now)
colf.write('\n')
colf.close()

# graphing 
for i in range(1,clusternum+1):
    print "Cluster: " + str(i) + " of " + str(clusternum)
    graph = nx.Graph()
    gvgraph = gv.Graph(format='svg')
    ipsdone=[]
    for f in fingerprints:
        print gvgraph
        if f.clusternum==i and f.nrcs!=0:
            asncol=asn2colour(f.asndec)
            print "asncol: " + asncol
            print "ipsdone: " + str(ipsdone)
            graph.add_node(f.ip,node_color=asncol)
            if f.ip not in ipsdone:
                gvgraph.node(f.ip,node_color=asncol)
                ipsdone.append(f.ip)
                print "ipsdone2: " + str(ipsdone)
            #graph.add_node(f.ip)
            #graph.node[f.ip]['color']='red'
            for recn in f.rcs:
                cip=f.rcs[recn]['ip']
                if asndec in f.rcs[recn]:
                    asncol=asn2colour(f.rcs['asndec'])
                    print "\tasncol2: " + asncol
                graph.add_node(cip,node_color=asncol)
                labels=[]
                mask2labels(f.rcs[recn]['ports'],labels)
                if cip not in ipsdone:
                    gvgraph.node(cip,node_color=asncol)
                    ipsdone.append(cip)
                    print "ipsdone3: " + str(ipsdone)
                    for lab in labels:
                        gvgraph.edge(f.ip,cip,label=lab)
                #colours=[]
                #mask2colours(f.rcs[recn]['ports'],colours)
                #for col in colours:
                    #graph.add_edge(f.ip,cip,color=col)
                for lab in labels:
                    graph.add_edge(f.ip,cip,label=lab)
    nx.draw(graph)
    #plt.show()
    #nx.write_gpickle(graph,"graphs/graph"+str(i)+".pickle")
    nx.write_gexf(graph,"graphs/graph"+str(i)+".gexf")
    graph.clear()
    gvgraph.render("graphs/graph"+str(i))

print gvgraph
del fingerprints

print >> sys.stderr, "\toverall: " + str(overallcount) + "\n\t" + \
        "good: " + str(goodcount) + "\n\t" + \
        "bad: " + str(badcount) + "\n\t" + \
        "remote collisions: " + str(colcount) + "\n\t" + \
        "no collisions: " + str(noncolcount) + "\n\t" + \
        "most collisions: " + str(mostcollisions) + " for record: " + str(biggestcollider) + "\n\t" + \
        "total clusters: " + str(clusternum)
