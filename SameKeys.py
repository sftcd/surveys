#!/usr/bin/python

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
# THE SOFTWARE.

# check who's re-using the same keys 
# CensysIESMTP.py

# figure out if we can get port 587 ever - looks like not, for now anyway
# my FreshGrab's do have that but we don't for censys.io's Nov 2017 scans

import sys
import json
import gc

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

from SurveyFuncs import * 

# this is an array to hold the set of keys we find
fingerprints=[]
bads={}

with open(sys.argv[1],'r') as f:
    overallcount=0
    badcount=0
    goodcount=0
    for line in f:
        badrec=False
        j_content = json.loads(line)
        somekey=False
        thisone=OneFP()
        thisone.ip_record=overallcount
        thisone.ip=j_content['ip'].strip()

        #print "Doing " + thisone.ip

        if 'writer' in j_content:
            thisone.writer=j_content['writer']

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
            # look that chap up ourselves
            mm_inited=False
            if not mm_inited:
                mm_setup()
                mm_inited=True
            asninfo=mm_info(thisone.ip)
            #print "fixing up asn info",asninfo
            thisone.asn=asninfo['asn']
            thisone.asndec=asninfo['asndec']
            if asninfo['cc'] != 'IE' and asninfo['cc'] != 'EE':
                # TODO: what to actually if the country-code is (now) wrong?
                print "Bad country for ip",thisone.ip,asninfo['cc']
                badrec=True

        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p22']['data']['xssh']['key_exchange']['server_host_key']['fingerprint_sha256'] 
            else:
                fp=j_content['p22']['ssh']['v2']['server_host_key']['fingerprint_sha256'] 
            thisone.fprints['p22']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p25']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone.fprints['p25']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p110']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p110']['pop3']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone.fprints['p110']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p143']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p143']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p443']['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p443']['https']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p443']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass

        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p587']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p587']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p587']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass

        try:
            if thisone.writer=="FreshGrab.py":
                fp=j_content['p993']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            else:
                fp=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone.fprints['p993']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass

        if not badrec and somekey:
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

                    if r1.clusternum==0 and r2.clusternum==0:
                        clusternum += 1
                        r1.clusternum=clusternum
                        r2.clusternum=clusternum
                    elif r1.clusternum==0 and r2.clusternum>0:
                        r1.clusternum=r2.clusternum
                    elif r1.clusternum>0 and r2.clusternum==0:
                        r2.clusternum=r1.clusternum
                    elif r1.clusternum>0 and r2.clusternum>0 and r1.clusternum!=r2.clusternum:
                        # merge 'em, check all clusters up to r2 and do the merging
                        # into r1.clusternum from r2.clusternum
                        # note we waste a clusternum here
                        for k in range(0,j):
                            if fingerprints[k].clusternum==r2.clusternum:
                                fingerprints[k].clusternum=r1.clusternum
                        r2.clusternum=r1.clusternum

                    colcount += 1
                    r1r2coll=True # so we remember if there was one
                    if rec2 not in r1.rcs:
                        r1.rcs[rec2]={}
                        r1.rcs[rec2]['ip']=r2.ip
                        if r2.asn != r1.asn:
                            r1.rcs[rec2]['asn']=r2.asn
                            r1.rcs[rec2]['asndec']=r2.asndec
                        r1.rcs[rec2]['ports']=collmask('0x0',k1,k2)
                        r1.nrcs += 1
                    else: 
                        r12=r1.rcs[rec2]
                        r12['ports'] = collmask(r12['ports'],k1,k2)

                    if rec1 not in r2.rcs:
                        r2.rcs[rec1]={}
                        r2.rcs[rec1]['ip']=r1.ip
                        if r2.asn != r1.asn:
                            r2.rcs[rec1]['asn']=r1.asn
                            r2.rcs[rec1]['asndec']=r1.asndec
                        r2.rcs[rec1]['ports']=collmask('0x0',k2,k1)
                        r2.nrcs += 1
                    else: 
                        r21=r2.rcs[rec1]
                        r21['ports'] = collmask(r21['ports'],k2,k1)

        if r1r2coll==True: # so we remember if there was one
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

keyf.write(']\n')
keyf.close()

colcount=0
noncolcount=0
accumcount=0

# do clustersizes
clustersizes={}
for f in fingerprints:
    if f.clusternum in clustersizes:
        clustersizes[f.clusternum]+=1
    else:
        clustersizes[f.clusternum]=1

for f in fingerprints:
    f.csize=clustersizes[f.clusternum]

histogram={}
clusterf=open("clustersizes.csv","w")
print >>clusterf, "clusternum,size"
for c in clustersizes:
    print >> clusterf, str(c) + ", " + str(clustersizes[c])
    if clustersizes[c] in histogram:
        histogram[clustersizes[c]]= histogram[clustersizes[c]]+1
    else:
        histogram[clustersizes[c]]=1
print >>clusterf, "\n"
print >>clusterf, "clustersize,#clusters,collider"
# "collider" is y or n, so we mark the special "no-external collisions cluster" with an "n"
for h in histogram:
    if h==clustersizes[0]:
        print >> clusterf, str(h) + "," + str(histogram[h]) + ",n"
    else:
        print >> clusterf, str(h) + "," + str(histogram[h]) + ",y"
del clustersizes
clusterf.close()

colf=open('collisions.json', 'w')
colf.write('[\n')
firstone=True
mergedclusternums=[]
try:
    for f in fingerprints:
        if f.nrcs!=0:
            if f.clusternum not in mergedclusternums:
                mergedclusternums.append(f.clusternum)
            for recn in f.rcs:
                cip=f.rcs[recn]['ip']
                f.rcs[recn]['str_colls']=expandmask(f.rcs[recn]['ports'])
            bstr=jsonpickle.encode(f,unpicklable=False)
            if not firstone:
                colf.write('\n,\n')
            firstone=False
            colf.write(bstr)
            del bstr
            colcount += 1
        else:
            noncolcount += 1
        accumcount += 1
        if accumcount % 100 == 0:
            # exit early for debug purposes
            #break
            print >> sys.stderr, "Saving collisions, did: " + str(accumcount) + " found: " + str(colcount) + " IP's with remote collisions"
except Exception as e: 
    print >> sys.stderr, "Saving exception " + str(e)

# this gets crapped on each time (for now)
colf.write('\n]\n')
colf.close()
mergedclusternum=len(mergedclusternums)

del fingerprints


print >> sys.stderr, "\toverall: " + str(overallcount) + "\n\t" + \
        "good: " + str(goodcount) + "\n\t" + \
        "bad: " + str(badcount) + "\n\t" + \
        "remote collisions: " + str(colcount) + "\n\t" + \
        "no collisions: " + str(noncolcount) + "\n\t" + \
        "most collisions: " + str(mostcollisions) + " for record: " + str(biggestcollider) + "\n\t" + \
        "non-merged total clusters: " + str(clusternum) + "\n\t" + \
        "merged total clusters: " + str(mergedclusternum) 
