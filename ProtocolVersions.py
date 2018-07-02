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

# check the protocol versions being used 

# This goes back to records.fresh as I don't keep the versioning info
# in the fingerprint structure (TODO: add version stuff to metadata
# in FP structures)

# we'll count versions per-port overall, and for IPs that are, and
# are not, within a cluster

# for that last, an initial step is to select the IPs from the 
# dodgy.json which are those not within clusters

# GOT HERE, code below is legacy


import re, os, sys, argparse, tempfile, gc
import json
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

# our own stuff
from SurveyFuncs import *  

# default values
infile="records.fresh"
outfile="versions.tex"

# if this file exists, read it to determine if IP is (not) in some cluster
dodgyfile="dodgy.json"

# command line arg handling 
argparser=argparse.ArgumentParser(description='Count protocol versions in a run')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing output from zgrab')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put latex table')
argparser.add_argument('-d','--dodgy_file',     
                    dest='dodgy',
                    help='file in which we find non-clustered IPs')
args=argparser.parse_args()

if args.infile is not None:
    infile=args.infile

if args.outfile is not None:
    outfile=args.outfile

if args.dodgy is not None:
    dodgyfile=args.dodgy

# we won't fully decode this, just grep out the IP addresses
# do: grep '^    "ip":' dodgyfile
nonclusterips=[]
df = open(dodgyfile,"r")
for line in df:
     if re.search('^    "ip"', line):
         print line

# debug exit
sys.exit(0)

# fix up below to count versions

# encoder options
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

# keep track of how long this is taking per ip
peripaverage=0
overallcount=0
 
with open(infile,'r') as f:
    for line in f:
            ipstart=time.time()
            badrec=False
            j_content = json.loads(line)
            somekey=False
            thisone=OneFP()
            thisone.ip_record=overallcount
            thisone.ip=j_content['ip'].strip()

            for pstr in portstrings:
                thisone.analysis[pstr]={}
    
            # name from banner
            try:
                p25=j_content['p25']
                if thisone.writer=="FreshGrab.py":
                    #print p25['data']['banner']
                    banner=p25['data']['banner'] 
                else:
                    banner=p25['smtp']['starttls']['banner'] 
                ts=banner.split()
                if ts[0]=="220":
                    banner_fqdn=ts[1]
                    nameset['banner']=banner_fqdn
                elif ts[0].startswith("220-"):
                    banner_fqdn=ts[0][4:]
                    nameset['banner']=banner_fqdn
            except Exception as e: 
                #print >> sys.stderr, "FQDN banner exception " + str(e) + " for record:" + str(overallcount) + " ip:" + thisone.ip
                nameset['banner']=''
    
            try:
                if thisone.writer=="FreshGrab.py":
                    fp=j_content['p22']['data']['xssh']['key_exchange']['server_host_key']['fingerprint_sha256'] 
                    shk=j_content['p22']['data']['xssh']['key_exchange']['server_host_key']
                    if shk['algorithm']=='ssh-rsa':
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['algorithm']
                else:
                    fp=j_content['p22']['ssh']['v2']['server_host_key']['fingerprint_sha256'] 
                    shk=j_content['p22']['ssh']['v2']['server_host_key']
                    if shk['key_algorithm']=='ssh-rsa':
                        thisone.analysis['p22']['rsalen']=shk['rsa_public_key']['length']
                    else:
                        thisone.analysis['p22']['alg']=shk['key_algorithm']
                thisone.fprints['p22']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p22 exception " + str(e) + " ip:" + thisone.ip
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    tls=j_content['p25']['data']['tls']
                    cert=tls['server_certificates']['certificate']
                else:
                    tls=j_content['p25']['smtp']['starttls']['tls']
                    cert=tls['certificate']
                fp=cert['parsed']['subject_key_info']['fingerprint_sha256'] 
                get_tls(thisone.writer,'p25',tls,j_content['ip'],thisone.analysis['p25'],scandate)
                get_certnames('p25',cert,nameset)
                thisone.fprints['p25']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p25 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    cert=j_content['p110']['data']['tls']['server_certificates']['certificate']
                    fp=j_content['p110']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    get_tls(thisone.writer,'p25',j_content['p110']['data']['tls'],j_content['ip'],thisone.analysis['p110'],scandate)
                else:
                    fp=j_content['p110']['pop3']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    cert=j_content['p110']['pop3']['starttls']['tls']['certificate']
                    get_tls(thisone.writer,'p25',j_content['p110']['pop3']['starttls']['tls'],j_content['ip'],thisone.analysis['p110'],scandate)
                get_certnames('p110',cert,nameset)
                thisone.fprints['p110']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p110 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    cert=j_content['p143']['data']['tls']['server_certificates']['certificate']
                    fp=j_content['p143']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    get_tls(thisone.writer,'p143',j_content['p143']['data']['tls'],j_content['ip'],thisone.analysis['p143'],scandate)
                else:
                    cert=j_content['p143']['pop3']['starttls']['tls']['certificate']
                    fp=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
                    get_tls(thisone.writer,'p143',j_content['p143']['imap']['starttls']['tls'],j_content['ip'],thisone.analysis['p143'],scandate)
                get_certnames('p143',cert,nameset)
                thisone.fprints['p143']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p143 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    fp=j_content['p443']['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    cert=j_content['p443']['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']
                    get_tls(thisone.writer,'p443',j_content['p443']['data']['http']['response']['request']['tls_handshake'],j_content['ip'],thisone.analysis['p443'],scandate)
                else:
                    fp=j_content['p443']['https']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
                    cert=j_content['p443']['https']['tls']['certificate']
                    get_tls(thisone.writer,'p443',j_content['p443']['https']['tls'],j_content['ip'],thisone.analysis['p443'],scandate)
                get_certnames('p443',cert,nameset)
                thisone.fprints['p443']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p443 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    fp=j_content['p587']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    cert=j_content['p587']['data']['tls']['server_certificates']['certificate']
                    get_tls(thisone.writer,'p587',j_content['p587']['data']['tls'],j_content['ip'],thisone.analysis['p587'],scandate)
                    somekey=True
                    get_certnames('p587',cert,nameset)
                    thisone.fprints['p587']=fp
                else:
                    # censys.io has no p587 for now
                    pass
            except Exception as e: 
                #print >> sys.stderr, "p587 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            try:
                if thisone.writer=="FreshGrab.py":
                    fp=j_content['p993']['data']['tls']['server_certificates']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
                    cert=j_content['p993']['data']['tls']['server_certificates']['certificate']
                    get_tls(thisone.writer,'p993',j_content['p993']['data']['tls'],j_content['ip'],thisone.analysis['p993'],scandate)
                else:
                    fp=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
                    cert=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']
                    get_tls(thisone.writer,'p993',j_content['p993']['imaps']['tls']['tls'],j_content['ip'],thisone.analysis['p993'],scandate)
                get_certnames('p993',cert,nameset)
                thisone.fprints['p993']=fp
                somekey=True
            except Exception as e: 
                #print >> sys.stderr, "p993 exception for:" + thisone.ip + ":" + str(e)
                pass
    
            besty=[]
            nogood=True # assume none are good
            tmp={}
            # try verify names a bit
            for k in nameset:
                v=nameset[k]
                #print "checking: " + k + " " + v
                # see if we can verify the value as matching our give IP
                if v != '' and not fqdn_bogon(v):
                    try:
                        rip=socket.gethostbyname(v)
                        if rip == thisone.ip:
                            besty.append(k)
                        else:
                            tmp[k+'-ip']=rip
                        # some name has an IP, even if not what we expect
                        nogood=False
                    except Exception as e: 
                        #oddly, an NXDOMAIN seems to cause an exception, so these happen
                        #print >> sys.stderr, "Error making DNS query for " + v + " for ip:" + thisone.ip + " " + str(e)
                        pass
            for k in tmp:
                nameset[k]=tmp[k]
            nameset['allbad']=nogood
            nameset['besty']=besty
    
            if not badrec and somekey:
                goodcount += 1
                fingerprints.append(thisone)
            else:
                bads[badcount]=j_content
                badcount += 1
            overallcount += 1
    
            # update average
            ipend=time.time()
            thistime=ipend-ipstart
            peripaverage=((overallcount*peripaverage)+thistime)/(overallcount+1)
            if overallcount % 5 == 0:
                print >> sys.stderr, "Reading fingerprints and rdns, did: " + str(overallcount) + \
                        " most recent ip " + thisone.ip + \
                        " average time/ip: " + str(peripaverage) \
                        + " last time: " + str(thistime)
            del j_content
            del thisone
    f.close()
    gc.collect()
    
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
    
    
    
    # this gets crapped on each time (for now)
    keyf=open('all-key-fingerprints.json', 'w')
    keyf.write("[\n");
    
# end of fpfile is not None
checkcount=0
colcount=0

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
    if args.fpfile is None:
        bstr=jsonpickle.encode(r1,unpicklable=False)
        keyf.write(bstr + ',\n')
        del bstr
    checkcount += 1

    if checkcount % 100 == 0:
        print >> sys.stderr, "Checking colisions, did: " + str(checkcount) + " found: " + str(colcount) + " remote collisions"

    if checkcount % 1000 == 0:
        gc.collect()

if args.fpfile is None:
    keyf.write(']\n')
    keyf.close()

colcount=0
noncolcount=0
accumcount=0

# do clustersizes
clustersizes={}
clustersizes[0]=0
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

colf=open(outfile, 'w')
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
        "merged total clusters: " + str(mergedclusternum) + "\n\t" + \
        "Scandate used is: " + str(scandate)
