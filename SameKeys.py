#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# TODO: figure out if we have a commensurate ssh fingerprint
# TODO: figure out if we can get port 587 ever

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons


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
        thisone={}
        thisone['record']=overallcount
        thisone['ip']=j_content['ip']
        thisone['fprints']={}
        thisone['local_collisions']=[]
        thisone['remote_collisions']=[]

        try:
            fp=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['spki_subject_fingerprint'] 
            thisone['fprints']['p25']=fp
            somekey=True
        except Exception as e: 
            print >> sys.stderr, "fprint exception " + str(e)
        try:
            fp=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['spki_subject_fingerprint'] 
            thisone['fprints']['p143']=fp
            somekey=True
        except Exception as e: 
            print >> sys.stderr, "fprint exception " + str(e)
        try:
            fp=j_content['p443']['https']['tls']['certificate']['parsed']['spki_subject_fingerprint'] 
            thisone['fprints']['p443']=fp
            somekey=True
        except Exception as e: 
            print >> sys.stderr, "fprint exception " + str(e)
        try:
            fp=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['spki_subject_fingerprint'] 
            thisone['fprints']['p993']=fp
            somekey=True
        except Exception as e: 
            print >> sys.stderr, "fprint exception " + str(e)

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
            print >> sys.stderr, "Did : " + str(overallcount)

# check if common fingeprints found
def commonfps(l1,l2,local):
    for k1 in l1['fprints']:
        for k2 in l2['fprints']:
            if k1!=k2 or not local:
                if l1['fprints'][k1]==l2['fprints'][k2]:
                    mstr=str(l1['record']) + ":" + k1 + "==" + str(l2['record']) + ":" + k2
                    if local:
                        l1['local_collisions'].append(mstr)
                    else:
                        print >> sys.stderr, "Remote collision!!! " + mstr
                        l1['remote_collisions'].append(mstr)
                        l2['remote_collisions'].append(mstr)


# loop over fingerprints to see who's sharing
for f1 in fingerprints:
    for f2 in fingerprints:
        if f1==f2: # within-host sharing
            local_shared=commonfps(f1,f2,True)
        else: # super-dodgy between-host sharing
            remote_shared=commonfps(f1,f2,False)

# this gets crapped on each time (for now)
keyf=open('key-fingerprints.json', 'w')
keyf.write(json.dumps(fingerprints) + '\n')
keyf.close()

# this gets crapped on each time (for now)
# in this case, these are the hosts with no crypto anywhere (except
# maybe on p22)
badf=open('dodgy.json', 'w')
badf.write(json.dumps(bads) + '\n')
badf.close()

print >> sys.stderr, "overall: " + str(overallcount) + " good: " + str(goodcount) + " bad: " + str(badcount) + "\n"
