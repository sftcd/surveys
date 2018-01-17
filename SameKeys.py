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

        fp=''
        try:
            fp=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone['fprints']['p25']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        fp=''
        try:
            fp=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone['fprints']['p143']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        fp=''
        try:
            fp=j_content['p443']['https']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone['fprints']['p443']=fp
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        fp=''
        try:
            fp=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256']
            thisone['fprints']['p993']=fp
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

# add info about remote collision
def addcoll(thetype,l1,k1,l2,k2):
    try:
        rc=l1[thetype]
    except:
        l1[thetype]={}
    rc=l1[thetype]
    try:
        rcr=rc[l2['record']]
    except:
        rcr=rc[l2['record']]={}
    rcr=rc[l2['record']]
    try:
        kc=rcr[k1]
    except:
        rcr[k1]=[]
    kc=rcr[k1]
    if k2 not in kc:
        kc.append(k2)

# check if common fingeprints found
def commonfps(l1,l2,local):
    foundone=False
    for k1 in l1['fprints']:
        for k2 in l2['fprints']:
            if k1!=k2 or not local:
                if l1['fprints'][k1]==l2['fprints'][k2]:
                    #mstr=str(l1['record']) + ":" + k1 + "==" + str(l2['record']) + ":" + k2
                    #print >> sys.stderr, "Remote collision!!! " + mstr
                    if local:
                        addcoll("local_collisions",l2,k2,l1,k1)
                        foundone=True
                    else:
                        addcoll("remote_collisions",l1,k1,l2,k2)
                        addcoll("remote_collisions",l2,k2,l1,k1)
                        foundone=True
    return foundone

checkcount=0
colcount=0
# loop over fingerprints to see who's sharing
for f1 in fingerprints:
    for f2 in fingerprints:
        if f1==f2: # within-host sharing
            local_shared=commonfps(f1,f2,True)
        else: # super-dodgy between-host sharing
            remote_shared=commonfps(f1,f2,False)
            if remote_shared:
                #print "Found a collision between " + f1['ip'] + "/" + str(f1['record']) + " and " + f2['ip'] + "/" + str(f2['record']) 
                colcount += 1
    checkcount += 1
    if checkcount % 100 == 0:
        # exit early for debug purposes
        #break
        print >> sys.stderr, "Checking colissions, did: " + str(checkcount) + " found: " + str(colcount) + " remote collisions"

colcount=0
accumcount=0
collisions=[]
for f in fingerprints:
    if 'remote_collisions' in f:
        collisions.append(f)
        colcount += 1
    accumcount += 1
    if accumcount % 100 == 0:
        # exit early for debug purposes
        #break
        print >> sys.stderr, "Accumulating colissions, did: " + str(accumcount) + " found: " + str(colcount) + " IP's with remote collisions"

# this gets crapped on each time (for now)
keyf=open('all-key-fingerprints.json', 'w')
keyf.write(json.dumps(fingerprints) + '\n')
keyf.close()

# this gets crapped on each time (for now)
colf=open('collisions.json', 'w')
colf.write(json.dumps(collisions) + '\n')
colf.close()


# this gets crapped on each time (for now)
# in this case, these are the hosts with no crypto anywhere (except
# maybe on p22)
badf=open('dodgy.json', 'w')
badf.write(json.dumps(bads) + '\n')
badf.close()

print >> sys.stderr, "overall: " + str(overallcount) + \
        " good: " + str(goodcount) + \
        " bad: " + str(badcount) + \
        " remote collisions: " + str(colcount) + \
        "\n"
