#!/usr/bin/python

# check who's re-using the same keys 
# CensysIESMTP.py

# TODO: figure out if we have a commensurate ssh fingerprint
# TODO: figure out if we can get port 587 ever

import sys
import json
import gc

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle


class OneFP():
    __slots__ = ['record','ip','asn','amazon','fprints','rcs']
    def __init__(self):
        self.record=-1
        self.ip=''
        self.asn=''
        self.amazon=False
        self.fprints={}
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
        thisone.record=overallcount
        thisone.ip=j_content['ip']

        # amazon is the chief susspect for key sharing, via some 
        # kind of fronting
        try:
            asn=j_content['autonomous_system']['name'].lower()
            if "amazon" in asn:
                thisone.amazon=True
            thisone.asn=asn
        except:
            thisone.asn="unknown"

        try:
            fp=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['subject_key_info']['fingerprint_sha256'] 
            thisone.fprints['p25']=fp
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
keyf.write("\n")
keyf.close()

checkcount=0
colcount=0

fl=len(fingerprints)
for i in range(0,fl):
    r1=fingerprints[i]
    rec1=r1.record
    for j in range (i+1,fl):
        r2=fingerprints[j]
        rec2=r2.record
        for k1 in r1.fprints:
            for k2 in r2.fprints:
                if r1.fprints[k1]==r2.fprints[k2]:
                    if rec2 not in r1.rcs:
                       r1.rcs[rec2]={}
                    r12=r1.rcs[rec2]
                    r12['ip']=r2.ip
                    r12['asn']=r2.asn
                    if k1 not in r12:
                        r12[k1]=[]
                    if k2 not in r12[k1]:
                        r12[k1].append(k2)
                        colcount += 1
                    if rec1 not in r2.rcs:
                        r2.rcs[rec1]={}
                    r21=r2.rcs[rec1]
                    r21['ip']=r1.ip
                    r21['asn']=r1.asn
                    if k2 not in r21:
                        r21[k2]=[]
                    if k1 not in r21[k2]:
                        r21[k2].append(k1)
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Checking colisions, did: " + str(checkcount) + " found: " + str(colcount) + " remote collisions"
    if checkcount % 1000 == 0:
        gc.collect()

# this gets crapped on each time (for now)
keyf=open('all-key-fingerprints.json', 'w')
bstr=jsonpickle.encode(fingerprints,unpicklable=False)
keyf.write(bstr + '\n')
keyf.close()

colcount=0
accumcount=0
collisions=[]
amazcolcount=0
nonamazons=[]
amaznoncolcount=0
nonamazcolcount=0
nonamaznoncolcount=0

for f in fingerprints:
    if f.rcs:
        collisions.append(f)
        colcount += 1
        if f.amazon==True:
            amazcolcount += 1
        else:
            #print "non-amazon remote collision, asn: " + f['asn'] + " ip: " + f['ip']
            nonamazons.append(f)
            nonamazcolcount += 1
    else:
        if f.amazon==True:
            amaznoncolcount += 1 
        else:
            nonamaznoncolcount += 1
    accumcount += 1
    if accumcount % 100 == 0:
        # exit early for debug purposes
        #break
        print >> sys.stderr, "Accumulating colissions, did: " + str(accumcount) + " found: " + str(colcount) + " IP's with remote collisions"

del fingerprints

# this gets crapped on each time (for now)
colf=open('collisions.json', 'w')
bstr=jsonpickle.encode(collisions,unpicklable=False)
colf.write(bstr + '\n')
colf.close()

del collisions

# let's look at non-amazon collisions
nas=open('non-amazons.json', 'w')
bstr=jsonpickle.encode(nonamazons,unpicklable=False)
nas.write(bstr + '\n')
nas.close()

del nonamazons

# this gets crapped on each time (for now)
# in this case, these are the hosts with no crypto anywhere (except
# maybe on p22)
badf=open('dodgy.json', 'w')
bstr=jsonpickle.encode(bads,unpicklable=False)
badf.write(bstr + '\n')
badf.close()

print >> sys.stderr, "\toverall: " + str(overallcount) + "\n\t" + \
        "good: " + str(goodcount) + "\n\t" + \
        "bad: " + str(badcount) + "\n\t" + \
        "remote collisions: " + str(colcount) + "\n\t" + \
        "amazon collisions: " + str(amazcolcount) +"\n\t" +  \
        "non-amazon collisions: " + str(nonamazcolcount) + "\n\t" + \
        "amazon non-collisions: " + str(amaznoncolcount) + "\n\t" + \
        "non-amazon non-collisions: " + str(nonamaznoncolcount) + \
        "\n"
