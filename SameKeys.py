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
    __slots__ = ['ip_record','ip','asn','amazon','fprints','nsrc','rcs']
    def __init__(self):
        self.ip_record=-1
        self.ip=''
        self.asn=''
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
        # kind of fronting
        try:
            asn=j_content['autonomous_system']['name'].lower()
            if "amazon" in asn:
                thisone.amazon=True
            thisone.asn=asn
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
# compact form, we have five ports to consider 22,25,143,443 and 993
# and 25==25 is diferent from 25==143
# we use five octets, one for each local port;
# values are bitmasks, a set bit means the key on the remote
# port is the same as this one, so octet values can be:
# 0x00 no match
# 0x02 local port matches remote p25
# 0x06 local port matches remote p25 and p143
# etc
def portindex(p):
    pind=-1
    if k1=='p22':
        pind=0
    elif k1=='p25':
        pind=1
    elif k1=='p143':
        pind=2
    elif k1=='p443':
        pind=3
    elif k1=='p993':
        pind=4
    else:
        print >>sys.stderr, "Error - unknown port: " + k1
        sys.exit(-1)
    return pind

def collmask(mask,k1,k2):
    lp=portindex(k1)
    rp=portindex(k2)
    intmask=int(mask,16)
    intmask |= (1<<rp) * (lp*256)
    mask="0x%x" % intmask
    return mask

# this gets crapped on each time (for now)
keyf=open('all-key-fingerprints.json', 'w')
keyf.write("[\n");

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
                        if r1.asn != r1.asn:
                            r1.rcs[rec2]['asn']=r2.asn
                        r1.rcs[rec2]['ports']=collmask('0x00',k1,k2)
                        colcount += 1
                        r1r2coll=True # so we remember if there was one
                    else: 
                        r12=r1.rcs[rec2]
                        r12['ports'] = collmask(r12['ports'],k1,k2)
                        colcount += 1
                        r1r2coll=True # so we remember if there was one
                    if rec1 not in r2.rcs:
                        r2.rcs[rec1]={}
                        r2.rcs[rec1]['ip']=r1.ip
                        if r1.asn != r1.asn:
                            r2.rcs[rec1]['asn']=r1.asn
                        r2.rcs[rec1]['ports']=collmask('0x00',k2,k1)
                    else: 
                        r21=r2.rcs[rec1]
                        r21['ports'] = collmask(r21['ports'],k2,k1)
        if r1r2coll==True: # so we remember if there was one
            r1.nrcs += 1
            r2.nrcs += 1
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
accumcount=0
amazcolcount=0
amaznoncolcount=0
nonamazcolcount=0
nonamaznoncolcount=0

colf=open('collisions.json', 'w')
colf.write('[\n')
nas=open('non-amazons.json', 'w')
nas.write('[\n')
for f in fingerprints:
    if f.nrcs!=0:
        #collisions.append(f)
        bstr=jsonpickle.encode(f,unpicklable=False)
        colf.write(bstr + '\n')
        del bstr
        colcount += 1
        if f.amazon==True:
            amazcolcount += 1
        else:
            #print "non-amazon remote collision, asn: " + f['asn'] + " ip: " + f['ip']
            #nonamazons.append(f)
            bstr=jsonpickle.encode(f,unpicklable=False)
            nas.write(bstr + '\n')
            del bstr
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
colf.write('\n')
colf.close()

# let's look at non-amazon collisions
nas.write('\n')
nas.close()

print >> sys.stderr, "\toverall: " + str(overallcount) + "\n\t" + \
        "good: " + str(goodcount) + "\n\t" + \
        "bad: " + str(badcount) + "\n\t" + \
        "remote collisions: " + str(colcount) + "\n\t" + \
        "amazon collisions: " + str(amazcolcount) +"\n\t" +  \
        "non-amazon collisions: " + str(nonamazcolcount) + "\n\t" + \
        "amazon non-collisions: " + str(amaznoncolcount) + "\n\t" + \
        "non-amazon non-collisions: " + str(nonamaznoncolcount) + \
        "\n"
