#!/usr/bin/python

# check what kind of keys are in use
# CensysIESMTP.py

# TODO: figure out if we have a commensurate ssh fingerprint
# TODO: figure out if we can get port 587 ever

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

bads={}
ktcounts={'rsa':0,'dsa':0,'ecc':0}
rsalengths={}
rsamoduli={}
p25ciphersuites={}
p443ciphersuites={}
p143ciphersuites={}
p993ciphersuites={}

def countkeytype(spki,ktcounts):
    if 'rsa_public_key' in spki and spki['rsa_public_key']:
        ktcounts['rsa'] += 1
        klen=spki['rsa_public_key']['length']
        rsalengths[klen]=rsalengths.get(klen,0) + 1
        kmod=spki['rsa_public_key']['modulus']
        rsamoduli[kmod]=rsamoduli.get(kmod,0) + 1
    if 'ecdsa_public_key' in spki and spki['ecdsa_public_key']:
        ktcounts['ecc'] += 1
    if 'dsa_public_key' in spki and spki['dsa_public_key']:
        ktcounts['dsa'] += 1
    return

def countciphersuites(c,name):
    c["total"] = c.get("total",0) + 1
    c[name] = c.get(name,0) + 1

with open(sys.argv[1],'r') as f:
    overallcount=0
    badcount=0
    goodcount=0
    for line in f:
        j_content = json.loads(line)
        somekey=False
        try:
            skpi=j_content['p25']['smtp']['starttls']['tls']['certificate']['parsed']['subject_key_info']
            countkeytype(spki,ktcounts)
            ciphersuite=j_content['p25']['smtp']['starttls']['tls']['cipher_suite']['name']
            countciphersuites(p25ciphersuites,ciphersuite)
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            spki=j_content['p143']['imap']['starttls']['tls']['certificate']['parsed']['subject_key_info']
            countkeytype(spki,ktcounts)
            ciphersuite=j_content['p143']['imap']['starttls']['tls']['cipher_suite']['name']
            countciphersuites(p143ciphersuites,ciphersuite)
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            spki=j_content['p443']['https']['tls']['certificate']['parsed']['subject_key_info']
            countkeytype(spki,ktcounts)
            ciphersuite=j_content['p443']['https']['tls']['cipher_suite']['name']
            countciphersuites(p443ciphersuites,ciphersuite)
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass
        try:
            spki=j_content['p993']['imaps']['tls']['tls']['certificate']['parsed']['subject_key_info']
            countkeytype(spki,ktcounts)
            ciphersuite=j_content['p993']['imaps']['tls']['tls']['cipher_suite']['name']
            countciphersuites(p993ciphersuites,ciphersuite)
            somekey=True
        except Exception as e: 
            #print >> sys.stderr, "fprint exception " + str(e)
            pass

        if somekey:
            goodcount += 1
        else:
            bads[badcount]=j_content
            badcount += 1
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print >> sys.stderr, "Reading keys, did: " + str(overallcount)

# this gets crapped on each time (for now)
# in this case, these are the hosts with no crypto anywhere (except
# maybe on p22)
badf=open('dodgy.json', 'w')
badf.write(json.dumps(bads) + '\n')
badf.close()

print >> sys.stderr, "overall: " + str(overallcount) + \
        " good: " + str(goodcount) + \
        " bad: " + str(badcount) + \
        " keytpes: " + str(ktcounts) 
print "rsa lengths: " + json.dumps(rsalengths)
print "unique moduli: " + str(len(rsamoduli))
#print "rsa moduli: " + json.dumps(rsamoduli)
print "p25ciphersuites: " + json.dumps(p25ciphersuites,indent=2)
print "p143ciphersuites: " + json.dumps(p143ciphersuites,indent=2)
print "p443ciphersuites: " + json.dumps(p443ciphersuites,indent=2)
print "p993ciphersuites: " + json.dumps(p993ciphersuites,indent=2)
