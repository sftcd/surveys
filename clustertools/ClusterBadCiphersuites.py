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

# Count up the keys that are (a) re-used and (b) use RSA key transport

import sys
import os
import tempfile
import gc
import copy
import argparse
import datetime
import pytz # for adding back TZ info to allow comparisons

import time
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import binascii

from pympler import asizeof

codedir=os.path.dirname(os.path.realpath(__file__))
pdir=os.path.dirname(codedir)

sys.path.insert(0,pdir)
from SurveyFuncs import *

def usage():
    print 'Count up the keys that are (a) re-used and (b) use RSA key transport'
    print 'usage: ' + sys.argv[0] + ' -i <space separated list of cluster files>'
    sys.exit(99)

# command line arg handling 
parser=argparse.ArgumentParser(description='Anonymise all the IP addresses that don\'t belong to the given AS for the set of cluster files given')
parser.add_argument('-i','--infiles',     
                    dest='fnames',
                    help='space separated list of file names')
args=parser.parse_args()

if args.fnames is None:
    usage()
    sys.exit(2)

# main line processing ...

print "Starting"

# this file comes from https://testssl.sh/mapping-rfc.txt, which is GPL
cslistfile=os.path.dirname(os.path.realpath(__file__))+"/mapping-rfc.txt"
if not os.path.exists(cslistfile):
    print "Can't open " + cslistfile
    sys.exit(1)

csinfo={}

# load ciphersuites into structure - we're *vary* lenient here
# we really only mark as "bad" things that are screamingly bad
# or that are badly affected by key re-use, which is mainly
# RSA key transport
def loadcs():
    if len(csinfo) > 0:
        print "Done already"
        return
    try:
        fp=open(cslistfile,"r")
        for line in fp:
            larr=line.split('  ')
            csdec=int(larr[0][1:],16)
            csname=larr[1].strip()
            bad=csname.startswith("TLS_RSA")
            if not bad:
                bad=csname.startswith("SSL_")
            if not bad:
                bad=csname.startswith("TLS_PSK")
            if "NULL" in csname:
                bad=True
            if "EXPORT" in csname:
                bad=True
            if "anon" in csname:
                bad=True
            if "_DES_" in csname:
                bad=True
            if "RC4" in csname:
                bad=True
            # oddballs
            if "EMPTY" in csname:
                bad=True
            if "FALLBACK" in csname:
                bad=True
            if "SRP" in csname:
                bad=True
            if "KRB" in csname:
                bad=True
            csinfo[csdec]={"isbad": bad,"name": csname}
        fp.close()
    except:
        print "Error loading " + cslistfile + " - exiting"
        sys.exit(2)

loadcs()

def okcs(cs):
    try:
        if csinfo[cs]['isbad']:
            return False
        else:
            return True
    except:
        return False

def pcsinfo():
    print "Bad list"
    for cs in csinfo:
        if csinfo[cs]["isbad"]==True:
            print str(cs) + " " + csinfo[cs]['name']
    print "ok list"
    for cs in csinfo:
        if csinfo[cs]["isbad"]==False:
            print str(cs) + " " + csinfo[cs]['name']

# pcsinfo()

# we need to pass over all the fingerprints and try get the
# cert for each one

checkcount=0

# it's bad if the cs is bad and the key is re-used somewhere
# count each key in two ways - count unique key with bad cs (cuk) and
# as count of all uses (coau) with bad cs
cuk=0
coau=0
# to do cuk we need to remember
fpswithbadcs=[]
dodgycses={}

for fname in args.fnames.split():
    print "Reading " + fname

    # open file
    fp=open(fname,"r")

    jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
    f=getnextfprint(fp)
    while f:

        try:
            goody=True
            for port in portstrings:
                #print "Checking " + port
                if port == "p22":
                    continue
                if port in f.analysis:
                    if 'cipher_suite' in f.analysis[port]:
                        goody=okcs(f.analysis[port]["cipher_suite"])
                        if not goody:
                            cs=f.analysis[port]["cipher_suite"]
                            #print "cs=" + str(cs) + " goody=" + str(goody) + " for: " + f.ip
                            # now is that particular key being re-used?
                            for recn in f.rcs:
                                if port+"==" in f.rcs[recn]['str_colls']:
                                    coau += 1
                                    if f.fprints[port] not in fpswithbadcs:
                                        cuk += 1
                                        fpswithbadcs.append(f.fprints[port])
                                    if cs in dodgycses:
                                        dodgycses[cs] += 1
                                    else: 
                                        dodgycses[cs] = 0
                                    #print dodgycses
                                    

        except Exception as e: 
            print "Error with " + f.ip + " " + str(e)
            pass

        # print something now and then to keep operator amused
        checkcount += 1
        if checkcount % 100 == 0:
            print >> sys.stderr, "Counting bad ciphersuite uses, fingerprint: " + str(checkcount) 
        if checkcount % 1000 == 0:
            gc.collect()

        # read next fp
        f=getnextfprint(fp)

    # close file
    fp.close()

print "Overall:" + str(checkcount) + "\n" + "cuks: " + str(cuk) + "\n" + "coau: " + str(coau)
for cs in dodgycses:
    print csinfo[cs]['name'] + " occurs " + str(dodgycses[cs]) +  " times"
