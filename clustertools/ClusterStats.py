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

# Count values for cluster that we report on in tablular form:
# Cluster 		
# Graph		
# IPs 	
# ASes 		
# AS type(s) 	
# Crypto Ports 
# SSH ports
# SSH keys
# TLS ports
# TLS keys 
# BT certs
# WC certs
# Max Key Use  
# Since..

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
    print 'Generate some cluster stats'
    print 'usage: ' + sys.argv[0] + ' -i <filename>'
    sys.exit(99)

# command line arg handling 
parser=argparse.ArgumentParser(description='Generate some cluster stats')
parser.add_argument('-i','--infile',     
                    dest='fname',
                    help='cluster file name')
args=parser.parse_args()

if args.fname is None:
    usage()
    sys.exit(2)

# main line processing ...


checkcount=0

fname = args.fname
print >>sys.stderr, "Reading " + fname

asns=set()
sshkeys=set()
tlskeys=set()
fpsseen={}

portcount=0
sshports=0
tlsports=0
btcerts=0
wccerts=0



# open file
fp=open(fname,"r")
if fp:
    f=getnextfprint(fp)
    print 'ClusterNumber:' + str(f.clusternum)
    print 'ClusterSize:' + str(f.csize)
    while f:

        try:
            asns.add(f.asndec)

            for port in f.fprints:
                if f.fprints[port] in fpsseen:
                    fpsseen[f.fprints[port]] += 1
                else:
                    fpsseen[f.fprints[port]] = 1
                portcount+=1
                if port == 'p22':
                    sshports+=1
                    sshkeys.add(f.fprints['p22'])
                else:
                    tlsports+=1
                    tlskeys.add(f.fprints[port])
                    somewc=False
                    if f.analysis[port]['browser_trusted']:
                        btcerts+=1
                        # wild cards must be btowser-trusted to be counted
                        if port+'dn' in f.analysis['nameset']:
                            if '*' in f.analysis['nameset'][port+'dn']:
                                somewc=True
                            sanind=0
                            while port+'san'+str(sanind) in f.analysis['nameset']:
                                if '*' in f.analysis['nameset'][port+'san'+str(sanind)]:
                                    somewc=True
                                sanind+=1
                    if somewc:
                        wccerts+=1


        except Exception as e: 
            print "Error with " + f.ip + " " + str(e)
            pass

        # print something now and then to keep operator amused
        checkcount += 1
        if checkcount % 100 == 0:
            print >> sys.stderr, "Counting browser-trusted stuff, host: " + str(checkcount) 
        if checkcount % 1000 == 0:
            gc.collect()

        # read next fp
        f=getnextfprint(fp)

# close file
fp.close()

mostcommonkey=0
mcfp=''
for fp in fpsseen:
    if fpsseen[fp] > mostcommonkey:
        mostcommonkey=fpsseen[fp]
        mcfp=fp

kdiff = len(fpsseen)-(len(sshkeys)+len(tlskeys)) 
if kdiff != 0:
    print "odd #2keys, all=" + str(len(fpsseen)) + " ssh="+str(len(sshkeys))+ " tls="+str(len(tlskeys)) + " diff="+str(kdiff)


print "ASes: " + str(len(asns))
print "ASTypes: TBD " 
print "Ports: " + str(portcount)
print "SSHPorts: " +str(sshports)
print "SSHKeys : " +str(len(sshkeys))
print "TLSPorts: " +str(tlsports)
print "TLSKeys : " +str(len(tlskeys))
print "BTCerts : " +str(btcerts)
print "WCCerts : " +str(wccerts)
print "MaaxKey: " + str(mostcommonkey)
print "Since: TBD"

print >>sys.stderr, "Overall:" + str(checkcount) 
