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

# if we assume that all the SSH host key re-uses in a cluster are due to
# those IPs really being on a single multi-homed, kosher, host, then this
# script determines if there's any remaining smelliness...

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
import binascii

codedir=os.path.dirname(os.path.realpath(__file__))
pdir=os.path.dirname(codedir)

sys.path.insert(0,pdir)
from SurveyFuncs import *

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a confirmation scan of ssh key hashes')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of collisions')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json results (one per line)')
args=parser.parse_args()

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> [-o <putfile>]"
    sys.exit(1)

if args.infile is None:
    usage()

# checks - can we read/write 
if not os.access(args.infile,os.R_OK):
    print >> sys.stderr, "Can't read input file " + args.infile + " - exiting"
    sys.exit(1)
if args.outfile is not None and os.path.isfile(args.outfile) and not os.access(args.outfile,os.W_OK):
    print >> sys.stderr, "Can't write to output file " + args.outfile + " - exiting"
    sys.exit(1)

if args.outfile is not None:
    out_f=open(args.outfile,"a")
else:
    out_f=sys.stdout

#print >>out_f, "Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time()))

# mainline processing

fp=open(args.infile,"r")

# for this, a "host" is the set of IPs with the same SSH host key
# the value here is the SSH host key FP
hosts={}

# the asns for the IP addresses are recorded, >1 means smelly 
asns={}
asnsmelly=False

# smelly is True if some host found and something not on that one host too
ipwithnossh=0
ipwithssh=0

ipcount=0
hostcount=0
f=getnextfprint(fp)
while f:
    ipcount+=1
    ip=f.ip
    if 'p22' not in f.fprints:
        #print >>out_f, "no SSH for " + f.ip
        ipwithnossh+=1
    else:
        ipwithssh+=1
        #print >>out_f, "SSH FP for " + f.ip + " is: " + f.fprints['p22']
        if f.fprints['p22'] in hosts:
            #print >>out_f, "saw that already"
            hosts[f.fprints['p22']]=hosts[f.fprints['p22']]+1 
        else:
            #print >>out_f, "new host"
            hosts[f.fprints['p22']]=1
    if f.asndec not in asns:
        asns[f.asndec]=1
    else:
        asns[f.asndec]= asns[f.asndec]+1
    f=getnextfprint(fp)

#print hosts
#print asns

# overall smelliness
smelly=False

if ipwithnossh>0 and len(hosts) > 0 :
    print  >>out_f, args.infile + " (" + str(ipcount) + ") is Mixed smelly as we see " + str(ipwithnossh) + " IPs with no SSH and " + str(ipcount-ipwithnossh) + " with"
    smelly=True

if len(asns) != 1:
    print  >>out_f, args.infile + " (" + str(ipcount) + ") is AS smelly with " +str(len(asns)) + " ASes "
    smelly=True

if ipcount and len(hosts) >1 :
    print  >>out_f, args.infile + " (" + str(ipcount) + ") is SSH smelly with " +str(len(hosts)) + " FPs "
    smelly=True

if smelly:
    print >>out_f,  args.infile + " (" + str(ipcount) + ") General smelly flag "
    for fp in hosts:
        print >>out_f,  args.infile + " (" + str(ipcount) + ") SSH " + fp + " is seen " + str(hosts[fp]) + " times "
    for asn in asns:
        print >>out_f,  args.infile + " (" + str(ipcount) + ") ASN " + str(asn) + " is seen " + str(asns[asn]) + " times "

if not smelly and len(hosts)==1 and len(asns)==1 and ipwithnossh==0 :
    thefp=''
    for fp in hosts:
        thefp=fp
    theasn=0
    for asn in asns:
        theasn=asns[asn]
    print >>out_f,  args.infile + " (" + str(ipcount) + ") Possible Multi-Homed-Host with FP " + thefp + " in ASN " + str(theasn)

#print >>out_f, "Ran ",sys.argv[0:]," finished at ",time.asctime(time.localtime(time.time()))

if args.outfile:
    out_f.close()
