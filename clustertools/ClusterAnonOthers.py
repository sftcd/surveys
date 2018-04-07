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

# Anonymise all the IP addresses that don't belong to the given AS
# for the set of cluster files given
# Note that this will modify the input files given

# This is to handle cases where we send a tarball to an AS asset-holder that
# involves >1 ASN - we zap the names and IP addresses for other ASNs that
# are mentioned. We do leave the fingerprints, and ASNs.

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
    print 'Anonymise all the IP addresses that don\'t belong to the given AS for the set of cluster files given'
    print 'usage: ' + sys.argv[0] + ' -a <asn> -i <space separated list of cluster files>'
    sys.exit(99)

# command line arg handling 
parser=argparse.ArgumentParser(description='Anonymise all the IP addresses that don\'t belong to the given AS for the set of cluster files given')
parser.add_argument('-i','--infiles',     
                    dest='fnames',
                    help='space separated list of file names')
parser.add_argument('-a','--asn',     
                    dest='asn',
                    help='the AS Number that doesn\'t need to be anonymised')
args=parser.parse_args()

if args.asn is None:
    usage()
    sys.exit(1)
if args.fnames is None:
    usage()
    sys.exit(2)

# main line processing ...

# we need to pass over all the fingerprints and try get the
# cert for each one

theASN=int(args.asn)
checkcount=0

fpstowrite=[]

for fname in args.fnames.split(' '):
    print "Reading " + fname

    # open file
    fp=open(fname,"r")


    jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
    f=getnextfprint(fp)
    while f:

        if f.asndec != theASN:
            #print "Do something about " + f.ip + " ASN: " + f.asn
            f.ip="XXX.XXX.XXX.XXX"
            f.analysis["nameset"]={}
            f.analysis["nameset"]["anonymised"]=True
        else:
            #print "Do nothng about " + f.ip
            pass

        for recn in f.rcs:
            if "asndec" in f.rcs[recn] and f.rcs[recn]["asndec"] != theASN:
                #print "\t and do something about " + f.rcs[recn]["ip"] + " ASN: " + f.rcs[recn]["asn"] 
                f.rcs[recn]["ip"]="XXX.XXX.XXX.XXX"
            else:
                #print "\t but do nothing about " + f.rcs[recn]["ip"]
                pass

        # print something now and then to keep operator amused
        checkcount += 1
        if checkcount % 100 == 0:
            print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) 
        if checkcount % 1000 == 0:
            gc.collect()

        fpstowrite.append(f)

        # read next fp
        f=getnextfprint(fp)

    # close file
    fp.close()
 
    print "Writing " + fname
    out_f=open(fname,"w")
    bstr=jsonpickle.encode(fpstowrite)
    out_f.write(bstr+"\n")
    out_f.close()

