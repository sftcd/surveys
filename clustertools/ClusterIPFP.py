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

# print just the IP and fp's for a cluster 

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
    print "print just the IP and fp's for a cluster"
    print 'usage: ' + sys.argv[0] + ' [-p port]  -i <cluster-file>'
    print '   port defaults to all, can be csv list of ports e.g. "443,22"'
    sys.exit(99)

# command line arg handling 
parser=argparse.ArgumentParser(description='print just the IP and fp\'s for a cluster')
parser.add_argument('-i','--infiles',     
                    dest='fnames',
                    help='cluster json file names (space sep)')
parser.add_argument('-p','--portcsv',     
                    dest='portcsv',
                    help='comma separated list of port numbers, or "all"')
args=parser.parse_args()

portcsv='all'
ports2do=portstrings
if args.portcsv is not None and args.portcsv != 'all':
    ports2do=[]
    for pnum in args.portcsv.split(","):
        port='p'+pnum
        if port not in portstrings:
            print "Bad port csv: "+str(args.portcsv)
            print "    only  22, 25, 110, 143, 443, 587, 993  allowed"
            sys.exit(1)
        ports2do.append(port)
        
    
if args.fnames is None:
    usage()
    sys.exit(2)

# main line processing ...


checkcount=0

for fname in args.fnames.split():
    print "Starting " + fname + " for " + str(ports2do)
    print >>sys.stderr, "Reading " + fname

    # open file
    #print fname
    fp=open(fname,"r")
    #print fp

    f=getnextfprint(fp)
    #print f
    while f:

        try:
            print "IP: " + f.ip + " fingerprints:" 
            for port in ports2do:
                if port in f.fprints:
                    print "\t",port, f.fprints[port]

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

