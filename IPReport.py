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

# Extended sorta-peronalised Report about a set of IPs

import sys
import os
import tempfile
import gc, re
import copy
import argparse
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

from pympler import asizeof

from SurveyFuncs import *

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

# direct to graphviz ...
import graphviz as gv

# if > this number of nodes we simplify graphing by not making edges
# for specific ports, but just mail,web,ssh etc.
toobiggraph=10

# deffault output directory
outdir="graphs"

# graph rendering func

# command line arg handling 
parser=argparse.ArgumentParser(description='Report about an IP from the collisions found by SameKeys.py')
parser.add_argument('-i','--ipsfile',     
                    dest='ipname',
                    help='file containing IP addresses of interest (not too many please:-)')
parser.add_argument('-d','--dir',     
                    dest='parentdir',
                    help='directory below which we find cluster files')
parser.add_argument('-a','--anonymise',     
                    help='replace IPs with other indices',
                    action='store_true')
args=parser.parse_args()

# default render graphs == off (due to diskspace)
doanon=False
if args.anonymise:
    doanon=True

# if this then just print legend
if args.ipname is None:
    print args
    sys.exit(0)

# checks - can we read outdir...
try:
    if not os.path.exists(args.ipname):
        print >> sys.stderr, "Can't read IP file " + args.ipname + " - exiting:" 
        sys.exit(1)
    if not os.path.exists(args.parentdir):
        print >> sys.stderr, "Can't find clusters directory " + args.parentdir + " - exiting:" 
        sys.exit(2)
except:
    print >> sys.stderr, "Exception checking inputs - exiting:" + str(e)
    sys.exit(3)

# main line processing ...

# we need to pass over all the fingerprints to make a graph for each
# cluster, note that due to cluster merging (in SameKeys.py) we may
# not see all cluster members as peers of the first cluster member

ipstrings=[]

# read in the IP's
with open(args.ipname) as f:
    for line in f:
        for word in line.split():
            if word != '"ip":':
                # format is "XXX.XXX.XXX.XXX" with the quotes,
                # which we wanna lose...
                ipstrings.append(word[1:-1])

# loop counter for debug
checkcount=0

# store FPs of interest
fps={}
names={}


# on one host (with python 2.7.12) it seems that I need to
# first set the options for the json backend before doing
# it for the simplejson backend. Without this, the json
# is output with one line per encooded thing, which breaks
# later tooling.
# on another (with python 2.7.14) just the 2nd call is 
# enough to get the indentation correct. 
# bit odd but whatever works I guess;-)
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

pattern=re.compile("cluster[0-9]+.json")

for subdir, dirs, files in os.walk(args.parentdir):
    for fname in files:
        if not pattern.match(fname):
            continue
        print >>sys.stderr, "Opening " + subdir+"/"+fname 
        fp=open(subdir+"/"+fname,"r")
        try:
            f=getnextfprint(fp)
            while f:
                #process it
                cnum=f.clusternum
                csize=f.csize
                nrcs=f.nrcs
                if f.ip in ipstrings:
                    # a match!
                    # record fprints
                    fps[f.ip]=f.fprints
                    names[f.ip]=f.analysis["nameset"]
    
                # print something now and then to keep operator amused
                now=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
                checkcount += 1
                if checkcount % 100 == 0:
                    print >> sys.stderr, "Reporting, fingerprints: " + str(checkcount) + " most recent cluster " + str(cnum) + \
                        " at: " + str(now)
                if checkcount % 1000 == 0:
                    gc.collect()
    
                # read next fp
                del f
                f=getnextfprint(fp)
        except Exception as e: 
            print "Decoding exception ("+str(e)+") reading file" + fname
            continue

print "FPS:"
print fps
print "Names:"
print names
    
print >> sys.stderr, "Done, fingerprints: " + str(checkcount) + " most recent cluster " + str(cnum) + \
        " at: " + str(now)

