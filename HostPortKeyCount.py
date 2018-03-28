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

# Count the host/port combos and the number of actual keys found, from
# all hosts that do some crypto

# TODO: fix this to work with fingerprints.json as well as all-jey-fingerprints.json
# but the latter is good enough!

import sys
import os
import tempfile
import gc
import copy
import argparse

from pympler import asizeof

from SurveyFuncs import *

# install via  "$ sudo pip install -U jsonpickle"
#import jsonpickle


# command line arg handling 
parser=argparse.ArgumentParser(description=' Count the host/port combos and the number of actual keys found, from all hosts that do some crypto')
parser.add_argument('-f','--file',     
                    dest='fname',
                    help='json file containing key fingerprints')
args=parser.parse_args()


# if this then just print legend
if args.fname is None:
    print args
    sys.exit(0)

# main line processing ...

# we need to pass over all the fingerprints to do our counts
checkcount=0
fps_seen=set()
hostsports=0
hosts=0

# open file
fp=open(args.fname,"r")

f=getnextfprint(fp)
while f:
    fps=f.fprints
    hosts += 1
    for port in fps:
        hostsports += 1
        #print fps[port]
        fps_seen.add(fps[port])

    # print something now and then to keep operator amused
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Counting hosts/ports/keys, did: " + str(hosts) 
    if checkcount % 1000 == 0:
        gc.collect()

    # read next fp
    del f
    f=getnextfprint(fp)

# close file
fp.close()

summary_fp=open("hpk_summary.txt","a+")
print >> summary_fp, "hosts: " + str(hosts) + "\n" + \
        "hostsports: " + str(hostsports) + "\n" + \
        "fps: " + str(len(fps_seen)) 
summary_fp.close()

print >> sys.stderr, "hosts: " + str(hosts) + "\n" + \
        "hostsports: " + str(hostsports) + "\n" + \
        "fps: " + str(len(fps_seen)) 

