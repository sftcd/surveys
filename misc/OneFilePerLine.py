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

# split a ZGrab output file with one JSON structure per line
# into one file per structure pretty printed into a file each

import re, os, sys, argparse, tempfile, gc
import json
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

codedir=os.path.dirname(os.path.realpath(__file__))
pdir=os.path.dirname(codedir)

sys.path.insert(0,pdir)
# our own stuff
from SurveyFuncs import *  

# default values
infile="records.fresh"
outfile_pref="line"

# if this file exists, read it to determine if IP is (not) in some cluster
dodgyfile="dodgy.json"

# command line arg handling 
argparser=argparse.ArgumentParser(description='Count protocol versions in a run')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing output from zgrab')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='output file prefix')
args=argparser.parse_args()

if args.infile is not None:
    infile=args.infile

if args.outfile is not None:
    outfile_pref=args.outfile

# encoder options
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

overallcount=0

with open(infile,'r') as f:
    for line in f:
            j_content = json.loads(line)
            thisip=j_content["ip"].strip()
            overallcount += 1

            bstr=jsonpickle.encode(j_content)
            with open(outfile_pref+str(overallcount)+".json","w") as lf:
                lf.write(bstr)
    
            # update average
            if overallcount % 100 == 0:
                print >> sys.stderr, "Reading lines, did: " + str(overallcount) + " most recent ip " + thisip 
            del j_content

f.close()
print >> sys.stderr, "Done Reading lines, did: " + str(overallcount) + " most recent ip " + thisip 



