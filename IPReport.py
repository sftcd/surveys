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
import dns.resolver #import the module
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
parser=argparse.ArgumentParser(description='Report about a name or set of IPs from the collisions found by SameKeys.py')
parser.add_argument('-i','--ipsfile',     
                    dest='ipname',
                    help='file containing IP addresses of interest (not too many please:-)')
parser.add_argument('-d','--dir',     
                    dest='parentdir',
                    help='directory below which we find cluster files')
parser.add_argument('-n','--name',     
                    dest='onename',
                    help='single DNS name to check for')
parser.add_argument('-a','--anonymise',     
                    help='replace IPs with other indices',
                    action='store_true')
args=parser.parse_args()

# default render graphs == off (due to diskspace)
doanon=False
if args.anonymise:
    doanon=True

# if this then just print legend
if args.ipname is None and args.onename is None:
    print "You need to supply a DNS name or file of IP addresses - exiting"
    sys.exit(0)

# checks - can we read outdir...
try:
    if args.ipname is not None and not os.path.exists(args.ipname):
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

if args.ipname is not None:
    # read in the IP's
    with open(args.ipname) as f:
        for line in f:
            for word in line.split():
                if word != '"ip":':
                    # format is "XXX.XXX.XXX.XXX" with the quotes,
                    # which we wanna lose...
                    ipstrings.append(word[1:-1])
elif args.onename is not None:
    # do DNS lookup
    try:
        myResolver = dns.resolver.Resolver() #create a new instance named 'myResolver'
        answer = myResolver.query(args.onename, "A") 
        for rdata in answer: 
            if str(rdata) not in ipstrings:
                ipstrings.append(str(rdata))
        answer = myResolver.query(args.onename, "NS") 
        for rdata in answer: 
            oanswer = myResolver.query(str(rdata),"A") 
            for ordata in oanswer:
                if str(ordata) not in ipstrings:
                    ipstrings.append(str(ordata))
    except Exception as e: 
        print >>sys.stderr, "DNS exception ("+str(e)+") for name " + args.onename
else: 
    print "You need to supply a DNS name or file of IP addresses - exiting"
    sys.exit(0)

if len(ipstrings) == 0:
    print "Found no IP addresses to check for - exiting"
    sys.exit(4)

# loop counter for debug
checkcount=0

# store FPs of interest
fps={}
names={}

# remember cluster files we've seen already
cnames=[]

# extra matches
morematches={}
morecnames=[]

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

# cluster file name pattern
cpattern=re.compile("cluster[0-9]+.json$")
# run directory name pattern
dpattern=re.compile("[A-Z][A-Z]-201[89][0-9]+-[0-9]+")

for subdir, dirs, files in os.walk(args.parentdir):
    basesubdir=os.path.basename(subdir)
    if not dpattern.match(basesubdir):
        print >>sys.stderr, "Skipping " + subdir
        continue
    for fname in files:
        if not cpattern.match(fname):
            print >>sys.stderr, "Skipping " + subdir + "/ " + fname
            continue
        fullname=subdir+"/"+fname
        print >>sys.stderr, "Opening " + fullname
        fp=open(fullname,"r")
        try:
            f=getnextfprint(fp)
            match=False
            while f:
                #process it
                cnum=f.clusternum
                csize=f.csize
                nrcs=f.nrcs
                if f.ip in ipstrings:
                    # a match!
                    match=True
                    # record fprints and name for further searchng
                    fps[f.ip]=f.fprints
                    names[f.ip]=f.analysis["nameset"]
                    cnames.append(fullname)
                    # maybe pretty print this FP to a latex file
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
            print >>sys.stderr, "Decoding exception ("+str(e)+") reading file" + fname
            continue

print "FPS:"
print jsonpickle.encode(fps)
print "Names:"
print jsonpickle.encode(names)
print "Cluster names:"
print jsonpickle.encode(cnames)

checkcount=0
# now go back through all clusters to see if those FPs and/or names recur...
for subdir, dirs, files in os.walk(args.parentdir):
    basesubdir=os.path.basename(subdir)
    if not dpattern.match(basesubdir):
        print >>sys.stderr, "Skipping " + subdir
        continue
    for fname in files:
        if not cpattern.match(fname):
            print >>sys.stderr, "Skipping " + subdir + "/ " + fname
            continue
        fullname=subdir+"/"+fname
        print >>sys.stderr, "Opening " + fullname
        #if fullname in cnames:
            # see it already and we're bored with it:-)
            #continue
        fp=open(fullname,"r")
        try:
            f=getnextfprint(fp)
            while f:
                #process it
                cnum=f.clusternum
                csize=f.csize
                nrcs=f.nrcs
            
                # see if any fps or names occur here...
                match=False
                
                # any matching fprint
                for ip in fps:
                    for port1 in fps[ip]:
                        for port2 in f.fprints:
                            if f.fprints[port2]==fps[ip][port1]:
                                match=True
                                print >>sys.stderr, "FP match: " + f.fprints[port2] + "==" + fps[ip][port1]

                # any matching name
                if not match:
                    for ip in names:
                        for field1 in names[ip]:
                            if field1 != "allbad" and field1 != "besty":
                                for field2 in f.analysis["nameset"]:
                                    if field2 != "allbad" and field2 != "besty":
                                        try:
                                            if f.analysis["nameset"][field2]==names[ip][field1]:
                                                # TODO: add a bogon blacklist maybe, e.g. for "localhost"
                                                # TODO: add wildcard matching?
                                                if not name_bogon(names[ip][field]):
                                                    match=True
                                                    print >>sys.stderr, "Name match: " + f.analysis["nameset"][field2] + "==" + names[ip][field1]
                                        except e:
                                            print >> sys.stderr, "Decoding exception 2nd time ("+str(e)+") reading file " + fullname + \
                                                        "Field1=" + field1 + " field2=" + field2 + "ip="+ip

                # if so, keep those for outputting later
                if match:
                    morematches[f.ip]=f
                    morecnames.append(fullname)

                # print something now and then to keep operator amused
                now=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
                checkcount += 1
                if checkcount % 100 == 0:
                    print >> sys.stderr, "Reporting2, fingerprints: " + str(checkcount) + " most recent cluster " + str(cnum) + \
                        " at: " + str(now)
                if checkcount % 1000 == 0:
                    gc.collect()
    
                # read next fp
                del f
                f=getnextfprint(fp)
        except Exception as e: 
            print >> sys.stderr, "Decoding exception 2nd time ("+str(e)+") reading file " + fname
            continue

print "More matches:"
print jsonpickle.encode(morematches)
print "More cluster names:"
print jsonpickle.encode(morecnames)

print "IPs"
for ip in fps:
    print  ip
for ip in morematches:
    print ip

print >> sys.stderr, "Done, fingerprints: " + str(checkcount) + " most recent cluster " + str(cnum) + \
        " at: " + str(now)

