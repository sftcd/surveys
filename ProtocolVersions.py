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

# check the protocol versions being used 

# This goes back to records.fresh as I don't keep the versioning info
# in the fingerprint structure (TODO: add version stuff to metadata
# in FP structures)

# we'll count versions per-port overall, and for IPs that are, and
# are not, within a cluster

# for that last, an initial step is to select the IPs from the 
# dodgy.json which are those not within clusters

import re, os, sys, argparse, tempfile, gc
import json
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

# our own stuff
from SurveyFuncs import *  

# counters, per port, per version 
counters={}
counters['o']={}
counters['c']={}
counters['nc']={}
for pstr in portstrings:
    # overall counters
    # in-cluster counters
    # not in-cluster counters
    counters['o'][pstr]={}
    counters['c'][pstr]={}
    counters['nc'][pstr]={}

# counter updater
def counterupdate(incluster,pstr,ver):
    if ver in counters['o'][pstr]:
        counters['o'][pstr][ver]=counters['o'][pstr][ver]+1
    else:
        counters['o'][pstr][ver]=1
    if incluster:
        if ver in counters['c'][pstr]:
            counters['c'][pstr][ver]=counters['c'][pstr][ver]+1
        else:
            counters['c'][pstr][ver]=1
    else:
        if ver in counters['nc'][pstr]:
            counters['nc'][pstr][ver]=counters['nc'][pstr][ver]+1
        else:
            counters['nc'][pstr][ver]=1

# figure out runname
dirname=os.getcwd()
#print dirname
fullrunname=dirname.split('/')[-1]
runname=fullrunname.split('-')[0] + '-' + fullrunname.split('-')[1] 
print >>sys.stderr, "Doing " + runname

# default values
infile="records.fresh"
outfile="versions.tex"

# if this file exists, read it to determine if IP is (not) in some cluster
dodgyfile="dodgy.json"

# command line arg handling 
argparser=argparse.ArgumentParser(description='Count protocol versions in a run')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing output from zgrab')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put latex table')
argparser.add_argument('-d','--dodgy_file',     
                    dest='dodgy',
                    help='file in which we find non-clustered IPs')
args=argparser.parse_args()

if args.infile is not None:
    infile=args.infile

if args.outfile is not None:
    outfile=args.outfile

if args.dodgy is not None:
    dodgyfile=args.dodgy

# we won't fully decode this, just grep out the IP addresses
# do: grep '^    "ip":' dodgyfile
dodgycount=0
nonclusterips=[]
ooccount=0
oocips=[]
thatip=''
df = open(dodgyfile,"r")
for line in df:
    if re.search('^    "ip"', line):
        thatip=line.split()[1][1:-2]
        nonclusterips.append(thatip)
        dodgycount+=1
        if dodgycount % 100 == 0:
            print >>sys.stderr, "Reading dodgies, did: " + str(dodgycount)
    if re.search('"wrong_country"',line):
        ooccount+=1
        oocips.append(thatip)
print >>sys.stderr, "Done reading dodgies, did: " + str(dodgycount)
print >>sys.stderr, "Number of non-cluster IPs: " + str(len(nonclusterips))
print >>sys.stderr, "Number of ooc IPs: " + str(len(oocips))

# encoder options
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

# keep track of how long this is taking per ip
peripaverage=0
overallcount=0

# initialise to versions we know about - others that we don't
# will be added as we find 'em - that may screw up the latex 
# output but that'll be visible and can be fixed as we see 'em
sshversions=["1.99", "2.0"]
tlsversions=["SSLv3","TLSv1.0","TLSv1.1","TLSv1.2"]

# init counters
for ctype in counters:
    for pstr in portstrings:
        if pstr=="p22":
            for ver in sshversions:
                counters[ctype][pstr][ver]=0
        else:
            for ver in tlsversions:
                counters[ctype][pstr][ver]=0

# count our fp exceptions
sshfpes=0
tlsfpes=0

with open(infile,'r') as f:
    for line in f:
            ipstart=time.time()
            badrec=False
            j_content = json.loads(line)
            somekey=False
            thisip=j_content['ip'].strip()
            incluster=True

            # ignore if not in-country
            if thisip in oocips:
                continue

            if thisip in nonclusterips:
                incluster=False

            for pstr in portstrings:
                if pstr=='p22':
                    try:
                        sshver=j_content['p22']['data']['xssh']['server_id']['version']
                        # make sure we got an FP for that - sometimes we get protocol versions
                        # but don't get an FP, which skews the numbers. That can happen
                        # e.g. if something doesn't decode or whatever
                        # attempting to get this should cause an exception if it's not there
                        try:
                            fp=j_content['p22']['data']['xssh']['key_exchange']['server_host_key']['fingerprint_sha256'] 
                            counterupdate(incluster,'p22',sshver)
                            somekey=True
                            if sshver not in sshversions:
                                sshversions.append(sshver)
                        except Exception as e: 
                            sshfpes+=1
                            print >> sys.stderr, "p22 ver/FP exception #" + str(sshfpes) + " " + str(e) + " ip:" + thisip
                    except Exception as e: 
                        #print >> sys.stderr, "p22 exception " + str(e) + " ip:" + thisone.ip
                        pass
                elif pstr=='p443':
                    try:
                        tls=j_content['p443']['data']['http']['response']['request']['tls_handshake']
                        ver=tls['server_hello']['version']['name']
                        # make sure we got an FP for that - sometimes we get protocol versions
                        # but don't get an FP, which skews the numbers. That can happen
                        # e.g. if something doesn't decode or whatever
                        # attempting to get this should cause an exception if it's not there
                        try: 
                            cert=tls['server_certificates']['certificate']
                            fp=cert['parsed']['subject_key_info']['fingerprint_sha256'] 
                            counterupdate(incluster,pstr,ver)
                            if ver not in tlsversions:
                                tlsversions.append(ver)
                            somekey=True
                        except Exception as e: 
                            tlsfpes+=1
                            print >> sys.stderr, pstr + "ver/FP exception #" + str(tlsfpes) + " " + str(e) + " ip:" + thisip
                    except Exception as e: 
                        #print >> sys.stderr, pstr + "exception for:" + thisip + ":" + str(e)
                        pass
                else:
                    try:
                        tls=j_content[pstr]['data']['tls']
                        ver=tls['server_hello']['version']['name']
                        # make sure we got an FP for that - sometimes we get protocol versions
                        # but don't get an FP, which skews the numbers. That can happen
                        # e.g. if something doesn't decode or whatever
                        # attempting to get this should cause an exception if it's not there
                        try:
                            cert=tls['server_certificates']['certificate']
                            fp=cert['parsed']['subject_key_info']['fingerprint_sha256'] 
                            counterupdate(incluster,pstr,ver)
                            if ver not in tlsversions:
                                tlsversions.append(ver)
                            somekey=True
                        except Exception as e: 
                            tlsfpes+=1
                            print >> sys.stderr, pstr + "ver/FP exception #" + str(tlsfpes) + " " + str(e) + " ip:" + thisip
                    except Exception as e: 
                        #print >> sys.stderr, pstr + "exception for:" + thisip + ":" + str(e)
                        pass

            overallcount += 1
    
            # update average
            ipend=time.time()
            thistime=ipend-ipstart
            peripaverage=((overallcount*peripaverage)+thistime)/(overallcount+1)
            if overallcount % 100 == 0:
                print >> sys.stderr, "Reading versions, did: " + str(overallcount) + \
                        " most recent ip " + thisip + \
                        " average time/ip: " + str(peripaverage) \
                        + " last time: " + str(thistime)
            del j_content

    f.close()
    gc.collect()
    print >> sys.stderr, "Done reading versions, did: " + str(overallcount) + \
                        " most recent ip " + thisip + \
                        " average time/ip: " + str(peripaverage) \
                        + " last time: " + str(thistime)

bstr=jsonpickle.encode(counters)
print >>sys.stderr, "Counters:\n" + bstr

ocounters={}

# count tls versions overall
for pstr in portstrings:
    if pstr=='p22':
        continue
    else:
        for ver in counters['o'][pstr]:
            if ver not in ocounters:
                ocounters[ver]=counters['o'][pstr][ver]
            else:
                ocounters[ver]=ocounters[ver]+counters['o'][pstr][ver]

bstr=jsonpickle.encode(ocounters)
print >>sys.stderr, "Overall TLS Counters:\n" + bstr

# produce some latex table entry lines, for tls
eotl=' \\\\ \\hline'
print runname + eotl
lineout= 'port ' 
for ver in sorted(tlsversions):
    lineout+= ' & ' + ver
print lineout + ' & Total ' + eotl
coltotal=0
for pstr in portstrings:
    if pstr=='p22':
        continue
    lineout= pstr
    linetotal=0
    for ver in sorted(tlsversions):
        if ver not in counters['o'][pstr]:
            lineout+= ' & 0 '
        else:
            lineout+= ' & ' + str(counters['o'][pstr][ver])
            linetotal+= counters['o'][pstr][ver]

    print lineout + ' & ' + str(linetotal) + eotl
    coltotal+=linetotal
lineout='Total ' 
linetotal=0
for ver in sorted(tlsversions):
    lineout+= ' & ' + str(ocounters[ver]) 
    linetotal += ocounters[ver]
if linetotal != coltotal:
    print >>sys.stderr, "Totals mismatch!!!, cols (" + str(coltotal) + ") != last line (" + str(linetotal) + ")"
print lineout + ' & ' + str(linetotal) + eotl

