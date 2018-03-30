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

# Report the collisions, via graphs and text

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

sys.path.insert(0,'..')
from SurveyFuncs import *


# command line arg handling 
parser=argparse.ArgumentParser(description='Graph the collisions found by SameKeys.py')
parser.add_argument('-f','--file',     
                    dest='fname',
                    help='json file containing cluster details')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='directory in which to put (maybe many) graph files')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='country in which we\'re interested')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between openssl s_client calls (fractions allowed')
args=parser.parse_args()
# default country 
def_country='IE'
country=def_country
if args.country is not None:
    country=args.country
# if this then just print legend
if args.fname is None:
    print args
    sys.exit(0)
now=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
nowstr=str(now).replace(" ","T")
nowstr=nowstr.replace(":","-")
outfile=args.fname+".certall."+nowstr+".txt"
if args.outfile:
    outfile=args.outfile
defsleep=0.1
sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print >>out_f, "Will sleep for " + str(sleepval) + " seconds between openssl s_client calls"

# TODO: lots of overlap with ../CheckTLSPPort.py - re-factor later when we know more

opensslcmd={ 
        'p22': "ignore me - I shouldn't be used here", 
        'p25': "openssl s_client -connect ",
        'p110': "openssl s_client -connect ",
        'p143': "openssl s_client -connect ",
        'p443': "openssl s_client -connect ",
        'p587': "openssl s_client -connect ",
        'p993': "openssl s_client -connect  "
        }

opensslparms={ 
        'p22': "ignore me - I shouldn't be used here", 
        'p25': "-starttls smtp",
        'p110': "-starttls pop3",
        'p143': "-starttls imap",
        'p443': "",
        'p587': "-starttls smtp",
        'p993': ""
        }

opensslpno={ 
        'p22': 22,
        'p25': 25,
        'p110': 110,
        'p143': 143,
        'p443': 443,
        'p587': 587,
        'p993': 993
        }

def gettlscertstr(ip,portstr):
    certstr=""
    #print >> sys.stdout,'Doing gettlsserverkey '+ip+portstr
    try:
        cmd=opensslcmd[portstr] + ' ' + ip +':'+ str(opensslpno[portstr]) + ' ' + opensslparms[portstr] 
        #print "***|" + cmd + "|***"
        proc=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        print "Sleepin for ",sleepval
        time.sleep(sleepval)
        pc=proc.communicate()
        lines=pc[0].split('\n')
        incert=False
        pem_data=''
        for x in range(0,len(lines)):
            if lines[x]=='-----BEGIN CERTIFICATE-----':
                incert=True
            if lines[x]=='-----END CERTIFICATE-----':
                pem_data += lines[x] + '\n'
                incert=False
            if incert:
                pem_data += lines[x] + '\n'
        #print pem_data
        #cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        cmd='openssl x509 -noout -text'
        proc_hash=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None)
        pc=proc_hash.communicate(input=pem_data)
        return pc[0]
    except Exception as e:
        print >> sys.stderr, "gettlsserverkey exception:" + str(e)  
        pass
    return certstr


# main line processing ...

# we need to pass over all the fingerprints and try get the
# cert for each one

try: 
    outf=open(outfile,"w")
except:
    print >> sys.stderr, "Can't open " + outfile + " - exiting"
    sys.exit(1)

checkcount=0

# open file
fp=open(args.fname,"r")

jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
f=getnextfprint(fp)
while f:

    for port in f.fprints:
        print >> outf, "Doing",f.ip,port,f.analysis[port]
        certstr=gettlscertstr(f.ip,port)
        print >> outf, certstr

    # print something now and then to keep operator amused
    checkcount += 1
    if checkcount % 100 == 0:
        print >> sys.stderr, "Creating graphs, fingerprint: " + str(checkcount) 
    if checkcount % 1000 == 0:
        gc.collect()

    # read next fp
    del f
    f=getnextfprint(fp)

# close file
fp.close()
outf.close()

