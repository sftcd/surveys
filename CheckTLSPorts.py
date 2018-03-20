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

# check the clusters that claim to show TLS overlaps

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import binascii

from SurveyFuncs import *

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a confirmation scan of TLS key hashes')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of collisions')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json results (one per line)')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between openssl s_client calls (fractions allowed')

args=parser.parse_args()

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> [-o <putfile>] [-s <sleepsecs>]"
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

# default to a 100ms wait between checks
defsleep=0.1

if args.outfile is not None:
    out_f=open(args.outfile,"w")
else:
    out_f=sys.stdout

print >>out_f, "Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time()))

sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print >>out_f, "Will sleep for " + str(sleepval) + " seconds between openssl s_client calls"

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

def gettlsserverkey(ip,portstr):
    rv=[]
    print 'Doing gettlsserverkey',ip,portstr
    try:
        cmd='openssl s_client -connect ' + ip +':'+ str(opensslpno[portstr]) + ' ' + opensslparms[portstr] 
        #print "***|" + cmd + "|***"
        proc=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
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
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        pubk=cert.public_key()
        pubbytes=pubk.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        #pubbytes=pubk.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.PKCS1)
        digest=hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(pubbytes)
        spki_hash=binascii.hexlify(digest.finalize())
        rv.append(spki_hash)
    except Exception as e:
        print >> sys.stderr, "gettlsserverkey exception:" + str(e)  
        pass
    return rv

def anymatch(one,other):
    # might handle both-empty case nicely
    if one == other:
        return True
    try:
        for x in one:
            for y in other:
                if x==y and x!="error":
                    #print "anymatch",x,y
                    return True
    except Exception as e:
        #print >>out_f, "nomatch: x",x,"y",y,e
        pass
    return False

# mainline processing

fp=open(args.infile,"r")

ipsdone={}

ipmatrix={}



ipcount=0
ttcount=0
tlscount=0
portcounts={}
for port in portstrings:
    portcounts[port]=0
matches=0
mismatches=0
f=getnextfprint(fp)
while f:
    ipcount+=1
    ip=f.ip
    only22=True
    for portstr in f.fprints:
        portcounts[portstr] += 1
        if portstr != 'p22':
            only22=False
            break
    if only22:
        print >>out_f, "Ignoring",ip,"only SSH involved"
        ttcount += 1
    else:
        for portstr in f.fprints:
            if portstr=='p22':
                continue
            tlscount+=1 # count of ips with some tls
            print >>out_f,  "Checking " + ip + portstr + " recorded as: " + f.fprints['p22']

            hkey=gettlsserverkey(ip,portstr)
            if hkey:
                print  >>out_f, "keys at " + ip + portstr + " now are:"+str(hkey)
            else:
                print  >>out_f, "No TLS keys visible at " + ip + portstr + " now"
            ipsdone[ip]=hkey
            for ind in f.rcs:
                pip=f.rcs[ind]['ip']
    
                str_colls=f.rcs[ind]['str_colls']

                if 'p22' in str_colls:
                    if ip in ipmatrix:
                        if pip in ipmatrix[ip]:
                            print >>out_f, "\tChecking",ip,portstr,"vs",pip,"done already"
                            continue
                    else:
                        ipmatrix[ip]={}
                    ipmatrix[ip][pip]=True
                    print >>out_f, "\tChecking",ip,portstr,"vs",pip
                    if pip in ipmatrix:
                        if ip in ipmatrix[pip]:
                            continue
                    else:
                        ipmatrix[pip]={}
                    ipmatrix[pip][ip]=True
                    if pip in ipsdone:
                        pkey=ipsdone[pip]
                    else:
                        pkey=gettlsserverkey(pip,portstr)
                        ipsdone[pip]=pkey
                    if pkey:
                        print  >>out_f, "\t"+ "keys at " + pip + portstr + " now are: " + str(pkey)
                    else:
                        print  >>out_f, "\tNo TLS keys visible at " + pip + portstr + " now"

                    if anymatch(pkey,hkey):
                        matches+=1
                    else:
                        print >>out_f, "EEK - Discrepency between "+ ip +" and " + pip 
                        print >>out_f, "EEK - " + ip + " == " + str(hkey)
                        print >>out_f, "EEK - " + pip + " == " + str(pkey)
                        mismatches+=1
    f=getnextfprint(fp)

print >>out_f, "TLSKey,infile,ipcount,22count,matches,mismatches"
print >>out_f, "TLSKey,"+args.infile+","+str(ipcount)+","+str(tlscount)+","+str(matches)+","+str(mismatches)
#print >>out_f, ipsdone

print >>out_f, "Ran ",sys.argv[0:]," started at ",time.asctime(time.localtime(time.time()))

#jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
#print jsonpickle.encode(ipmatrix)

if args.outfile:
    out_f.close()
