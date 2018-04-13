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

# Fix up p443san - p587 names overwrote p443 names when both
# were present, or if only p587 was present. 

# Fix is to delve back into records.fresh, pick out 
# the right record, update the p443 names and then produce a new 
# collisions.json file. After that, usual make targets can be used
# to recrate graphs etc. as desired and they should be the same.

# Crap - same problem for p993 overwriting p443 names! Sigh

# For the IE-20180316 run, we need to check/fix 2959 from 9765 records
# for p587

import os, re, sys, argparse, tempfile, gc
import json
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"
import time, datetime
from dateutil import parser as dparser  # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

# our own stuff
from SurveyFuncs import *  

# default values
infile="records.fresh"
outfile="collisions.json"

# command line arg handling 
argparser=argparse.ArgumentParser(description='Fix mcuked-up p443san records for collisions')
argparser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing previously generated collisions')
argparser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put fixed json records')
args=argparser.parse_args()

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> -o <putfile> "
    print >>sys.stderr, "    both inputs are mandatory and must differ"

if args.infile is None:
    print "You need to supply all inputs"
    usage()

infile=args.infile

if args.outfile is None:
    print "You need to supply all inputs"
    usage()

outfile=args.outfile

if infile==outfile:
    print "can't overwrite input with output"
    usage()

def certfromrf(ip,rf):
    # will do real code here shortly...
    # search for the ip from records.fresh
    # the file pointer for records.fresh should (I hope) be ok to
    # move along in natural order given how we made collisions.json
    # in the first place - this wouldn't generally be true
    # we really should also always find the IP, if not then scream!!!
    found=False
    #print "Called certfromrf looking for " + ip + ", rf.tell says: " + str(rf.tell())
    for line in rf:
        if re.search(ip,line):
            #print "Found " + ip + " in records.fresh at offset " + str(rf.tell())
            found=True
            break
    if not found:
        print >>sys.stderr, "EEK - No sign of " + ip + " in records.fresh at offset " + str(rf.tell())
        sys.exit(99)
    # decode the json for that ip
    j_content = json.loads(line)
    try:
        # FreshGrab.py sourced version
        cert=j_content['p443']['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']
    except:
        try:
            # censys.io sourced version
            cert=j_content['p443']['https']['tls']['certificate']
        except:
            print "EEK - Cen't decode cert for " + ip 
            sys.exit(98)
    # we're done - return the cert
    return cert

# fixup function
def fix443names(f,rf):
    # grab f.ip record p443 server cert from records.fresh into cert
    pnum=443
    cert=certfromrf(f.ip,rf)
    if cert is None:
        return False
    nameset=f.analysis['nameset']
    portstring='p'+str(pnum)
    dn=cert['parsed']['subject_dn'] 
    dn_fqdn=dn2cn(dn)
    nameset[portstring+'dn'] = dn_fqdn
    # name from cert SAN
    # zap old sans
    oldsancount=0
    elname=portstring+'san'+str(oldsancount) 
    while elname in nameset:
        del nameset[elname]
        oldsancount += 1
        elname=portstring+'san'+str(oldsancount) 
    # and repair from cert
    if 'subject_alt_name' in cert['parsed']['extensions']:
        sans=cert['parsed']['extensions']['subject_alt_name'] 
        if 'dns_names' in sans:
            san_fqdns=sans['dns_names']
            # we ignore all non dns_names - there are very few in our data (maybe 145 / 12000)
            # and they're mostly otherName with opaque OID/value so not that useful. (A few
            # are emails but we'll skip 'em for now)
            #print "FQDN san " + str(san_fqdns) 
            sancount=0
            for san in san_fqdns:
                nameset[portstring+'san'+str(sancount)]=san_fqdns[sancount]
                sancount += 1
                # there are some CRAAAAAAZZZY huge certs out there - saw one with >1500 SANs
                # which slows us down loads, so we'll just max out at 20
                if sancount >= 100:
                    toobig=str(len(san_fqdns))
                    nameset['san'+str(sancount+1)]="Bollox-eoo-many-sans-1-" + toobig
                    print >> sys.stderr, "Too many bleeding ( " + toobig + ") sans "
                    break
        for elname in sans:
            if elname != 'dns_names':
                print "SAN found with non dns_nsme for " + f.ip
                print "\t" + str(sans)
                break
    return True

# mainline processing

# open records.fresh
rf=open("records.fresh","r")

# open file
fp=open(infile,"r")
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
colf=open(outfile,"w")
colf.write('[\n')
firstone=True

overallcount=0
checkcount=0
fixcount=0
zapcount=0

f=getnextfprint(fp)
while f:

    if ('p443' in f.fprints) and (('p587' in f.fprints) or ('p993' in f.fprints)):
        checkcount += 1
        if fix443names(f,rf):
            fixcount += 1
    elif ('p443' not in f.fprints) and (('p587' in f.fprints) or ('p993' in f.fprints)):
        # that's a case where we don't have a 443 listener, but mistakenly added p587 or p993 names instead
        checkcount += 1
        zapcount += 1
        if 'p443dn' not in f.analysis['nameset']:
            print "EEK - no p443dn for " + f.ip
            sys.exit(97)
        del f.analysis['nameset']['p443dn']
        oldsancount=0
        elname='p443san'+str(oldsancount) 
        while elname in f.analysis['nameset']:
            del f.analysis['nameset'][elname]
            oldsancount += 1
            elname='p443san'+str(oldsancount) 

    bstr=jsonpickle.encode(f,unpicklable=False)
    if not firstone:
        colf.write('\n,\n')
    firstone=False
    colf.write(bstr)
    del bstr

    if overallcount % 100 == 0:
        print >> sys.stderr, "Repairing colisions, did: " + str(overallcount) + \
                " checked: " + str(checkcount) + \
                " fixed: " + str(fixcount) + \
                " zapped: " + str(zapcount)

    f=getnextfprint(fp)
    overallcount += 1

fp.close()
rf.close()
colf.write('\n]\n')
colf.close()

print >> sys.stderr, "Done epairing colisions, did: " + str(overallcount) + \
                " checked: " + str(checkcount) + \
                " fixed: " + str(fixcount) + \
                " zapped: " + str(zapcount)

