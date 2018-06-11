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

# read out the port 22 collisions and verify those using ssh-keyscan

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
import binascii

from SurveyFuncs import *

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a confirmation scan of ssh key hashes')
parser.add_argument('-d','--dryrun',     
                    help='just do a dry-run, listing IPs that would be checked',
                    action='store_true')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of collisions')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json results (one per line)')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between ssh-keyscan (fractions allowed)')
args=parser.parse_args()

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> [-d] [-o <putfile>] [-s <sleepsecs>]"
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
    print >>out_f, "Will sleep for " + str(sleepval) + " seconds between ssh-keyscans"

def gethostkey(ip):
    rv=[]
    try:
        time.sleep(sleepval)
        cmd='/usr/bin/ssh-keyscan ' + ip 
        proc_scan=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        pc=proc_scan.communicate()
        lines=pc[0].split('\n')
        #print "lines: " + str(lines) + "\n"
        for x in range(0,len(lines)):
            #print lines[x]
            if lines[x]=='\n' or lines[x]=='' or lines[x][0]=='#':
                continue
            # pass to ssh-keygen
            cmd='/usr/bin/ssh-keygen -l -f -'
            proc_hash=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None)
            pc=proc_hash.communicate(input=lines[x])
            b64hashes=pc[0].split('\n')
            for y in range(0,len(b64hashes)):
                if b64hashes[y]=='\n' or b64hashes[y]=='' or b64hashes[y]==[]:
                    continue
                #print b64hashes[y]
                foo=b64hashes[y].split()
                #print foo
                fooh=foo[1][7:]
                #print fooh
                barh=binascii.a2b_base64(fooh+'===')
                #print str(barh)
                ahhash=binascii.hexlify(barh)
                #print ahhash
                rv.append(ahhash)
    except Exception as e:
        #print >>out_f, "gethostkey",ip,e
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
matches=0
mismatches=0
f=getnextfprint(fp)
while f:
    ipcount+=1
    ip=f.ip
    if 'p22' not in f.fprints:
        print >>out_f, "Ignoring",ip,"no SSH involved"
    else:
        ttcount+=1
        print >>out_f,  "Checking " + ip + " recorded as: " + f.fprints['p22']
        if args.dryrun:
            f=getnextfprint(fp)
            continue
        hkey=gethostkey(ip)
        if hkey:
            print  >>out_f, "keys at " + ip + " now are:"+str(hkey)
        else:
            print  >>out_f, "No ssh keys visible at " + ip + " now"
        ipsdone[ip]=hkey
        for ind in f.rcs:
            pip=f.rcs[ind]['ip']
            str_colls=f.rcs[ind]['str_colls']
            if 'p22' in str_colls:
                if ip in ipmatrix:
                    if pip in ipmatrix[ip]:
                        print >>out_f, "\tChecking",ip,"vs",pip,"done already"
                        continue
                else:
                    ipmatrix[ip]={}
                ipmatrix[ip][pip]=True
                print >>out_f, "\tChecking",ip,"vs",pip
                if pip in ipmatrix:
                    if ip in ipmatrix[pip]:
                        continue
                else:
                    ipmatrix[pip]={}
                ipmatrix[pip][ip]=True
                if pip in ipsdone:
                    pkey=ipsdone[pip]
                else:
                    pkey=gethostkey(pip)
                    ipsdone[pip]=pkey
                if pkey:
                    print  >>out_f, "\t"+ "keys at " + pip + " now are: " + str(pkey)
                else:
                    print  >>out_f, "\tNo ssh keys visible at " + pip + " now"

                if anymatch(pkey,hkey):
                    matches+=1
                else:
                    print >>out_f, "EEK - Discrepency between "+ ip +" and " + pip 
                    print >>out_f, "EEK - " + ip + " == " + str(hkey)
                    print >>out_f, "EEK - " + pip + " == " + str(pkey)
                    mismatches+=1
    f=getnextfprint(fp)

print >>out_f, "TwentyTwo,infile,ipcount,22count,matches,mismatches"
print >>out_f, "TwentyTwo,"+args.infile+","+str(ipcount)+","+str(ttcount)+","+str(matches)+","+str(mismatches)
#print >>out_f, ipsdone

print >>out_f, "Ran ",sys.argv[0:]," finished at ",time.asctime(time.localtime(time.time()))

#jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
#print jsonpickle.encode(ipmatrix)

if args.outfile:
    out_f.close()
