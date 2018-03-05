#!/usr/bin/python

# read out the port 22 collisions and verify those using ssh-keyscan

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess

from SurveyFuncs import *

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a confirmation scan of ssh collisions')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of collisions')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json results (one per line)')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between ssh-keyscan (fractions allowed')
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

# default to a 100ms wait between zgrab calls
defsleep=0.1

print "Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time()))

sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print "Will sleep for " + str(sleepval) + " seconds between ssh-keyscans"

if args.outfile is not None:
    out_f=open(args.outfile,"w")
else:
    out_f=sys.stdout

def gethostkey(ip):
    rv=[]
    try:
        cmd='/usr/bin/ssh-keyscan ' + ip
        #print "\tTrying",cmd,ip
        proc=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        time.sleep(sleepval)
        pc=proc.communicate()
        lines=pc[0].split('\n')
        #print "\t",lines
        for x in range(0,len(lines)):
            #print "\tlines",x,"|",lines[x],"|"
            foo=lines[x].split()
            #print "\tfoo","|",foo,"|"
            if foo[2]!='':
                rv.append(foo[2])
        #print "\trv:",rv
    except Exception as e:
        # something goes wrong, we just record what
        #print "\tErrorwith",ip,cmd,str(e)
        #rv.append("error")
        pass
    return rv

def anymatch(one,other):
    try:
        for x in one:
            for y in other:
                if x==y and x!="error":
                    #print "anymatch",x,y
                    return True
    except Exception as e:
        print "nomatch: x",x,"y",y,e
    return False

# mainline processing

fp=open(args.infile,"r")

ipsdone={}

ipcount=0
ttcount=0
matches=0
mismatches=0
f=getnextfprint(fp)
while f:
    ipcount+=1
    ip=f.ip
    if 'p22' not in f.fprints:
        print "Ignoring",ip
    else:
        hkey=gethostkey(ip)
        ipsdone[ip]=hkey
        for ind in f.rcs:
            pip=f.rcs[ind]['ip']
            str_colls=f.rcs[ind]['str_colls']
            if 'p22' in str_colls:
                ttcount+=1
                print "Checking",ip,"vs",pip
                if pip in ipsdone:
                    pkey=ipsdone[pip]
                else:
                    pkey=gethostkey(pip)
                    ipsdone[pip]=pkey
                if anymatch(pkey,hkey):
                    matches+=1
                else:
                    print "EEK - Discrepency between",ip,"and",pip
                    print hkey
                    print pkey
                    mismatches+=1
    f=getnextfprint(fp)

print ipcount,ttcount,matches,mismatches
#print ipsdone
