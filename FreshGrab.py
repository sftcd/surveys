#!/usr/bin/python3

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

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
import copy
from SurveyFuncs import *

# use zgrab to grab fresh records for a set of IPs

# command line arg handling 
parser=argparse.ArgumentParser(description='Do a fresh grab of IPs')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of IPs')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
parser.add_argument('-e','--erro_file',     
                    dest='errfile',
                    help='file in which to put stderr output from zgrab')
parser.add_argument('-p','--ports',     
                    dest='portstring',
                    help='comma-sep list of ports to scan')
parser.add_argument('-s','--sleep',     
                    dest='sleepsecs',
                    help='number of seconds to sleep between zgrabs (fractions allowed')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='country in which we\'re interested')
parser.add_argument('-d', '--mmdbdir',    
                    dest='mmdbdir',
                    help='directory in which to find mmdb files')
args=parser.parse_args()

# default (all) ports to scan - added in 587 for fun (wasn't in original scans)
defports=['22', '25', '110', '143', '443', '587', '993']

# default country 
def_country='IE'
country=def_country
if args.country is not None:
    country=args.country

# default timeout for zgrab, in seconds
ztimeout=' -timeout 2'

# port parameters
pparms={ 
        '22': '-port 22 -xssh',
        '25': '-port 25 -smtp -starttls -banners',
        '110': '-port 110 -pop3 -starttls -banners',
        '143': '-port 143 -imap -starttls -banners',
        '443': '-port 443 -tls -http /',
        '587': '-port 587 -smtp -starttls -banners',
        '993': '-port 993 -imap -tls -banners',
        }

def usage():
    print("usage: " + sys.argv[0] + " -i <infile> -o <putfile> [-p <portlist>] [-s <sleepsecs>]", file=sys.stderr)
    sys.exit(1)

ports=defports
if args.portstring is not None:
    ports=args.portstring.split(",")

if args.infile is None or args.outfile is None:
    usage()

# checks - can we read/write 
if not os.access(args.infile,os.R_OK):
    print("Can't read input file " + args.infile + " - exiting", file=sys.stderr)
    sys.exit(1)
if os.path.isfile(args.outfile) and not os.access(args.outfile,os.W_OK):
    print("Can't write to output file " + args.outfile + " - exiting", file=sys.stderr)
    sys.exit(1)

err_fn="/dev/null"
if args.errfile is not None:
    err_fn=args.errfile

# default to a 100ms wait between zgrab calls
defsleep=0.1

print("Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time())), file=sys.stderr)
print("Will scan ports: " + str(ports), file=sys.stderr)
print("Current working directory is: " + os.getcwd(), file=sys.stderr)

sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print("Will sleep for " + str(sleepval) + " seconds between zgrabs", file=sys.stderr)

# keep track of how long this is taking per ip
peripaverage=0

# what's done is done
ipdone=set()

# see if outfile is there and has stuff already
if os.path.isfile(args.outfile):
    pre_ips=0
    try:
        with open(args.outfile,'r') as f:
            for line in f:
                j_content = json.loads(line)
                if 'ip' in j_content:
                    ipdone.add(j_content['ip'])
                    pre_ips += 1
    except Exception as e:
        # we might hit a non-decoding last line or other badness, not unexpected
        print("Exception",args.outfile,"might end badly:",str(e), file=sys.stderr)
        pass
    f.close()
    print("Loaded",str(pre_ips),"previously fetched records from",args.outfile, file=sys.stderr)

# now go get more...
out_f=open(args.outfile,"a")

# initialise mm
mm_setup(args.mmdbdir)

with open(args.infile,'r') as f:
    checkcount=0
    ooc=0
    for ip in f:
        ip=ip.strip() # lose the CRLF

        # if we have this one we're done
        if ip in ipdone:
            print(ip,"is in ipdone - skipping", file=sys.stderr)
            continue
        else: 
            pass
            #print >>sys.stderr, "Doing",ip
        # check country matches
        if not mm_ipcc(ip,country):
            print("Bad country (fg)" + ip + " is not in " + country + " - skipping", file=sys.stderr)
            ooc+=1
            continue
        ipstart=time.time()
        jthing={}
        jthing['ip']=ip
        jthing['writer']="FreshGrab.py"
        for port in ports:
            try:
                cmd='zgrab '+  pparms[port] + ztimeout
                proc=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                pc=proc.communicate(input=ip.encode())
                lines=pc[0].decode("utf-8").split('\n')
                jinfo=json.loads(lines[1])
                jres=json.loads(lines[0])
                #print jinfo
                #print jres
                jthing['p'+port]=jres
            except Exception as e:
                # something goes wrong, we just record what
                jthing['p'+port]=str(e)

        # update average
        ipend=time.time()
        thistime=ipend-ipstart
        peripaverage=((checkcount*peripaverage)+thistime)/(checkcount+1)
        #print ip,"time taken:",str(thistime),"average:",str(peripaverage)
        jthing['duration']=thistime
        jthing['average']=peripaverage

        bstr=jsonpickle.encode(jthing)
        del jthing
        out_f.write(bstr+"\n")
        del bstr

        # sleep a bit
        time.sleep(sleepval)

        # print something now and then to keep operator amused
        checkcount += 1
        #if checkcount % 100 == 0:
        if checkcount % 5 == 0:
            print("Freshly grabbing... did: " + str(checkcount) + " most recent ip " + ip + " average time/ip: " + str(peripaverage), file=sys.stderr)
        if checkcount % 1000 == 0:
            gc.collect()

out_f.close()

print("FreshGrab: Out of country: " + str(ooc), file=sys.stderr)

print("Ran ",sys.argv[0:]," finished at",time.asctime(time.localtime(time.time())),"average seconds/ip:",peripaverage, file=sys.stderr)
