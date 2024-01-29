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

# Write out IP ranges from the country in question in a form zmap can take
# 'em as input

import os, sys, argparse, tempfile, gc
import csv
import ipaddress

# command line arg handling 
parser=argparse.ArgumentParser(description='Write out IP ranges from the country in question')
parser.add_argument('-i','--input-dir',     
                    dest='indir',
                    help='directory name containing list of IPs in ccv files')
parser.add_argument('-4','--ipv4',
                    dest='v4file',
                    help='file name containing maxmind IPv4 address ranges for countries')
parser.add_argument('-6','--ipv6',
                    dest='v6file',
                    help='file name containing maxmind IPv6 address ranges for countries')
parser.add_argument('--nov4',
                    dest='nov4',
                    help='don\'t bother with IPv4', action='store_true')
parser.add_argument('--nov6',
                    dest='nov6',
                    help='don\'t bother with IPv6', action='store_true')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='file in which to put stderr output from zgrab')
args=parser.parse_args()

def_country="IE"
def_indir=os.environ['HOME']+'/code/surveys/mmdb'
def_outfile="mm-ips."+def_country
def_v4file='GeoLite2-Country-Blocks-IPv4.csv'
def_v6file='GeoLite2-Country-Blocks-IPv6.csv'

country=def_country
indir=def_indir
outfile=def_outfile

if args.country is not None:
    country=args.country
    outfile="mm-ips."+country

if args.indir is not None:
    indir=args.indir

if args.outfile is not None:
    outfile=args.outfile

if args.v4file is not None:
    v4file=indir+'/'+args.v4file
else:
    v4file=indir+'/'+def_v4file

if args.v6file is not None:
    v6file=indir+'/'+args.v6file
else:
    v6file=indir+'/'+def_v6file

dov4=True
if args.nov4:
    dov4=False

dov6=True
if args.nov6:
    dov6=False

# can we read inputs?
nov4=False
if not os.access(v4file,os.R_OK):
    nov4=True

nov6=False
if not os.access(v6file,os.R_OK):
    nov6=True

if dov4 and nov4:
    print("Can't read IPv4 input file " + v4file + " - exiting", file=sys.stderr)
    sys.exit(1)

if dov6 and nov6:
    print("Can't read IPv6 input file " + v6file + " - exiting", file=sys.stderr)
    sys.exit(1)

# can we write output?
if os.path.isfile(outfile) and not os.access(outfile,os.W_OK):
    print("Can't write output file " + outfile + " - exiting", file=sys.stderr)
    sys.exit(1)

#print "4: " + v4file + " do: " + str(dov4)
#print "6: " + v6file + " do: " + str(dov6)
#print "outfile: " + outfile + "[.v4|.v6]"

if dov4:
    lc=0 # lines count
    mc=0 # matching count
    v4outfile=outfile+".v4"
    of=open(v4outfile,'w')
    with open(v4file) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            if row[2]=="2963597":
                network=row[0]
                net = ipaddress.ip_network(network)
                for ip in net.hosts():
                    print(str(ip), file=of)
                mc+=1
            lc+=1
            if (lc%1000)==0:
                print("v4: read " + str(lc) + " records, " + str(mc) + " matching", file=sys.stderr)
        of.close()
    print("v4: read " + str(lc) + " records, " + str(mc) + " matching", file=sys.stderr)

if dov6:
    lc=0 # lines count
    mc=0 # matching count
    v6outfile=outfile+".v6"
    of=open(v6outfile,'w')
    with open(v6file) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            if row[2]==country:
                network=row[0]
                net = ipaddress.ip_network(network)
                for ip in net.hosts():
                    print(str(ip), file=of)
                mc+=1
            lc+=1
            if (lc%1000)==0:
                print("v6: read " + str(lc) + " records, " + str(mc) + " matching", file=sys.stderr)
        of.close()
    print("v6: read " + str(lc) + " records, " + str(mc) + " matching", file=sys.stderr)


