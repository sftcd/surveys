#!/usr/bin/python

# grab just the IPs from a censys file 
# or any other with one json structure per line and an 'ip' key in that dict

import os, sys, argparse, gc
import json

# command line arg handling 
parser=argparse.ArgumentParser(description='grab IPs from a file with one json structure per line and an "ip" key in that dict')
parser.add_argument('-i','--input',     
                    dest='infile',
                    help='file containing list of IPs')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
args=parser.parse_args()

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> -o <putfile>" 
    sys.exit(1)

if args.infile is None:
    usage()

# checks - can we read/write 
if not os.access(args.infile,os.R_OK):
    print >> sys.stderr, "Can't read input file " + args.infile + " - exiting"
    sys.exit(1)
if os.path.isfile(args.outfile) and not os.access(args.outfile,os.W_OK):
    print >> sys.stderr, "Can't write to output file " + args.outfile + " - exiting"
    sys.exit(1)


out_f=open(args.outfile,"w")

with open(args.infile,'r') as f:
    checkcount=0
    goodcount=0
    badcount=0
    for line in f:
        jthing=json.loads(line)
        if 'ip' in jthing:
            ip=jthing['ip']
            out_f.write(ip+'\n')
            goodcount+=1
        else:
            badcount+=1

        # print something now and then to keep operator amused
        checkcount += 1
        if checkcount % 100 == 0:
            print >> sys.stderr, "Grabbing IPs... did: " + str(checkcount) + " most recent IP " + ip + \
                    " good: " + str(goodcount) + " bad: " + str(badcount)

        if checkcount % 1000 == 0:
            gc.collect()

out_f.close()
