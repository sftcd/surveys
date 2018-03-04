#!/usr/bin/python

import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time

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
args=parser.parse_args()

# default (all) ports to scan - added in 587 for fun (wasn't in original scans)
defports=['22', '25', '110', '143', '443', '587', '993']

# port parameters
pparms={ 
        '22': '-port 22 -xssh',
        '25': '-port 25 -smtp -starttls -banners',
        '110': '-port 110 -pop3 -starttls -banners',
        '143': '-port 143 -imap -starttls -banners',
        '443': '-port 443 -tls -http="/"',
        '587': '-port 587 -smtp -starttls -banners',
        '993': '-port 993 -imap -tls -banners',
        }

def usage():
    print >>sys.stderr, "usage: " + sys.argv[0] + " -i <infile> -o <putfile> [-p <portlist>]"
    sys.exit(1)

ports=defports
if args.portstring is not None:
    ports=args.portstring.split(",")

if args.infile is None or args.outfile is None:
    usage()

# checks - can we read/write 
if not os.access(args.infile,os.R_OK):
    print >> sys.stderr, "Can't read input file " + args.infile + " - exiting"
    sys.exit(1)
if os.path.isfile(args.outfile) and not os.access(args.outfile,os.W_OK):
    print >> sys.stderr, "Can't write to output file " + args.outfile + " - exiting"
    sys.exit(1)

err_fn="/dev/null"
if args.errfile is not None:
    err_fn=args.errfile

# default to a 100ms wait between zgrab calls
defsleep=0.1

sleepval=defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print "Will sleep for " + str(sleepval) + " seconds between zgrabs"

out_f=open(args.outfile,"w")

with open(args.infile,'r') as f:
    checkcount=0
    for ip in f:
        jthing={}
        ip=ip.strip() # lose the CRLF
        jthing['ip']=ip
        jthing['writer']="FreshGrab.py"
        # this is awkward - need to provide IP input in a file as the pipe we'd usually
        # use to pipe input to zgrab causes a file descriptor to be consumed in a way
        # that's not recovered. So we'll put the IP in a temp file and use that.
        tif=tempfile.mkstemp()
        ti=open(tif[1],"w")
        ti.write(ip)
        ti.close()
        for port in ports:
            tof=tempfile.mkstemp()
            command='zgrab ' + pparms[port] + " -input-file " + tif[1] + " -output-file=" + tof[1] + " >> " + err_fn + " 2>&1"
            #print command 
            rv=os.system(command)
            if rv:
                print "system call returned " + str(rv)
            else:
                # accumulate results
                with open(tof[1],"r") as resf:
                    for line in resf:
                        jthing['p'+port]=json.loads(line)
                resf.close()
            os.remove(tof[1])
        os.remove(tif[1])
        bstr=jsonpickle.encode(jthing)
        del jthing
        out_f.write(bstr+"\n")
        del bstr

        # sleep a bit
        time.sleep(sleepval)

        # print something now and then to keep operator amused
        checkcount += 1
        if checkcount % 100 == 0:
            print >> sys.stderr, "Freshly grabbing... did: " + str(checkcount) + " most recent ip " + ip
        if checkcount % 1000 == 0:
            gc.collect()

out_f.close()


