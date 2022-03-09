import os, sys, argparse, tempfile, gc
import json, jsonpickle
import time
import subprocess
import copy
from SurveyFuncs import *
import io

#Port list
# 22 - ssh
# 25 - smtp
# 80 - http
# 110 - pop3
# 143 - imap
# 443 - https/tls double check

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
args=parser.parse_args()

defports=['22', '25', '80' '110', '143', '443']

# default country 
def_country='IE'
country=def_country

# default timeout for zgrab, in seconds
ztimeout=' -timeout 2'

# port parameters
pparms={ 
        '22': 'ssh',
        '25': 'smtp',
        '80': 'http',
        '110': 'pop3',
        '143': 'imap',
        '443': 'tls',
        }

def usage():
    print (sys.stderr, "usage: " + sys.argv[0] + " -i <infile> -o <putfile> [-p <portlist>] [-s <sleepsecs>]")
    sys.exit(1)

ports=defports
if args.portstring is not None:
    ports=args.portstring.split(",")

if args.infile is None or args.outfile is None:
    usage()

# checks - can we read/write 
if not os.access(args.infile,os.R_OK):
    print (sys.stderr, "Can't read input file " + args.infile + " - exiting")
    sys.exit(1)
if os.path.isfile(args.outfile) and not os.access(args.outfile,os.W_OK):
    print (sys.stderr, "Can't write to output file " + args.outfile + " - exiting")
    sys.exit(1)

err_fn="/dev/null"
if args.errfile is not None:
    err_fn=args.errfile

print (sys.stderr, "Running ",sys.argv[0:]," starting at",time.asctime(time.localtime(time.time())))

defsleep=0.1
sleepval = defsleep
if args.sleepsecs is not None:
    sleepval=float(args.sleepsecs)
    print (sys.stderr, "Will sleep for " + str(sleepval) + " seconds between zgrabs")

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
        print (sys.stderr, "Excetion",args.outfile,"might end badly:",str(e))
        pass
    f.close()
    print (sys.stderr, "Loaded",str(pre_ips),"previously fetched records from",args.outfile)

out_f=open(args.outfile,"a")


with open(args.infile,'r') as f:
    checkcount=0
    ooc=0
    for ip in f:
        ip=ip.strip() # lose the CRLF

        ipstart=time.time()
        jthing={}
        jthing['ip']=ip
        jthing['writer']="FreshGrab.py"
        for port in ports:
            try:
                cmd='./zgrab2 '+  pparms[port]
                proc=subprocess.Popen(cmd.split(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                pc=proc.communicate(input=ip.encode())
                lines=pc[0].split(b'\n')
                # jinfo=json.loads(lines[1])
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
            print(sys.stderr, "Freshly grabbing... did: " + str(checkcount) + " most recent ip " + ip + " average time/ip: " + str(peripaverage))
        if checkcount % 1000 == 0:
            gc.collect()

out_f.close()

print(sys.stderr, "FreshGrab: Out of country: " + str(ooc))
print(sys.stderr, "Ran ",sys.argv[0:]," finished at",time.asctime(time.localtime(time.time())),"average seconds/ip:",peripaverage)