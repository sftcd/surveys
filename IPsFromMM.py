import os, sys, argparse, tempfile, gc
import csv
import netaddr
import socket


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
def_v4file='GeoIPCountryWhois.csv'

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


dov4=True
if args.nov4:
    dov4=False

# can we read inputs?
nov4=False
if not os.access(v4file,os.R_OK):
    nov4=True



if dov4 and nov4:
    print(sys.stderr, "Can't read IPv4 input file " + v4file + " - exiting")
    sys.exit(1)


# can we write output?
if os.path.isfile(outfile) and not os.access(outfile,os.W_OK):
    print(sys.stderr, "Can't write onput file " + outfile + " - exiting")
    sys.exit(1)

#print "4: " + v4file + " do: " + str(dov4)
#print "6: " + v6file + " do: " + str(dov6)
#print "outfile: " + outfile + "[.v4|.v6]"

if dov4:
    data = []
    lc=0 # lines count
    mc=0 # matching count
    v4outfile=outfile+".v4"
    of=open(v4outfile,'w')
    with open(v4file) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        writer = csv.writer(of)
        for row in readCSV:
            if row[2]==country:
              cidr = row[0]
              data = [cidr]
              writer.writerow(data)
                mc+=1
            lc+=1
            if (lc%1000)==0:
                print(sys.stderr, "v4: read " + str(lc) + " records, " + str(mc) + " matching")
        of.close()
    print(sys.stderr, "v4: read " + str(lc) + " records, " + str(mc) + " matching")

