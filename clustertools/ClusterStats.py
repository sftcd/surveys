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

# Count values for cluster that we report on in tablular form:
# Cluster 		
# Graph		
# IPs 	
# ASes 		
# AS type(s) 	
# Crypto Ports 
# SSH ports
# SSH keys
# TLS ports
# TLS keys 
# BT certs
# WC certs
# Max Key Use  
# Since..

import sys
import os
import tempfile
import gc
import copy
import argparse
import datetime
import pytz # for adding back TZ info to allow comparisons

import re # for runname 

import time
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import binascii

from pympler import asizeof

codedir=os.path.dirname(os.path.realpath(__file__))
pdir=os.path.dirname(codedir)

sys.path.insert(0,pdir)
from SurveyFuncs import *

def usage():
    print 'Generate some cluster stats'
    print 'usage: ' + sys.argv[0] + ' -i <filenames> [-l] [-t <collectivetablename>]'
    print '    filenames must be space-sep (if >1) and enclosed in quotes on command line'
    print '    -l means produce latex output'
    print '    -t is needed for the table name if latex output chosen and >1 file input'
    sys.exit(99)

# command line arg handling 
parser=argparse.ArgumentParser(description='Generate some cluster stats')
parser.add_argument('-l','--latex',
                    help='produce latex output',
                    action='store_true')
parser.add_argument('-t','--tablab',     
                    dest='tablab',
                    help='collective name for set of clusters')
parser.add_argument('-i','--infile',     
                    dest='fnames',
                    help='cluster file name')
args=parser.parse_args()

if args.fnames is None:
    usage()
    sys.exit(2)

if args.latex and args.tablab is None:
    usage()
    sys.exit(0)

# main line processing ...


checkcount=0

fnames = args.fnames
if not args.latex:
    print >>sys.stderr, "Reading " + fnames

cstats={}

def runname(fname):
    # return country code from run name e e.g. "IE" given something like "cluster111.json" or "/home/foo/bar/IE-YYYYblah/cluster111.json"
    rn=""
    dname=os.path.realpath("./"+fname)
    m=re.search('/(..)-201[89]',dname)
    if m:
        rn=m.group(1)
    #print "dname= " + dname + " rn= " + rn
    return rn

# mainline code

for fname in fnames.split(' '):

    asns=set()
    sshkeys=set()
    tlskeys=set()
    fpsseen={}
    portcount=0
    sshports=0
    tlsports=0
    btcerts=0
    wccerts=0

    if not os.path.isfile(fname):
        continue

    # open file
    fp=open(fname,"r")
    if fp:
        f=getnextfprint(fp)

        # if parent dir doesn't match XX-YYYY* naming pattern, the sname 
        # could be odd/collide, but should mostly be ok
        sname=runname(fname)+str(f.clusternum)
        cstats[sname]={}
        cstats[sname]['cnum']=f.clusternum
        cstats[sname]['csize']=f.csize

        # not sure why I print this here but sure why not:-)
        if not args.latex:
            print 'ClusterNumber:' + str(f.clusternum)
            print 'ClusterSize:' + str(f.csize)

        while f:
    
            try:
                asns.add(f.asndec)
    
                for port in f.fprints:
                    if f.fprints[port] in fpsseen:
                        fpsseen[f.fprints[port]] += 1
                    else:
                        fpsseen[f.fprints[port]] = 1
                    portcount+=1
                    if port == 'p22':
                        sshports+=1
                        sshkeys.add(f.fprints['p22'])
                    else:
                        tlsports+=1
                        tlskeys.add(f.fprints[port])
                        somewc=False
                        if f.analysis[port]['browser_trusted']:
                            btcerts+=1
                            # wild cards must be btowser-trusted to be counted
                            if port+'dn' in f.analysis['nameset']:
                                if '*' in f.analysis['nameset'][port+'dn']:
                                    somewc=True
                                sanind=0
                                while port+'san'+str(sanind) in f.analysis['nameset']:
                                    if '*' in f.analysis['nameset'][port+'san'+str(sanind)]:
                                        somewc=True
                                    sanind+=1
                        if somewc:
                            wccerts+=1
    
    
            except Exception as e: 
                print >>sys.stderr, "Error with " + f.ip + " " + str(e)
                pass

            # print something now and then to keep operator amused
            checkcount += 1
            if checkcount % 100 == 0:
                print >> sys.stderr, "Counting browser-trusted stuff, host: " + str(checkcount) 
            if checkcount % 1000 == 0:
                gc.collect()
    
            # read next fp
            f=getnextfprint(fp)
    
    # close file
    fp.close()

    mostcommonkey=0
    mcfp=''
    for fp in fpsseen:
        if fpsseen[fp] > mostcommonkey:
            mostcommonkey=fpsseen[fp]
            mcfp=fp
    
    kdiff = len(fpsseen)-(len(sshkeys)+len(tlskeys)) 
    if kdiff != 0:
        print "odd #2keys, all=" + str(len(fpsseen)) + " ssh="+str(len(sshkeys))+ " tls="+str(len(tlskeys)) + " diff="+str(kdiff)


    cstats[sname]['asns']=len(asns)
    cstats[sname]['portcount']=portcount
    cstats[sname]['sshports']=sshports
    cstats[sname]['sshkeys']=len(sshkeys)
    cstats[sname]['tlsports']=tlsports
    cstats[sname]['tlskeys']=len(tlskeys)
    cstats[sname]['btcerts']=btcerts
    cstats[sname]['wccerts']=wccerts
    cstats[sname]['mostcommonkey']=mostcommonkey

    if not args.latex:
        print "ASes: " + str(len(asns))
        print "Ports: " + str(portcount)
        print "SSHPorts: " +str(sshports)
        print "SSHKeys : " +str(len(sshkeys))
        print "TLSPorts: " +str(tlsports)
        print "TLSKeys : " +str(len(tlskeys))
        print "BTCerts : " +str(btcerts)
        print "WCCerts : " +str(wccerts)
        print "MaxKey: " + str(mostcommonkey)

totals={}
totals['csize'] = 0
totals['asns'] = 0
totals['portcount'] = 0
totals['sshports'] = 0
totals['sshkeys'] = 0
totals['tlsports'] = 0
totals['tlskeys'] = 0
totals['btcerts'] = 0
totals['wccerts'] = 0

if len(fnames.split(' ')) > 1:
    for k in cstats:
        #print k
        # accumulate totals, where relevant
        totals['csize'] += cstats[k]['csize']
        totals['asns'] += cstats[k]['asns']
        totals['portcount'] += cstats[k]['portcount']
        totals['sshports'] += cstats[k]['sshports']
        totals['sshkeys'] += cstats[k]['sshkeys']
        totals['tlsports'] += cstats[k]['tlsports']
        totals['tlskeys'] += cstats[k]['tlskeys']
        totals['btcerts'] += cstats[k]['btcerts']
        totals['wccerts'] += cstats[k]['wccerts']
    if not args.latex:
        print totals

if args.latex:
    # dump out in latex happy form
    # print cstats

    print '\\begin{table*}'
    print '\\centering'
    print '\caption{Summary of ' + args.tablab + ' clusters.}'

    theline = '\\begin{tabular} { | l | '
    for k in cstats:
        theline += ' c | '
    theline += ' c | }' # last one for totals 
    print theline + "\n\\hline"

    theline = "Name " 
    for k in cstats:
        theline += " & " + k
    print theline + " & Total  \\\\ \hline"
    print '\\hline'

    theline = "IP addrs " 
    for k in cstats:
        theline += " & " + str(cstats[k]['csize'])
    print theline + " & " + str(totals['csize']) + " \\\\ \hline"

    theline = "ASes " 
    for k in cstats:
        theline += " & " + str(cstats[k]['asns'])
    print theline + " & " + str(totals['asns']) + " \\\\ \hline"

    theline = "Port count " 
    for k in cstats:
        theline += " & " + str(cstats[k]['portcount'])
    print theline + " & " + str(totals['portcount']) + " \\\\ \hline"

    theline = "SSH ports " 
    for k in cstats:
        theline += " & " + str(cstats[k]['sshports'])
    print theline + " & " + str(totals['sshports']) + " \\\\ \hline"

    theline = "SSH keys " 
    for k in cstats:
        theline += " & " + str(cstats[k]['sshkeys'])
    print theline + " & " + str(totals['sshkeys']) + " \\\\ \hline"

    theline = "TLS ports " 
    for k in cstats:
        theline += " & " + str(cstats[k]['tlsports'])
    print theline + " & " + str(totals['tlsports']) + " \\\\ \hline"

    theline = "TLS Keys " 
    for k in cstats:
        theline += " & " + str(cstats[k]['tlskeys'])
    print theline + " & " + str(totals['tlskeys']) + " \\\\ \hline"

    theline = "B-T certs " 
    for k in cstats:
        theline += " & " + str(cstats[k]['btcerts'])
    print theline + " & " + str(totals['btcerts']) + " \\\\ \hline"

    theline = "W/C certs " 
    for k in cstats:
        theline += " & " + str(cstats[k]['wccerts'])
    print theline + " & " + str(totals['wccerts']) + " \\\\ \hline"

    theline = "Most key re-uses " 
    for k in cstats:
        theline += " & " + str(cstats[k]['mostcommonkey'])
    print theline + " &  \\\\ \hline"

    print '\\hline'
    print '\end{tabular}'
    print '\label{tab:'+args.tablab+'}'
    print '\end{table*}'

    print 'Table \\ref{tab:'+args.tablab+'} summaries the clusters in ' + args.tablab + '.' 

if not args.latex:
    print "Overall:" + str(checkcount) 
