#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

# this is our main line code, to read the output from Classify.py 
# and answer our questions (see questions.md)

#1. What names go with the record (LATER)
#1. Which have detectable good DNS names
#1. What product was in use
#1. Which did/didn't  do SMTP/TLS on port25
#1. Which were using browser-trusted certs
#1. Which were using self-signed certs only
#1. Which were using expired certs (self-signed or not)
#1. Which were using up-to-date/out-of-date software (LATER)

with open(sys.argv[1],'r') as f:
    overallcount=0
    goodname=0
    nogoodname=0
    products={}
    doestls=0
    notls=0
    browser_trusted=0
    not_browser_trusted=0
    self_signed=0
    expired=0
    too_early=0
    was_timely=0
    for line in f:
        try:
            j_content = json.loads(line)
            #print j_content
            nameset=j_content['nameset']
            if nameset['meta']['besty']==[]:
                nogoodname += 1
            else:
                goodname += 1
            tlsdets=j_content['tlsdets']
            if tlsdets['tls']==True:
                doestls += 1
                if tlsdets['browser_trusted']=="True":
                    browser_trusted += 1
                else:
                    not_browser_trusted += 1
                if tlsdets['validthen']=='expired':
                    expired += 1
                elif tlsdets['validthen']=='too-early':
                    too_early += 1
                elif tlsdets['validthen']=='good':
                    was_timely += 1
            else:
                notls += 1
            banner=j_content['banner']
            products[banner['product']] = products.get(banner['product'],0) + 1

        except Exception as e: 
            print >> sys.stderr, "Exception: " + str(e) + " for record: " + str(overallcount)
        overallcount += 1
        

print "Products: "
print "\tName, count"
for p in products:
    print "\t" + p + ","  + str(products[p])

print >> sys.stderr, "Good-Name, yes, " + str(goodname) + " no, " + str(nogoodname)  \
            + " total," + str(goodname+nogoodname)
print >> sys.stderr, "Does-TLS, yes, " + str(doestls) + " no, " + str(notls)  \
            + " total," + str(doestls+notls)
print >> sys.stderr, "Browser-Trusted, yes, " + str(browser_trusted) + " no, "  \
            + str(not_browser_trusted) + " total," + str(browser_trusted+not_browser_trusted)
print >> sys.stderr, "Validity, good, " + str(was_timely) \
            + " expired, " + str(expired) \
            + " too-early," + str(too_early) \
            + " total," + str(was_timely+expired+too_early)
print >> sys.stderr, "overall: " + str(overallcount) 
