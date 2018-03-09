#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

# this is really preliminary - eventually we'll want to construct
# SQL queries we can execute against the "live" censys data and to
# just get the reports from that, for now, we're doing it this was
# to understand the data better

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

#1. How many postfix did/didn't do tls
#1. How many named,non-postfix did/didn't do tls
#1. How many non-postfix did/didn't do tls

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
    not_self_signed=0
    expired=0
    too_early=0
    was_timely=0
    postfixes={"dotls":0,"notls":0,"bt":0,"ss":0,"exp":0,"v":0,"te":0}
    notpostfixes={"dotls":0,"notls":0,"bt":0,"ss":0,"exp":0,"v":0,"te":0}
    postfix_with_ss_names=[]
    postfix_with_bt_names=[]
    for line in f:
        try:
            j_content = json.loads(line)
            #print j_content
            thisname=''
            nameset=j_content['nameset']
            if nameset['meta']['besty']==[]:
                nogoodname += 1
            else:
                goodname += 1
                shortest=65536 # longest possible DNS name
                for besty in nameset['meta']['besty']:
                    thislen=len(nameset[besty])
                    if thislen>0 and thislen<shortest:
                        thisname=nameset[besty]
                        shortest=len(thisname)
            banner=j_content['banner']
            thisproduct=banner['product']
            products[thisproduct] = products.get(thisproduct,0) + 1
            tlsdets=j_content['tlsdets']
            thisoneis_tls=False
            thisoneis_bt=False
            thisoneis_ss=False
            thisoneis_exp=False
            thisoneis_v=False
            thisoneis_te=False
            try:
                if tlsdets['tls']==True:
                    thisoneis_tls=True
                    doestls += 1
                    if tlsdets['browser_trusted']=="True":
                        browser_trusted += 1
                        thisoneis_bt=True
                    else:
                        not_browser_trusted += 1
                    if tlsdets['self_signed']=="True":
                        self_signed += 1
                        thisoneis_ss=True
                    else:
                        not_self_signed += 1
                    if tlsdets['validthen']=='expired':
                        expired += 1
                        thisoneis_exp=True
                    elif tlsdets['validthen']=='too-early':
                        too_early += 1
                        thisoneis_te=True
                    elif tlsdets['validthen']=='good':
                        was_timely += 1
                        thisoneis_v=True
                else:
                    notls += 1
            except Exception as e: 
                notls += 1
            # count (not)postfixes...
            if thisoneis_tls:
                if thisproduct=="Postfix":
                    postfixes['dotls']+=1
                else:
                    notpostfixes['dotls']+=1
                if thisoneis_exp:
                    if thisproduct=="Postfix":
                        postfixes['exp']+=1
                    else:
                        notpostfixes['exp']+=1
                if thisoneis_bt:
                    if thisproduct=="Postfix":
                        postfixes['bt']+=1
                        if len(thisname)!=0:
                            postfix_with_bt_names.append(thisname)
                    else:
                        notpostfixes['bt']+=1
                if thisoneis_v:
                    if thisproduct=="Postfix":
                        postfixes['v']+=1
                    else:
                        notpostfixes['v']+=1
                if thisoneis_ss:
                    if thisproduct=="Postfix":
                        postfixes['ss']+=1
                        if len(thisname)!=0:
                            postfix_with_ss_names.append(thisname)
                    else:
                        notpostfixes['ss']+=1
                if thisoneis_te:
                    if thisproduct=="Postfix":
                        postfixes['te']+=1
                    else:
                        notpostfixes['te']+=1
            else:
                if thisproduct=="Postfix":
                    postfixes['notls']+=1
                else:
                    notpostfixes['notls']+=1

        except Exception as e: 
            print >> sys.stderr, "Exception: " + str(e) + " for record: " + str(overallcount)
        overallcount += 1
        

print "postfix:" + str(postfixes)
print "notpostfix:" + str(notpostfixes)

print "postfix_with_bt_names: " + str(len(postfix_with_bt_names))
print "postfix_with_ss_names: " + str(len(postfix_with_ss_names))

ptotal=0
for p in products:
    ptotal += products[p]
ntotal= ptotal - products.get('noguess',0)
print "Products: total:" + str(ptotal) + " named: " + str(ntotal)
print "\tName, count, percent of all, percent of named"
for p in products:
    print "\t" + p + ","  + str(products[p]) + "," +  str(100*products[p]/ptotal) + "%," + str(100*products[p]/ntotal) + "%"

print >> sys.stderr, "Good-Name, " + \
            " yes, " + str(goodname) + "(" + str(100*goodname/(goodname+nogoodname)) + "%)" + \
            " no, " + str(nogoodname) + "(" + str(100*nogoodname/(goodname+nogoodname)) + "%), " + \
            " total," + str(goodname+nogoodname)

print >> sys.stderr, "Does-TLS, " + \
            " yes, " + str(doestls) + "(" + str(100*doestls/(doestls+notls)) + "%)" + \
            " no, " + str(notls)  + "(" + str(100*notls/(doestls+notls)) + "%)" + \
            " total," + str(doestls+notls)

print >> sys.stderr, "Self-signed, " +  \
            " yes, " + str(self_signed) + "(" + str(100*self_signed/(self_signed+not_self_signed)) + "%)" + \
            " no, " + str(not_self_signed) + "(" + str(100*not_self_signed/(self_signed+not_self_signed)) + "%)" + \
            " total," + str(self_signed+not_self_signed)

print >> sys.stderr, "Browser-Trusted, " +  \
            " yes, " + str(browser_trusted) + "(" + str(100*browser_trusted/(browser_trusted+not_browser_trusted)) + "%)" + \
            " no, " + str(not_browser_trusted) + "(" + str(100*not_browser_trusted/(browser_trusted+not_browser_trusted)) + "%)" + \
            " total," + str(browser_trusted+not_browser_trusted)

print >> sys.stderr, "Validity, " + \
            " good, " + str(was_timely) + "(" + str(100*was_timely/(was_timely+expired+too_early)) + "%)" \
            " expired, " + str(expired) + "(" + str(100*expired/(was_timely+expired+too_early)) + "%)" \
            " too-early," + str(too_early) + "(" + str(100*too_early/(was_timely+expired+too_early)) + "%)" \
            " total," + str(was_timely+expired+too_early)
print >> sys.stderr, "overall: " + str(overallcount) 

# this gets zapped on each time (for now)
pbt=open('postfix-bt.json', 'w')
pbt.write(json.dumps(postfix_with_bt_names) + '\n')
pbt.close()

# this gets zapped on each time (for now)
pss=open('postfix-ss.json', 'w')
pss.write(json.dumps(postfix_with_ss_names) + '\n')
pss.close()

