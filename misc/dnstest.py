#!/usr/bin/python

import dns.resolver
import socket
import sys
import datetime

# check timing for DNS queries

dnsname=sys.argv[1]
ip=''
rdns=''

# caching means just do one at a time, not sure where the caches for these different
# things are, but in real classifying uses, we'll almost all be cache misses

sockettest=True
try:
    if sys.argv[2]=='dns':
        sockettest=False
except:
    pass

if sockettest:

    start=datetime.datetime.utcnow()
    try:
        ip=socket.gethostbyname(dnsname)
    except Exception as e: 
        print >> sys.stderr, "dns exception " + str(e) + " for " + dnsname
    end=datetime.datetime.utcnow()
    d1=end-start
    start=datetime.datetime.utcnow()
    try:
        rdns=socket.gethostbyaddr(ip)
    except Exception as e: 
        print >> sys.stderr, "dns exception " + str(e) + " for " + dnsname
    end=datetime.datetime.utcnow()
    d2=end-start
    print "socket calls: for " + dnsname + ": forward: " + str(d1) + " reverse: " + str(d2) + " [" + ip + "," + str(rdns) + "]"

else:

    start=datetime.datetime.utcnow()
    try:
        answers=dns.resolver.query(dnsname,"A")
        for rdata in answers:
            #print rdata
            ip=str(rdata)
    except Exception as e: 
        print >> sys.stderr, "dns exception " + str(e) + " for " + dnsname
    end=datetime.datetime.utcnow()
    d1=end-start
    start=datetime.datetime.utcnow()
    try:
        req = '.'.join(reversed(ip.split("."))) + ".in-addr.arpa"
        answers = dns.resolver.query(req, "PTR")
        for rdata in answers:
            #print rdata
            rdns=str(rdata)
    except Exception as e: 
        print >> sys.stderr, "dns exception " + str(e) + " for " + dnsname
    end=datetime.datetime.utcnow()
    d2=end-start
    print "   dns calls: for " + dnsname + ": forward: " + str(d1) + " reverse: " + str(d2) + " [" + ip + "," + rdns + "]"

