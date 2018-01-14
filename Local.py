#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py
# this one just tries to see if the enrties are really local

import sys
import json
import socket
import datetime

# Extract a CN= from a DN, if present - moar curses on the X.500 namers!
# mind you, X.500 names were set in stone in 1988 so it's a bit late. 
# Pity we still use 'em though. 
def dn2cn(dn):
    try:
        start_needle="CN="
        start_pos=dn.find(start_needle)
        if start_pos==-1:
            # no commonName there... bail
            return ''
        start_pos += len(start_needle)
        end_needle=","
        end_pos=dn.find(end_needle,start_pos)
        if end_pos==-1:
            end_pos=len(dn)
        cnstr=dn[start_pos:end_pos]
        #print "dn2cn " + cnstr + " d: " + dn + " s: " + str(start_pos) + " e: " + str(end_pos) 
    except Exception as e: 
        print >> sys.stderr, "dn2cn exception " + str(e)
        return ''
    return cnstr

# check if supposed domain name is a bogon so as to avoid
# doing e.g. DNS checks
def fqdn_bogon(dn):
    try:
        # if there are no dots, for us, it's bogus
        if dn.find('.')==-1:
            return True
        # if it ends-with ".internal" it's bogus
        if dn.endswith(".internal"):
            return True
        # if it ends-with ".example.com" it's bogus
        if dn.endswith("example.com"):
            return True
        # if it ends-with ".localdomain" it's bogus
        if dn.endswith(".localdomain"):
            return True
        # if it ends-with ".local" it's bogus
        if dn.endswith(".local"):
            return True
        # if it ends-with ".arpa" it's bogus
        if dn.endswith(".arpa"):
            return True
        # if it's ESMTP it's bogus
        if dn=="ESMTP":
            return True
        # wildcards are also bogons
        if dn.find('*') != -1:
            return True
    except:
        return True
    return False
    

# figure out what names apply - return the set of names we've found
# and not found in a dict
def get_fqdns(count,p25,ip):
    # make empty dict
    nameset={}
    # metadata in our return dict is in here, the rest are names or
    # empty strings - note the names may well be bogus and not be
    # real fqdns at this point
    meta={}
    # note when we started - since we'll likely be doing DNS queries
    # the end-start time won't be near-zero;-(
    meta['startddate']=str(datetime.datetime.utcnow())
    # name from reverse dns of ip
    try:
        # name from reverse DNS
        rdnsrec=socket.gethostbyaddr(ip)
        rdns=rdnsrec[0]
        #print "FQDN reverse: " + rdns
        nameset['rnds']=rdns
    except Exception as e: 
        print >> sys.stderr, "FQDN reverse exception " + str(e) + " for record:" + str(count)
        nameset['rnds']=''
    # name from banner
    try:
        banner=p25['smtp']['starttls']['banner'] 
        ts=banner.split()
        banner_fqdn=ts[1]
        nameset['banner']=banner_fqdn
    except Exception as e: 
        print >> sys.stderr, "FQDN banner exception " + str(e) + " for record:" + str(count)
        nameset['banner']=''
    try:
        dn=p25['smtp']['starttls']['tls']['certificate']['parsed']['subject_dn'] 
        dn_fqdn=dn2cn(dn)
        #print "FQDN dn " + dn_fqdn
        nameset['dn']=dn_fqdn
    except Exception as e: 
        print >> sys.stderr, "FQDN dn exception " + str(e) + " for record:" + str(count)
        nameset['dn']=''
    # name from cert SAN
    try:
        sans=p25['smtp']['starttls']['tls']['certificate']['parsed']['extensions']['subject_alt_name'] 
        san_fqdns=sans['dns_names']
        # we ignore all non dns_names - there are very few in our data (maybe 145 / 12000)
        # and they're mostly otherName with opaque OID/value so not that useful. (A few
        # are emails but we'll skip 'em for now)
        #print "FQDN san " + str(san_fqdns) 
        sancount=0
        for san in san_fqdns:
            nameset['san'+str(sancount)]=san_fqdns[sancount]
            sancount += 1
    except Exception as e: 
        print >> sys.stderr, "FQDN san exception " + str(e) + " for record:" + str(count)
        nameset['san0']=''

    besty=[]
    nogood=True # assume none are good
    # try verify names a bit
    for k in nameset:
        v=nameset[k]
        #print "checking: " + k + " " + v
        # see if we can verify the value as matching our give IP
        if v != '' and not fqdn_bogon(v):
            try:
                rip=socket.gethostbyname(v)
                if rip == ip:
                    besty.append(k)
                else:
                    meta[k+'-ip']=rip
                # some name has an IP, even if not what we expect
                nogood=False
            except:
                print >> sys.stderr, "Error making DNS query for " + v + " for record:" + str(count)

    meta['allbad']=nogood
    meta['besty']=besty
    meta['enddate']=str(datetime.datetime.utcnow())
    meta['orig-ip']=ip
    nameset['meta']=meta
    return nameset

def p_banner(p25):
    try:
        print "banner: " + p25['smtp']['starttls']['banner'] ;
        return True
    except:
        return False
    return False

def p_ehlo(p25):
    try:
        print "ehlo: " + p25['smtp']['starttls']['ehlo'] ;
        return True
    except:
        return False
    return False

def p_starttlsbanner(p25):
    try:
        print "starttls: " + p25['smtp']['starttls']['starttls'] ;
        return True
    except:
        return False
    return False

bads={}

with open(sys.argv[1],'r') as f:
    overallcount=0
    badcount=0
    goodcount=0
    bannercount=0
    for line in f:
        j_content = json.loads(line)
        p25=j_content['p25']
        print "\nRecord: " + str(overallcount) + ":"
        dodgy=False
        nameset=get_fqdns(overallcount,p25,j_content['ip'])
        print nameset
        if not p_banner(p25):
            dodgy=True
        if not p_starttlsbanner(p25):
            dodgy=True
        if not p_ehlo(p25):
            dodgy=True
        if not dodgy:
            goodcount += 1
        else:
            bads[badcount]=j_content
            badcount += 1
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print >> sys.stderr, "Did : " + str(overallcount)

# this gets crapped on each time (for now)
badf=open('dodgy.json', 'w')
badf.write(json.dumps(bads) + '\n')
badf.close()

print >> sys.stderr, "overall: " + str(overallcount) + " good: " + str(goodcount) + " bad: " + str(badcount) + "\n"
