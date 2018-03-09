#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

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
    #meta={}
    # note when we started - since we'll likely be doing DNS queries
    # the end-start time won't be near-zero;-(
    #meta['startddate']=str(datetime.datetime.utcnow())
    # name from reverse dns of ip
    try:
        # name from reverse DNS
        rdnsrec=socket.gethostbyaddr(ip)
        rdns=rdnsrec[0]
        #print "FQDN reverse: " + rdns
        nameset['rdns']=rdns
    except Exception as e: 
        #print >> sys.stderr, "FQDN reverse exception " + str(e) + " for record:" + str(count)
        nameset['rdns']=''
    # name from banner
    try:
        banner=p25['smtp']['starttls']['banner'] 
        ts=banner.split()
        if ts[0]=="220":
            banner_fqdn=ts[1]
        elif ts[0].startswith("220-"):
            banner_fqdn=ts[0][4:]
        else:
            banner_fqdn=''
        nameset['banner']=banner_fqdn
    except Exception as e: 
        #print >> sys.stderr, "FQDN banner exception " + str(e) + " for record:" + str(count)
        nameset['banner']=''
    try:
        dn=p25['smtp']['starttls']['tls']['certificate']['parsed']['subject_dn'] 
        dn_fqdn=dn2cn(dn)
        #print "FQDN dn " + dn_fqdn
        nameset['dn']=dn_fqdn
    except Exception as e: 
        #print >> sys.stderr, "FQDN dn exception " + str(e) + " for record:" + str(count)
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
        #these are v. common
        #print >> sys.stderr, "FQDN san exception " + str(e) + " for record:" + str(count)
        nameset['san0']=''

    besty=[]
    nogood=True # assume none are good
    tmp={}
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
                    tmp[k+'-ip']=rip
                # some name has an IP, even if not what we expect
                nogood=False
            except Exception as e: 
                #oddly, an NXDOMAIN seems to cause an exception, so these happen
                #print >> sys.stderr, "Error making DNS query for " + v + " for record:" + str(count) + " " + str(e)
                pass
    for k in tmp:
        nameset[k]=tmp[k]

    nameset['allbad']=nogood
    nameset['besty']=besty
    #meta['enddate']=str(datetime.datetime.utcnow())
    #nameset['meta']=meta
    return nameset

# try guess what product we're dealing with
def guess_product(banner):
    try:
        if banner.lower().find('postfix')!=-1:
            return 'Postfix'
        if banner.lower().find('icewarp')!=-1:
            return 'Icewarp'
        if banner.lower().find('exim')!=-1:
            return 'Exim'
        if banner.lower().find('sendmail')!=-1:
            return 'Sendmail'
        if banner.lower().find('microsoft')!=-1:
            return 'Microsoft'
    except Exception as e: 
        print >> sys.stderr, "guess_product exception: " + str(e)
        return 'guess_exception'
    return 'noguess'

def get_banner(count,p25,ip):
    # we'll try parse the banner according to https://tools.ietf.org/html/rfc5321
    # and see how we get on, we're using the ABNF for "Greeting" from page 47 of
    # the RFC
    banner={}
    # metadata in our return dict is in here, the rest are names or
    # empty strings - note the names may well be bogus and not be
    # real fqdns at this point
    #meta={}
    try:
        bannerstr=p25['smtp']['starttls']['banner'] 
        banner['raw']=bannerstr
        bsplit=bannerstr.split(' ')
        try:
            censys_meta=p25['smtp']['starttls']['metadata']
            if censys_meta['product']!='':
                banner['product']=censys_meta['product']
            else:
                banner['product']=guess_product(bannerstr)
        except:
            banner['product']=guess_product(bannerstr)
        #print "get_banner: " + str(bsplit) + " for record: " + str(count)
    except Exception as e: 
        print >> sys.stderr, "get_banner error getting SMTP banner for ip: " + ip + " record:" + str(count) + " " + str(e)

    #banner['meta']=meta
    return banner

# analyse the tls details - this ought work for other ports as
# well as p25
# scandate is needed to check if cert was expired at time of
# scan
def get_tls(count,tls,ip,tlsdets,scandate):
    try:
        # we'll put each in a try/except to set true/false values
        # would chain work in browser
        try:
            tlsdets['browser_trusted']=str(tls['validation']['browser_trusted'])
        except:
            tlsdets['browser_trusted']='exception'
        try:
            tlsdets['self_signed']=str(tls['certificate']['parsed']['signature']['self_signed'])
        except:
            tlsdets['self_signed']='exception'
        try:
            tlsdets['cipher_suite']=tls['cipher_suite']['name']
        except:
            tlsdets['cipher_suite']='exception'
        try:
            notbefore=parser.parse(tls['certificate']['parsed']['validity']['start'])
            notafter=parser.parse(tls['certificate']['parsed']['validity']['end'])
            if (notbefore <= scandate and notafter > scandate):
                tlsdets['validthen']='good'
            elif (notbefore > scandate):
                tlsdets['validthen']='too-early'
            elif (notafter < scandate):
                tlsdets['validthen']='expired'
            tlsdets['validthen-date']=scandate
        except Exception as e: 
            #print >> sys.stderr, "get_tls error for ip: " + ip + " record:" + str(count) + " " + str(e)
            tlsdets['validthen']='exception'

        try:
            now=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
            if (notbefore <= now and notafter > now):
                tlsdets['validnow']='good'
            elif (notbefore > now):
                tlsdets['validnow']='too-early'
            elif (notafter < now):
                tlsdets['validnow']='expired'
            tlsdets['validnow-date']=now
        except Exception as e: 
            #print >> sys.stderr, "get_tls error for ip: " + ip + " record:" + str(count) + " " + str(e)
            tlsdets['validnow']='exception'
    except Exception as e: 
        #print >> sys.stderr, "get_tls error for ip: " + ip + " record:" + str(count) + " " + str(e)
        pass
    return True

# first check out the smtp starttls banner, then, if possible
# dive into tls details (via get_tls above)
def get_https(count,p443,ip,scandate):
    # usual pattern here 
    tlsdets = {} # tls details
    #meta={}
    #meta['startddate']=str(datetime.datetime.utcnow())
    tlsdets['tls']=False # pessimism
    try:
        try:
            biggie=p443['https']['tls']
            tlsdets['tls']=True
            get_tls(count,biggie,ip,tlsdets,scandate)
        except Exception as e: 
            pass
    except Exception as e: 
        pass
    return tlsdets

# first check out the smtp starttls banner, then, if possible
# dive into tls details (via get_tls above)
def get_smtpstarttls(count,p25,ip,scandate):
    # usual pattern here 
    tlsdets = {} # tls details
    #meta={}
    #meta['startddate']=str(datetime.datetime.utcnow())
    tlsdets['tls']=False # pessimism
    try:
        tlsbanner=p25['smtp']['starttls']['starttls']
        # keep raw banner
        tlsdets['banner']=tlsbanner
        tbsplit=tlsbanner.split()
        tlsdets['code']=int(tbsplit[0])
        try:
            biggie=p25['smtp']['starttls']['tls']
            tlsdets['tls']=True
            get_tls(count,biggie,ip,tlsdets,scandate)
        except Exception as e: 
            #print >> sys.stderr, "get_smtpstarttls error for ip: " + ip + " record:" + str(count) + " " + str(e)
            pass
    except Exception as e: 
        #print >> sys.stderr, "get_smtpstarttls error for ip: " + ip + " record:" + str(count) + " " + str(e)
        pass
    #meta['endddate']=str(datetime.datetime.utcnow())
    #tlsdets['meta']=meta
    return tlsdets

# hack for dict->json dates as per https://stackoverflow.com/questions/455580/json-datetime-between-python-and-javascript
date_handler = lambda obj: (
    obj.isoformat()
    if isinstance(obj, (datetime.datetime, datetime.date))
    else None
)

# this is our main line code, to read a censys output and to 
# classify it

# this is a dict to hold the set of records we can't classify,
# it'll be dumped to dodgy.json at the end, we'd like there to
# be as few of these as possible
bads={}

scandate=datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
try:
    scandate=parser.parse(sys.argv[2]).replace(tzinfo=pytz.UTC)
except:
    print >> sys.stderr, "No (or bad) scan time provided, using 'now'"

with open(sys.argv[1],'r') as f:
    overallcount=0
    badcount=0
    goodcount=0
    bannercount=0
    for line in f:
        j_content = json.loads(line)
        analysis={}
        #analysis['startdate']=str(datetime.datetime.utcnow())
        analysis['ip_record']=overallcount
        analysis['ip']=j_content['ip']
        analysis['scandate']=scandate
        p25=j_content['p25']
        #print "\nRecord: " + str(overallcount) + ":"
        dodgy=False
        analysis['nameset']=get_fqdns(overallcount,p25,j_content['ip'])
        analysis['smtp_banner']=get_banner(overallcount,p25,j_content['ip'])
        try: 
            analysis['p25-tlsdets']={}
            analysis['p25-tlsdets']=get_smtpstarttls(overallcount,p25,j_content['ip'],scandate)
        except:
            analysis['p25-tlsdets']['tls']=False
        try:
            analysis['p110-tlsdets']={}
            get_tls(overallcount,j_content['p110']['pop3']['starttls']['tls'],j_content['ip'],analysis['p110-tlsdets'],scandate)
        except:
            analysis['p110-tlsdets']['tls']=False
        try:
            analysis['p143-tlsdets']={}
            get_tls(overallcount,j_content['p143']['imap']['starttls']['tls'],j_content['ip'],analysis['p143-tlsdets'],scandate)
        except:
            analysis['p143-tlsdets']['tls']=False
        try:
            analysis['p443-tlsdets']={}
            get_tls(overallcount,j_content['p443']['https']['tls'],j_content['ip'],analysis['p443-tlsdets'],scandate)
        except:
            analysis['p443-tlsdets']['tls']=False
        try:
            analysis['p993-tlsdets']={}
            get_tls(overallcount,j_content['p993']['imaps']['tls']['tls'],j_content['ip'],analysis['p993-tlsdets'],scandate)
        except:
            analysis['p993-tlsdets']['tls']=False

        #analysis['enddate']=str(datetime.datetime.utcnow())
        #nicer output for vi
        #print json.dumps(analysis,default=date_handler,indent=2,sort_keys=True) 
        print json.dumps(analysis,default=date_handler)
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
