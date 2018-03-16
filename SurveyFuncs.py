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

import json
import jsonpickle
import copy
import graphviz as gv
import os, sys, socket
import geoip2.database
from dateutil import parser as dparser  # for parsing time from comand line and certs

# variious utilities for surveying

# using a class needs way less memory than random dicts apparently
class OneFP():
    __slots__ = [   'writer',
                    'ip_record',
                    'ip',
                    'asn',
                    'asndec',
                    'fprints',
                    'csize',
                    'nsrc',
                    'rcs',
                    'analysis']
    def __init__(self):
        self.writer='unknown'
        self.ip_record=-1
        self.ip=''
        self.asn=''
        self.asndec=0
        self.clusternum=0
        self.fprints={}
        self.csize=1
        self.nrcs=0
        self.rcs={}
        self.analysis={}

# some "constants" for the above
KEYTYPE_UNKNOWN=0           # initial value
KEYTYPE_RSASHORT=1          # <1024
KEYTYPE_RSA1024=2           # 1024<=len<2048
KEYTYPE_RSA2048=3           # exactly 2048 only
KEYTYPE_RSA4096=4           # exactly 4096 only
KEYTYPE_ODD=5               # anything else
KEYTYPE_ECDSA=6             # for those oddballs
KEYTYPE_EDDSA=6             # for those oddballs, when they start to show
KEYTYPE_OTHER=8             # if we do find something else, e.g. EDDSA

# some "constants" for certs
CERTTYPE_UNKNOWN=0          # initial value
CERTTYPE_GOOD=1             # browser-trusted and timely
CERTTYPE_SC=2               # self-cert and timely
CERTTYPE_EXPIRED=3          # browser-trusted but not timely
CERTTYPE_SCEXPIRED=4        # self-cert but not timely
CERTTYPE_OTHER=5            # oddbballs, don't expect any

def printOneFP(f):
    print jsonpickle.encode(f)

def j2o(jthing):
    ot=OneFP()
    #print json.dumps(jthing)
    ot.ip=jthing['ip']
    ot.ip_record=jthing['ip_record']
    ot.writer=jthing['writer']
    ot.asn=jthing['asn']
    ot.asndec=jthing['asndec']
    ot.clusternum=jthing['clusternum']
    ot.fprints=jthing['fprints']
    ot.csize=jthing['csize']
    ot.nrcs=jthing['nrcs']
    ot.rcs=jthing['rcs']
    ot.analysis=jthing['analysis']
    #printOneFP(ot)
    return ot

# to save memory we'll encode port collision information in a 
# compact form, we have six ports to consider 22,25,110,143,443 and 993
# and 25==25 is diferent from 25==143
# we use five octets, one for each local port;
# values are bitmasks, a set bit means the key on the remote
# port is the same as this one, so octet values can be:
# 0x00 no match
# 0x02 local port matches remote p25
# 0x06 local port matches remote p25 and p143
# etc


# note - had to rebuild graphviz locally for sfdp to work (and that had
# *loads* of compiler warnings and seems to crash on some graphs) if
# running on ubuntu version dot ok-ish works here but not sfdp
# graphing globals
#the_engine='circo'
#the_engine='dot'
#the_engine='neato'
the_engine='sfdp'
the_format='svg'
#the_format='png'
#the_format='dot'

# reverse map from bit# to string
# the above could be done better using this... but meh
portstrings=['p22','p25','p110','p143','p443','p587','p993']

# this is manually made symmetric around the diagonal
# variant - make all the mail colours the same
merged_nportscols=[ \
        'black',     'bisque', 'yellow', 'aquamarine','darkgray',    'chocolate',    'magenta', \
        'bisque',    'blue',   'blue',   'blue',      'violet',      'blue',         'blue', \
        'yellow',    'blue',   'blue',   'blue',      'coral',       'blue',         'blue', \
        'aquamarine','blue',   'blue',   'blue',      'darkkhaki',   'blue',         'blue', \
        'darkgray',  'violet', 'coral',  'darkkhaki', 'orange',      'darkseagreen', 'blue', \
        'turquoise', 'blue',   'blue',   'blue',      'blue',        'blue',         'blue',
        'magenta',   'blue',   'blue',   'blue',      'darkseagreen','blue',         'blue', ] 

# new way - individual colours per port-pair  - this is manually made symmetric around the diagonal
unmerged_nportscols=[ \
        'black',     'bisque',        'yellow',          'aquamarine', 'darkgray',     'turquoise',      'magenta', \
        'bisque',    'blue',          'blanchedalmond',  'crimson',    'violet',       'wheat',          'brown', \
        'yellow',    'blanchedalmond','chartreuse',      'cyan',       'coral',        'yellowgreen',    'darkred', \
        'aquamarine','crimson',       'cyan',            'darkblue',   'darkkhaki',    'chocolate',      'darksalmon', \
        'darkgray',  'violet',        'coral',           'darkkhaki',  'orange',       'cornsilk',       'darkseagreen', \
        'turquoise', 'wheat',         'yellowgreen',     'chocolate',  'cornsilk',     'deeppink',       'deepskyblue', \
        'magenta',   'brown',         'darkred',         'darksalmon', 'darkseagreen', 'deepskyblue',    'maroon', \
        ]

# pick one of these - the first merges many mail port combos
# leading to clearer graphs, the 2nd keeps all the details
# nportscols=merged_nportscols
nportscols=unmerged_nportscols

def indexport(index):
    return portstrings[index]

def portindex(pname):
    for pind in range(0,len(portstrings)):
        if portstrings[pind]==pname:
            return pind
    print >>sys.stderr, "Error - unknown port: " + pname
    return -1

def collmask(mask,k1,k2):
    try:
        lp=portindex(k1)
        rp=portindex(k2)
        intmask=int(mask,16)
        intmask |= (1<<(rp+8*lp)) 
        newmask="0x%016x" % intmask
    except Exception as e: 
        print >> sys.stderr, "collmask exception, k1: " + k1 + " k2: " + k2 + " lp:" + str(lp) + " rp: " + str(rp) + " exception: " + str(e)  
        pass
    return newmask

def expandmask(mask):
    emask=""
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                emask += indexport(i) + "==" + indexport(j) + ";"
    return emask

def readfprints(fname):
    try:
        f=open(fname,'r')
        fp=json.load(f)
        f.close()
        return fp
    except Exception as e: 
        print >> sys.stderr, "exception reading " + fname + " exception: " + str(e)  
        return None

def getnextfprint(fp):
    # read the next fingerprint from the file pointer
    # fprint is a json structure, pretty-printed, so we'll
    # read to the first line that's just an "{" until
    # the next line that's just a "}"
    line=fp.readline()
    while line:
        if line=="{\n":
            break
        line=fp.readline()
    jstr=""
    while line:
        jstr += line
        if line=="}\n": 
            break
        if line=="},\n":
            # same as above but take away the "," at the end
            #print "|"+jstr[-10:]+"|"
            jstr=jstr.strip()
            jstr=jstr.strip(',')
            #print "|"+jstr[-10:]+"|"
            break
        line=fp.readline()
    if line:
        #print jstr
        jthing=json.loads(jstr)
        onething=j2o(jthing)
        del jthing
        return onething
    else:
        return line

def mask2labels(mask, labels):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                labels.append(indexport(i) + "==" + indexport(j) )

# colours - return a list of logical-Or of port-specific colour settings
def mask2colours(mask, colours, dynleg):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                cnum=i*len(portstrings)+j
                colcode=nportscols[cnum]
                if colcode not in colours:
                    colours.append(colcode)
                    if i>j:
                        dynleg.add(portstrings[i]+"-"+portstrings[j]+" "+colcode)
                    else:
                        dynleg.add(portstrings[j]+"-"+portstrings[i]+" "+colcode)

def mask2fewercolours(mask, colours, dynleg):
    intmask=int(mask,16)
    portcount=len(portstrings)
    for i in range(0,portcount):
        for j in range(0,portcount):
            cmpmask = (1<<(j+8*i)) 
            if intmask & cmpmask:
                cnum=i*len(portstrings)+j
                colcode=merged_nportscols[cnum]
                if colcode not in colours:
                    colours.append(colcode)
                    # recall i and j index this: portstrings=['p22','p25','p110','p143','p443','p587','p993']
                    if i==0 and j==0:
                        dynleg.add("ssh"+" "+colcode)
                    elif i==4 and j==4:
                        dynleg.add("web"+" "+colcode)
                    elif (i==1 or i==2 or i==3 or i==5 or i==6) and (j==1 or j==2 or j==3 or j==5 or j==6):
                        dynleg.add("mail"+" "+colcode)
                    elif i>j:
                        dynleg.add(portstrings[i]+"-"+portstrings[j]+" "+colcode)
                    else:
                        dynleg.add(portstrings[j]+"-"+portstrings[i]+" "+colcode)

def printlegend():
    # make a fake graph with nodes for each port and coloured edges
    leg=gv.Graph(format=the_format,engine='neato',name="legend")
    leg.attr('graph',splines='true')
    leg.attr('graph',overlap='false')
    leg.attr('edge',overlap='false')
    portcount=len(portstrings)
    c=0
    for i in range(0,portcount):
        for j in range(0,portcount):
            cnum=i*len(portstrings)+j
            colcode=nportscols[cnum]
            portpair = portstrings[i] + "-" + portstrings[j] 
            leg.edge(portstrings[i],portstrings[j],color=colcode)
    leg.render("legend.dot")

def asn2colour(asn):
    asni=int(asn)
    if asni==0:
        return '#A5A5A5'
    else:
        return '#' + "%06X" % (asni&0xffffff)

def ip2int(ip):
    sip=ip.split(".")
    sip=list(map(int,sip))
    iip=sip[0]*256**3+sip[1]*256**2+sip[2]*256+sip[3]
    del sip
    return iip

def edgename(ip1,ip2):
    # string form consumes more memory
    #return ip1+"|"+ip2
    int1=ip2int(ip1)
    int2=ip2int(ip2)
    int3=int2*2**32+int1
    del int1
    del int2
    return int3

# MaxMind stuff

mmdbpath='code/surveys/mmdb/'
mmdbdir=os.environ['HOME']+'/'+mmdbpath

def mm_setup():
    global asnreader
    global cityreader
    global countryreader
    global countrycodes
    asnreader=geoip2.database.Reader(mmdbdir+'GeoLite2-ASN.mmdb')
    cityreader=geoip2.database.Reader(mmdbdir+'GeoLite2-City.mmdb')
    countryreader=geoip2.database.Reader(mmdbdir+'GeoLite2-Country.mmdb')
    countrycodes=[]
    with open(mmdbdir+'countrycodes.txt') as ccf:
        for line in ccf:
            cc=line.strip()
            countrycodes.append(cc)
    ccf.close()

def mm_info(ip):
    rv={}
    rv['ip']=ip
    asnresponse=asnreader.asn(ip)
    rv['asndec']=asnresponse.autonomous_system_number
    rv['asn']=asnresponse.autonomous_system_organization
    cityresponse=cityreader.city(ip)
    countryresponse=countryreader.country(ip)
    #print asnresponse
    #print cityresponse
    rv['lat']=cityresponse.location.latitude
    rv['long']=cityresponse.location.longitude
    #print "\n"
    #print "\n"
    #print countryresponse
    rv['cc']=cityresponse.country.iso_code
    if cityresponse.country.iso_code != countryresponse.country.iso_code:
        rv['cc-city']=cityresponse.country.iso_code
    return rv

def mm_ipcc(ip,cc):
    # is cc really a country code? can come from command line, so check...
    if cc not in countrycodes:
        return False
    countryresponse=countryreader.country(ip)
    if cc == countryresponse.country.iso_code:
        return True
    else:
        return False

# analyse the tls details - this ought work for other ports as
# well as p25
# scandate is needed to check if cert was expired at time of
# scan
def get_tls(writer,portstr,tls,ip,tlsdets,scandate):
    #print tls
    try:
        # we'll put each in a try/except to set true/false values
        # would chain work in browser
        # two flavours of TLS struct - one from Censys and one from local zgrabs
        # first is the local variant, 2nd censys.io
        if writer == 'FreshGrab.py':
            # local
            tlsdets['cipher_suite']=tls['server_hello']['cipher_suite']['value']
            tlsdets['browser_trusted']=tls['server_certificates']['validation']['browser_trusted']
            tlsdets['self_signed']=tls['server_certificates']['certificate']['parsed']['signature']['self_signed']
            notbefore=dparser.parse(tls['server_certificates']['certificate']['parsed']['validity']['start'])
            notafter=dparser.parse(tls['server_certificates']['certificate']['parsed']['validity']['end'])

            try:
                spki=tls['server_certificates']['certificate']['parsed']['subject_key_info']
                if spki['key_algorithm']['name']=='RSA':
                    tlsdets['rsalen']=spki['rsa_public_key']['length']
                elif spki['key_algorithm']['name']=='ECDSA':
                    tlsdets['ecdsacurve']=spki['ecdsa_public_key']['curve']
                else:
                    tlsdets['spkialg']=spki['key_algorithm']['name']
            except:
                print >>sys.stderr, "RSA exception for ip: " + ip + "spki:" + \
                                str(tls['server_certificates']['certificate']['parsed']['subject_key_info']) 
                tlsdets['spkialg']="unknown"

        else:
            # censys.io
            tlsdets['cipher_suite']=int(tls['cipher_suite']['id'],16) 
            tlsdets['browser_trusted']=tls['validation']['browser_trusted']
            tlsdets['self_signed']=tls['certificate']['parsed']['signature']['self_signed']
            notbefore=dparser.parse(tls['certificate']['parsed']['validity']['start'])
            notafter=dparser.parse(tls['certificate']['parsed']['validity']['end'])

            try:
                spki=tls['certificate']['parsed']['subject_key_info']
                if spki['key_algorithm']['name']=='rsa':
                    tlsdets['rsalen']=spki['rsa_public_key']['length']
                elif spki['key_algorithm']['name']=='ECDSA':
                    tlsdets['ecdsacurve']=spki['ecdsa_public_key']['curve']
                else:
                    tlsdets['spkialg']=spki['key_algorithm']['name']
            except:
                print >>sys.stderr, "RSA exception for ip: " + ip + "spki:" + \
                                str(tls['server_certificates']['certificate']['parsed']['subject_key_info']) 
                tlsdets['spkialg']="unknown"

        if (notbefore <= scandate and notafter > scandate):
            tlsdets['timely']=True
        elif (notbefore > scandate):
            tlsdets['timely']=False
        elif (notafter < scandate):
            tlsdets['timely']=False
        #tlsdets['ip']=ip
    except Exception as e: 
        print >>sys.stderr, "get_tls exception for " + ip + ":" + portstr + str(e)
        pass
    return True


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
def get_fqdns(blob):
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
    ip=blob['ip']
    try:
        # name from reverse DNS
        rdnsrec=socket.gethostbyaddr(ip)
        rdns=rdnsrec[0]
        print "FQDN reverse: " + str(rdns)
        nameset['rdns']=rdns
    except Exception as e: 
        print >> sys.stderr, "FQDN reverse exception " + str(e) + " for record:" + ip
        nameset['rdns']=''
    # name from banner
    p25=blob['p25']
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
    print nameset
    return nameset

def get_certnames(portstring,cert,nameset):
    try:
        dn=cert['parsed']['subject_dn'] 
        dn_fqdn=dn2cn(dn)
        nameset[portstring+'dn'] = dn_fqdn
    except Exception as e: 
        #print >> sys.stderr, "FQDN dn exception " + str(e) + " for record:" + str(count)
        pass
    # name from cert SAN
    try:
        sans=cert['parsed']['extensions']['subject_alt_name'] 
        san_fqdns=sans['dns_names']
        # we ignore all non dns_names - there are very few in our data (maybe 145 / 12000)
        # and they're mostly otherName with opaque OID/value so not that useful. (A few
        # are emails but we'll skip 'em for now)
        #print "FQDN san " + str(san_fqdns) 
        sancount=0
        for san in san_fqdns:
            nameset[portstring+'san'+str(sancount)]=san_fqdns[sancount]
            sancount += 1
    except Exception as e: 
        #these are v. common
        #print >> sys.stderr, "FQDN san exception " + str(e) + " for record:" + str(count)
        pass
    return


# OLD CODE below here, hasn't been fully re-integrated yet, will likely
# move up above and then ditch what's not wanted below

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

