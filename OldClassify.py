#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

import sys
import json

def starttlsbanner(p25,file):
    try:
        if p25['smtp']['starttls']['starttls'] != "220 2.0.0 Ready to start TLS" :
            file.write(p25['smtp']['starttls']['starttls'] + '\n');
            return True
    except:
        return False
    return False


def good(p25):
    try:
        if p25['smtp']['starttls']['tls']['validation']['browser_trusted'] == True :
            return True
    except:
        return False
    return False

def medium(p25):
    try:
        if p25['smtp']['starttls']['tls']['signature']['valid'] == True :
            return True
    except:
        return False
    return False

def selfsigned(p25):
    try:
        if p25['smtp']['starttls']['tls']['certificate']['parsed']['signature']['self_signed'] == True \
             and p25['smtp']['starttls']['tls']['certificate']['parsed']['signature']['valid'] == True:
            return True
    except:
        return False
    return False

def badsig(p25):
    try:
        if p25['smtp']['starttls']['tls']['certificate']['parsed']['signature']['valid'] == False:
            return True
    except:
        return False
    return False

def bad(p25):
    try:
        if 'tls' not in p25['smtp']['starttls']:
            return True
    except:
        return False
    return False

with open(sys.argv[1],'r') as f:
    f0=open('outs/banner.json', 'w')
    f1=open('outs/good.json', 'w')
    f2=open('outs/medium.json', 'w')
    f3=open('outs/bad.json', 'w')
    f4=open('outs/dunno.json', 'w')
    f5=open('outs/selfsigned.json', 'w')
    f6=open('outs/badsig.json', 'w')
    overallcount=0
    goodcount=0
    bannercount=0
    mediumcount=0
    selfsignedcount=0
    badcount=0
    dunnocount=0
    badsigcount=0
    for line in f:
        j_content = json.loads(line)
        p25=j_content['p25']
        starttlsbanner(p25,f0)
        # note that above is independent of this
        if good(p25):
            f1.write(json.dumps(j_content) + '\n')
            goodcount += 1
        elif badsig(p25):
            f6.write(json.dumps(j_content) + '\n')
            badsigcount += 1
        elif medium(p25):
            f2.write(json.dumps(j_content) + '\n')
            mediumcount += 1
        elif selfsigned(p25):
            f5.write(json.dumps(j_content) + '\n')
            selfsignedcount += 1
        elif bad(p25):
            f3.write(json.dumps(j_content) + '\n')
            badcount += 1
        else:
            f4.write(json.dumps(j_content) + '\n')
            dunnocount += 1
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print "Did : " + str(overallcount)
        

print "banner: " + str(bannercount)
print "good: " + str(goodcount)
print "medium: " + str(mediumcount)
print "selfsigned: " + str(selfsignedcount)
print "badsig: " + str(badsigcount)
print "bad: " + str(badcount)
print "dunno: " + str(dunnocount)
print "overall: " + str(overallcount)
