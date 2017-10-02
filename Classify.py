#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

import sys
import json

def good(p25):
    #print "good check: " + json.dumps(p25)
    if 'smtp' not in p25:
        return False
    if 'starttls' not in p25['smtp']:
        return False
    if 'tls' not in p25['smtp']['starttls']:
        return False
    if 'validation' not in p25['smtp']['starttls']['tls']:
        return False
    if 'browser_trusted' not in p25['smtp']['starttls']['tls']['validation']:
        return False
    if p25['smtp']['starttls']['tls']['validation']['browser_trusted'] == True :
        return True
    else:
        return False

def medium(p25):
    if 'smtp' not in p25:
        return False
    if 'starttls' not in p25['smtp']:
        return False
    if 'tls' not in p25['smtp']['starttls']:
        return False
    if 'signature' not in p25['smtp']['starttls']['tls']:
        return False
    if 'valid' not in p25['smtp']['starttls']['tls']['signature']:
        return False
    if p25['smtp']['starttls']['tls']['signature']['valid'] == True :
        #print json.dumps(p25)
        return True
    else:
        return False

def selfsigned(p25):
    if 'smtp' not in p25:
        return False
    if 'starttls' not in p25['smtp']:
        return False
    if 'tls' not in p25['smtp']['starttls']:
        return False
    if 'certificate' not in p25['smtp']['starttls']['tls']:
        return False
    if 'parsed' not in p25['smtp']['starttls']['tls']['certificate']:
        return False
    if 'signature' not in p25['smtp']['starttls']['tls']['certificate']['parsed']:
        return False
    if 'self_signed' not in p25['smtp']['starttls']['tls']['certificate']['parsed']['signature']:
        return False
    if p25['smtp']['starttls']['tls']['certificate']['parsed']['signature']['self_signed'] == True:
        return True
    else:
        return False

def bad(p25):
    if 'smtp' not in p25:
        return True
    if 'starttls' not in p25['smtp']:
        return True
    if 'tls' not in p25['smtp']['starttls']:
        return True
    else:
        return False

with open(sys.argv[1],'r') as f:
    f1=open('outs/good.json', 'w')
    f2=open('outs/medium.json', 'w')
    f3=open('outs/bad.json', 'w')
    f4=open('outs/dunno.json', 'w')
    f5=open('outs/exception.json', 'w')
    f6=open('outs/selfsigned.json', 'w')
    overallcount=0
    goodcount=0
    mediumcount=0
    selfsignedcount=0
    badcount=0
    dunnocount=0
    exceptioncount=0
    for line in f:
        j_content = json.loads(line)
        p25=j_content['p25']
        try:
            if good(p25):
                f1.write(json.dumps(j_content) + '\n')
                goodcount += 1
            elif medium(p25):
                f2.write(json.dumps(j_content) + '\n')
                mediumcount += 1
            elif selfsigned(p25):
                f6.write(json.dumps(j_content) + '\n')
                selfsignedcount += 1
            elif bad(p25):
                f3.write(json.dumps(j_content) + '\n')
                badcount += 1
            else:
                f4.write(json.dumps(j_content) + '\n')
                dunnocount += 1
        except :
            f5.write(json.dumps(j_content) + '\n')
            exceptioncount += 1
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print "Did : " + str(overallcount)
        

print "good: " + str(goodcount)
print "medium: " + str(mediumcount)
print "selfsigned: " + str(selfsignedcount)
print "bad: " + str(badcount)
print "dunno: " + str(dunnocount)
print "exception: " + str(exceptioncount)
print "overall: " + str(overallcount)
