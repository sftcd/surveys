#!/usr/bin/python

# check if there are any non dns_name SANS in the output from
# CensysIESMTP.py

import sys
import json
import socket

def anythere(sans,thestr,ip):
    if sans[thestr]:
        print "anyoddnames:" + ip + " " + thestr + " " + str(sans[thestr])
    return

def anythere0(sans,thestr,ip):
    if sans[thestr][0]:
        print "anyoddnames:" + ip + " " + thestr + " " + str(sans[thestr][0])
    return

def anyoddsans(p25,ip):
    # name from cert SAN
    try:
        sans=p25['smtp']['starttls']['tls']['certificate']['parsed']['extensions']['subject_alt_name'] 
        anythere(sans,'ip_addresses',ip)
        # skip dns names - we do see those and will handle them later
        #anythere(sans,'dns_names',ip)
        anythere0(sans,'edi_party_names',ip)
        anythere(sans,'uniform_resource_identifiers',ip)
        anythere(sans,'email_addresses',ip)
        anythere0(sans,'other_names',ip)
        anythere(sans,'registered_ids',ip)
        anythere(sans,'directory_names',ip)
    except Exception as e: 
        #print "anyoddnames exception " + ip + " " + str(e)
        return False
    return True

with open(sys.argv[1],'r') as f:
    overallcount=0
    for line in f:
        j_content = json.loads(line)
        p25=j_content['p25']
        anyoddsans(p25,j_content['ip'])
        overallcount += 1
        if overallcount % 100 == 0:
            # exit early for debug purposes
            #break
            print >> sys.stderr, "Did : " + str(overallcount)

print >> sys.stderr, "overall: " + str(overallcount) 
