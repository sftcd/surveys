#!/usr/bin/python

# split a single JSON array on a single line of a file into
# an element per line file (so we can grep it)

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

needle=sys.argv[2].lower()
matches=[]
lines=0
with open(sys.argv[1],'r') as f:
    for line in f:
        j_content = json.loads(line)
        for k in j_content:
            strk=json.dumps(k).lower()
            if needle in strk:
                lines += 1
                matches.append(k)

outf=open('matches.json', 'w')
outf.write(json.dumps(matches)) 
outf.close()

print "Found " + str(lines) + " occurrences of " + needle + " in " + sys.argv[1] 

