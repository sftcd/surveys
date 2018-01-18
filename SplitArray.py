#!/usr/bin/python

# split a single JSON array on a single line of a file into
# an element per line file (so we can grep it)

import sys
import json
import socket
import datetime
from dateutil import parser # for parsing time from comand line and certs
import pytz # for adding back TZ info to allow comparisons

outf=open('split.json', 'w')
lines=0
with open(sys.argv[1],'r') as f:
    for line in f:
        j_content = json.loads(line)
        for k,row in enumerate(j_content):
            outf.write(json.dumps(j_content[k]) + '\n')
            lines += 1

outf.close()
print "Wrote " + str(lines) + " lines."

