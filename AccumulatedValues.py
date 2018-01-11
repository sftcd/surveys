#!/usr/bin/python

# To help figure out structure, accumulate one pesudo-record that has one
# of everything seen in all the outputs from CensysIESMTP.py

import sys
import json
import array

linecount=0
o_content={}

# main
with open(sys.argv[1],'r') as f:
    for line in f:
        j_content = json.loads(line)
        if o_content is not None:
            o_content=j_content.copy()
            #print json.dumps(o_content) + "\n"
        else:
            o_content = o_content.update(j_content)
            #print json.dumps(o_content) + "\n"
        linecount += 1


print json.dumps(o_content) + "\n"
#print "did " + str(linecount) + " lines"
