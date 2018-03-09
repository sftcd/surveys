#!/usr/bin/python

# To help figure out structure, accumulate one pesudo-record that has one
# of everything seen in all the outputs from CensysIESMTP.py

# this still isn't quite doing what I want, but is useful nonetheless

import sys
import json
import array
import collections

def myupdate(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = myupdate(d.get(k, {}), v)
        else:
            d[k] = v
    return d

linecount = 0
o_content = dict()
with open(sys.argv[1],'r') as f:
    for line in f:
        j_content = json.loads(line)
        if not o_content:
            o_content=j_content
            # print "b1 " + o_content['ip']
        else:
            myupdate(o_content,j_content)
            # print "b2 " + o_content['ip']
        linecount += 1
        print >> sys.stderr, "did " + str(linecount) + " lines"


print json.dumps(o_content) 
