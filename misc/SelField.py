#!/usr/bin/python

# for any file with one json-dict/line, read it line by line
# decode and pretty-print it - thus allowing a less or grep
# to be used to see what's what

import sys
import json
import gc

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
with open(sys.argv[1],'r') as f:
    goodcount=0
    for line in f:
        goodcount+=1
        try:
            j_content = json.loads(line)
            bstr=jsonpickle.encode(j_content,unpicklable=False)
            print bstr
        except Exception as e:
            print >>sys.stderr, "Error at line: " + str(goodcount) + " " + str(e)
            

