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

# Report the collisions, via graphs and text

import sys
import os
import tempfile
import gc
import copy
import argparse

from pympler import asizeof

from SurveyFuncs import *

# install via  "$ sudo pip install -U jsonpickle"
import jsonpickle

# direct to graphviz ...
import graphviz as gv

teststr='{ "foo": true, "bar": [ "baz" , "bat", "nerf" ] }'
js=json.loads(teststr)

jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)
print '"simplejson" backend:"'
fstr=jsonpickle.encode(js)
print fstr
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
fstr=jsonpickle.encode(js)
print '"json" backend:"'
print fstr

anFp=OneFP()

jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)
print '"simplejson" backend:"'
fstr=jsonpickle.encode(anFp)
print fstr
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
fstr=jsonpickle.encode(anFp)
print '"json" backend:"'
print fstr
