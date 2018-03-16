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

# basic test of country code checker

import sys

sys.path.insert(0,'..')

from SurveyFuncs import *

mm_setup()

# down.dsg.cs.tcd.ie
ip='134.226.36.81'

country='IE'
if mm_ipcc(ip,country):
    print ip + " is in " + country
else:
    print ip + " is not " + country

country='nonexistent'
if mm_ipcc(ip,country):
    print ip + " is in " + country
else:
    print ip + " is not " + country

# ietf.org
ip='4.31.198.44'

country='IE'
if mm_ipcc(ip,country):
    print ip + " is in " + country
else:
    print ip + " is not " + country

country='nonexistent'
if mm_ipcc(ip,country):
    print ip + " is in " + country
else:
    print ip + " is not " + country

country='US'
if mm_ipcc(ip,country):
    print ip + " is in " + country
else:
    print ip + " is not " + country

