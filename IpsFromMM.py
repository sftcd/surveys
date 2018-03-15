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

# Write out IP ranges from the country in question in a form zmap can take
# 'em as input

import os, sys, argparse, tempfile, gc
import csv

# command line arg handling 
parser=argparse.ArgumentParser(description='Write out IP ranges from the country in question')
parser.add_argument('-i','--input-dir',     
                    dest='indir',
                    help='directory name containing list of IPs in ccv files')
parser.add_argument('-o','--output_file',     
                    dest='outfile',
                    help='file in which to put json records (one per line)')
parser.add_argument('-c','--country',     
                    dest='country',
                    help='file in which to put stderr output from zgrab')
args=parser.parse_args()

def_country="IE"
def_indir='/home/stephen/code/surveys/mmdb'
def_outpur="ips.zg.in"

country=def_country
indir=def_indir
output="."


