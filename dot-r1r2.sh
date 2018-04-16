#!/bin/bash

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

# set -x

# Make a dot file comparing IP address and fingerprint overlaps
# between clusters of two runs from the same population.

# We've manually done the calls to ipoverlaps.sh and fpoverlaps.sh
# for IE-20171130 and IE-20180316 already. TODO: add those here

# shortnames for runs. TODO: Add fullnames as argument, derive shortnames
r1f="$HOME/data/smtp/runs/IE-20171130-000000"
r2f="$HOME/data/smtp/runs/IE-20180316-181141"
r1s="17"
r2s="18"

# node colours
r1ncol="orange"
r2ncol="green"

# edge colours
ipfwdcol="black"
iprevcol="blue"
fpfwdcol="red"
fprevcol="gray"

# working dir. TODO: derive from arguments
wdir="$HOME/data/smtp/runs/ie-17-18"

# output files from fpoverlaps.sh and ipoverlaps.sh
ipfwd="ip$r1s$r2s.out"
iprev="ip$r2s$r1s.out"
fpfwd="fp$r1s$r2s.out"
fprev="fp$r2s$r1s.out"

# node names for r1
r1nodes=`ls -v $r1f/cluster*.json | sed -e 's/.*cluster//' | sed -e 's/\.json//'`
r2nodes=`ls -v $r2f/cluster*.json | sed -e 's/.*cluster//' | sed -e 's/\.json//'`

for node in $r1nodes
do
	echo "$r1s-$node [color=$r1ncol]"
done
for node in $r2nodes
do
	echo "$r2s-$node [color=$r2ncol]"
done
