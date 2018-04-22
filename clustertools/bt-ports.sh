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

# see what's browser trusted for TLS ports for all ciusters in CWD

srcdir=$HOME/code/surveys

if [[ "$1" == "" ]]
then
	clusters=`ls -w 0 cluster*.json`
	ofileroot="cbt"
else
	# just expecting one really, otherwise names get mucked up
	clusters=$1
	cnum=`echo $clusters | sed -e 's/cluster//g' | sed -e 's/.json//g'`
	ofileroot="cbt-$cnum-p"
fi

for port in 25 110 143 443 587 993
do
	echo "Doing port " $port
	$srcdir/clustertools/ClusterPortBT.py -p $port -i "$clusters" >$ofileroot$port.out 2>$ofileroot$port.err
done
