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

# extract some name related values from a cluster file

function usage()
{
	echo "Make a wordle from the names in a cluster file"
	echo "$0 [-i <space-sep list of files>]"
	echo "  list of files should be e.g. \"cluster1.json cluster200.json\" - quotes will be good if >1"
	exit 99
}

srcdir=$HOME/code/surveys
infile=$1
tmpf=`mktemp /tmp/wordle.XXXX`

( $srcdir/clustertools/fvs.sh -f banner -i $infile -u
$srcdir/clustertools/fvs.sh -f p[0-9]*dn -i $infile -u
$srcdir/clustertools/fvs.sh -f rnds -i $infile -u ) >$tmpf

wordcloud_cli.py --text $tmpf --no_collocations >$infile-wordle.png

rm -f $tmpf
