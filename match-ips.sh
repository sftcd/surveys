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

#set -x

# count the number of IPs that involve a given string, starting from
# the original records.fresh's

TOPD="$HOME/data/smtp/runs"

DIRS="$TOPD/*-2018*"

function usage()
{
	echo "$0 <string>"
	echo "    Search the records.fresh files for a string and return per-run counts and total"
	exit 99
}

needle=$1
if [[ "$needle" == "" ]]
then
	echo "No input provided - exiting"
	usage
fi

total=0

echo "Looking for $needle below $TOPD"

for dir in $DIRS
do
	rcount=`grep -c $needle $dir/records.fresh`
	echo "$dir has $rcount"
	((total=total+rcount))
done

echo "Total is $total"



