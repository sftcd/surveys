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

# count different kinds of cluster smells...

function usage()
{
	echo "count different kinds of cluster smells..."
	echo "$0 <space-sep list of files>"
	exit 99
}

nfiles=$#

srcdir=$HOME/code/surveys/

if ((nfiles <= 0))
then
	usage
fi

tmpf=`mktemp /tmp/smellcountXXXX`

fcount=0

for file in $*
do
	echo "Checking $file"
	$srcdir/clustertools/MHSmelly.py -i $file -o $tmpf 
	fcount=$((fcount+1))
done

# count 'em up, note 1st 3 don't add up to 4th
mixedcount=`grep -c "Mixed smelly" $tmpf`
ascount=`grep -c "AS smelly" $tmpf`
sshcount=`grep -c "SSH smelly" $tmpf`
smellycount=`grep -c "General smelly" $tmpf`
mhcount=`grep -c "Possible Multi" $tmpf`
noinfo=$((fcount-(smellycount+mhcount)))

rm -f $tmpf

echo "Counted smells... for $*"
echo "Mixed: $mixedcount"
echo "AS: $ascount"
echo "SSH: $sshcount"
echo "Smelly Total: $smellycount"
echo "Possible MH: $mhcount"
echo "No info: $noinfo"
echo "Total clusters: $fcount"


