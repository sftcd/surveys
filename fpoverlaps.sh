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

# find overlapping keys between clusters in different runs
# this one is mainly intended for checking cross-border 
# run it pairwise e.g.:
# 	$ cd $HOME/data/smtp/runs
# 	$ fpoverlaps.sh -1 IE-20180316-181141 -2 EE-20180324-214756 >IE-EE-18.out 2>&1 &
# it's not quick but who cares:-)

function usage()
{
	echo "Find clusters from another run that have keys that overlap with these ones"
	echo "$0 [-i <space-sep list of files>] [-1 <run>] [-2 <run>]" 
	echo "  -1 means to take these clusters from this run"
	echo "  -2 means to compare these clusters to that run"
	echo "Defaults:"
	echo "      run1=\$HOME/data/smtp/runs/IE-20180316-181141"
	echo "      run2=\$HOME/data/smtp/runs/IE-20171130-000000"
	echo "  list of files should be e.g. \"cluster1.json cluster200.json\" - quotes will be good if >1"
	exit 99
}

srcdir=$HOME/code/surveys
infiles=""
run1="$HOME/data/smtp/runs/IE-20180316-181141"
run2="$HOME/data/smtp/runs/IE-20171130-000000"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o 1:2:i:h -l run1:,run2:,inputs:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-1|--run1) run1=$2; shift;;
		-2|--run2) run2=$2; shift;;
		-i|--input) infiles="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$infiles" == "" ]]
then
	infiles=`ls $run1/cluster*.json`
	echo "Doing all clusters between $run1 and $run1."
fi

tmpf=`mktemp /tmp/fpov.XXXX`
for file in $infiles
do
	c1num=`basename $file | sed -e 's/cluster//;s/.json//'`
	$srcdir/clustertools/fpsfromcluster.sh $file | awk '{print $2}' | grep -v total >$tmpf
	ols=""
	ol=`grep -l -F -f $tmpf $run2/cluster*.json`
	if [[ "$ol" != ""  ]] 
	then
		for cl in $ol
		do
			c2num=`basename $cl | sed -e 's/cluster//;s/.json//'`
			if [[ $ols != *"$c2num"* ]]
			then
				ols="$c2num $ols"
			fi
		done
	fi
	if [[ "$ols" == "" ]]
	then
		echo "$run1/$c1num has no overlaps with $run2"
	else
		echo "$run1/$c1num overlaps with $run2/$ols"
	fi
done
rm -f $tmpf

