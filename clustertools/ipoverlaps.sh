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

# find overlapping clusters from another run

function usage()
{
	echo "Find clusters from another run that overlap with these ones"
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
	echo "Doing all clusters between $run1 and $run2."
fi

for file in $infiles
do
	ips=`$srcdir/clustertools/clips.sh -i $file`
	#echo $ips
	ols=""
	for ip in $ips
	do
		ol=`grep -l '^  "ip": "'$ip'"' $run2/cluster*.json`
		if [[ "$ol" != ""  ]] 
		then
			#set -x
			#echo "found $ip in $ol"
			#ol1=`grep -l '^  "ip": "'$ip'"' $ol`
			#set +x
			for cl in $ol
			do
				cnum=`basename $cl | sed -e 's/cluster//;s/.json//'`
				if [[ $ols != *"$cnum"* ]]
				then
					ols="$cnum $ols"
				fi
			done
		fi
	done
	if [[ "$ols" == "" ]]
	then
		echo "$file has no overlaps"
	else
		echo "$file overlaps with $run2 clusters $ols"
	fi
done

