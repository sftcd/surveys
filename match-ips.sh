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
	echo "$0 -n <string>  [ -o <outfile> ]"
	echo "    Search the records.fresh files for a string and return per-run counts and total"
	echo "    -n specifies the needle to look for in the haystack"
	echo "    -o specifies the output file in which to put the records matching the needle"
	echo "With no output file provided, per-run counts of matches are provided"
	exit 99
}

needle=""
outfile=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o n:o:h -l needle:,out:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-n|--needle) needle=$2; shift;;
		-o|--out) outfile=$2; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$needle" == "" ]]
then
	echo "No needle to look for provided - exiting"
	usage
fi

if [[ "$outfile" != "" ]]
then
	# want output, but check if we'd overwrite something 
	if [ -f $outfile ]
	then
		echo "Renaming existing $outfile to $outfile.old"
		mv $outfile $outfile.old
	fi
fi

total=0

echo "Looking for $needle below $TOPD"

for dir in $DIRS
do
	rcount=`grep -c "$needle" $dir/records.fresh`
	echo "$dir has $rcount"
	if [[ "$outfile" !=  "" ]]
	then
		# extract those records to $outfile
		grep "$needle" $dir/records.fresh >>$outfile
	fi
	((total=total+rcount))
done

echo "Total is $total"



