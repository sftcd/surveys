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

# This is a variation on fpoverlaps.sh that also outputs the actual
# FP's that link clusters in latex format. I could have modified that
# script to do this, but that'd break the cross-border.sh analysis 
# script, so I'm being lazy here;-)

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

function nicename()
{
		rp=`realpath $1`
		rundir=`dirname $rp`
		runbase=`basename $rundir`
		cc=${runbase:0:2}
		cnum=`basename $rp .json | sed -e 's/cluster//'`
		echo $cc$cnum
}

srcdir=$HOME/code/surveys
infiles=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o i:h -l inputs:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-i|--input) infiles="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$infiles" == "" ]]
then
	echo "You need to provide input files - exiting "
	exit 1
fi

# assoc. array indexed by fp containing space-sep list of clusternames
declare -A fpclusters

tmpf=`mktemp /tmp/fpov.XXXX`
for file in $infiles
do
	c1num=`basename $file | sed -e 's/cluster//;s/.json//'`
	$srcdir/clustertools/fpsfromcluster.sh $file | awk '{print $2}' | grep -v total >$tmpf
	for otherfile in $infiles
	do
		if [ $file == $otherfile ]
		then
			continue
		fi
		lfps=`grep -F -f $tmpf $otherfile | awk '{print $2}' | sed -e s/,// | uniq | sed -e 's/"//g'` 
		if [[ "$lfps" != ""  ]] 
		then
			nn1=`nicename $file`
			nn2=`nicename $otherfile`
			#echo "See $lfps in $nn1 and $nn2"
			for fp in $lfps
			do
				if [[ "${fpclusters[$fp]}" == "" ]]
				then
					fpclusters[$fp]="$nn1 $nn2"
				else
					if [[ ${fpclusters[$fp]} != *"$nn1"* ]]
					then
						fpclusters[$fp]="${fpclusters[$fp]} $nn1"
					fi
					if [[ ${fpclusters[$fp]} != *"$nn2"* ]]
					then
						fpclusters[$fp]="${fpclusters[$fp]} $nn2"
					fi
				fi
			done
		fi
	done
done
rm -f $tmpf

echo "Need a two-match test case!"
for fp in "${!fpclusters[@]}"
do
	echo "$fp is in ${fpclusters[$fp]}"
done
# output latex, eventually:-)

