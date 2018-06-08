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

# Create a diretory with content specific to an asset-holder
# idea is we have a set of ranges that allows us to extract
# the set of collision info that we might wanna send to an
# asset-holder

# Note that manual examination is needed before makging a
# tarball and sending - the prefixes might select too
# many clusters

# this is based on ah-tb.sh

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

outdir="ah-"$NOW

function howmany() {
	case $- in *f*) set -- $1;; *) set -f; set -- $1; set +f;; esac
	echo $#
}

function copyif()
{
	# copy $1 if it exists to $2
	if [ -f $1 ]
	then
		cp $1 $2
	fi
}

function i2dq()
{
	ival=$1
	dq4=$((ival/(256*256*256)))
	dq3=$(((ival/(256*256))%256))
	dq2=$(((ival/256)%256))
	dq1=$((ival%256))
	echo \"$dq4.$dq3.$dq2.$dq1\"
}

function range2list()
{
	of=$2
	for i in $1; do
		# dotted quad, split into values
    	A4="${i%-*}"; B4="${i#*-}"
		a4=${A4/.*}; b4=${B4/.*};
    	A3="${A4#*.}"; B3="${B4#*.}"
		a3=${A3/.*}; b3=${B3/.*};
    	A2="${A3#*.}"; B2="${B3#*.}"
		a2=${A2/.*}; b2=${B2/.*};
    	A1="${A2#*.}"; B1="${B2#*.}"
		a1=${A1/.*}; b1=${B1/.*};
		# map to ints
		min=$((a1+a2*256+a3*(256*256)+a4*(256*256*256)))
		max=$((b1+b2*256+b3*(256*256)+b4*(256*256*256)))
		# print needed
		for ((i = min; i<= max; i++ ))
		do
			# map back to dotted quad
			i2dq $i >>$of
		done
	done
}

# testy test...
#range2list "80.93.28.0-80.93.29.255" /dev/stdout
#range2list "92.51.242.254-92.51.243.4" /dev/stdout
#exit 0

rangefile=""
rundir=""

usage()
{
	echo "Extract a set of clusters that match a search string/regexp to sending to asset-holder"
	echo "usage: $0 <range-file> <run-dir>"
	echo "    results will be in a directory named with a timestamp, e.g. $outdir"
	echo "    you might want to give that a more meaningful name"
	echo "    the rundir contains the cluster files"
	echo "    range file is a JSON file extracted from RIPE"
	exit 99
}

if (( $# != 2 ))
then
	usage
fi

rangefile=$1
rundir=$2

if [ ! -f $rangefile ]
then
	echo "Can't read $rangefile - exiting "
	exit 1
fi

if [ ! -d $rundir ]
then
	echo "No directory $rundir - exiting."
	exit 2
fi

# plan:
# grep out ranges from input
# generate IPs from ranges to ipaddrs
# then use grep

rawranges=`grep -A1 inetnum $rangefile  | grep value | sort -V | uniq`
ranges=`echo "$rawranges" | awk '{print $3"-"$5}' | sed -e 's/"//g'`

tmpf=`mktemp /tmp/ahrangesXXXX`

for range in $ranges
do
	#echo "range: $range"
	range2list $range $tmpf
done

matchingfiles=`grep -l -F -f $tmpf $rundir/cluster*.json`
matchingcount=$(howmany "$matchingfiles")

if (( matchingcount==0))
then
	echo "There are $matchingcount clusters matching - exiting"
	rm $tmpf
	exit 0
fi

echo "There are $matchingcount clusters matching "

mkdir -p $outdir
if [ ! -d $outdir ]
then
	echo "Can't make $outdir - exiting"
	exit 1
fi
mv $tmpf $outdir/allipaddrs.txt

for cluster in $matchingfiles
do
	echo "Copying over info about $cluster"
	cnum=`basename $cluster .json | sed -e 's/cluster//'`
	cp $rundir/cluster$cnum.json $outdir
	copyif $rundir/cluster$cnum.words $outdir
	copyif $rundir/graph$cnum.dot $outdir
	copyif $rundir/graph$cnum.dot.svg $outdir
	copyif $rundir/graph$cnum.dot.png $outdir
	copyif $rundir/cluster$cnum-wordle.png $outdir
	copyif $rundir/cluster$cnum-wordle.svg $outdir
done


echo "Done - Results are in $outdir"

