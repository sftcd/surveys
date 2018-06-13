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
# idea is we have a set of domain names that allows us to extract
# the set of collision info that we might wanna send to an
# asset-holder owning that name

# we de-reference the name in dns to determine the prefixes to
# use and then search about for that

# in contrast to ah-ranges, we search across all most-recent
# scans for this A/name

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
	# without the '"ip": ' prefix here, we suck in IPs found for SANs in certs
	# probably better to not do that (though interesting such overlaps exist!?)
	echo "\"ip\": \"$dq4.$dq3.$dq2.$dq1\""
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
parentdir="$HOME/data/smtp/runs"
namelist=""

usage()
{
	echo "Extract a set of clusters that match a search string/regexp to sending to asset-holder"
	echo "usage: $0 [<name> | <name-file> ]  [<parent-run-dir>]"
	echo "    results will be in a directory named with a timestamp, e.g. $outdir"
	echo "    you might want to give that a more meaningful name"
	echo "    the parent-rundir contains the directories containing cluster files"
	echo "      and defaults to $HOME/data/smtp/runs/"
	echo "    name file is a file with DNS names (space or/line separated)"
	exit 99
}

if (( $# >= 2 || $# < 1 ))
then
	usage
fi

nameornf=$1

if [ "$nameornf" == "" ]
then
	echo "No names/name files provided - exiting"
	exit 1
fi

if [ -f "$nameornf" ]
then
	namelist=`cat $nameornf`
else
	namelist="$nameornf"
fi

if [[ "$namelist" == "" ]]
then
	echo "Empty name list - exiting"
	exit 3
fi

atmpf=`mktemp /tmp/ahnamesXXXX`

rrs="a aaaa mx txt spf"

for name in $namelist
do
	#echo "Doing $name"
	reportline="$name"
	for rr in $rrs
	do
		rec=`dig +short $rr $name`
		if [[ "$rec" == "" ]]
		then
			rec="-"
		fi
		# handle multi-valued RRs (e.g. TXT)
		# this is likely to be ickky
		jrec=""
		for recv in "$rec"
		do
			jrec="$jrec/$recv"
		done
		lrec=`echo $jrec | sed -e 's/\n/ /g'`
		# lose first and last separator from jrec
		lrec=${lrec:-1}
		lrec=${lrec:1}
		reportline="$reportline,$rr,$lrec"
		# remember A record specially
		if [[ "$rr" == "a" ]]
		then
			# hacky hack - make one IP look like a range:-)
			echo "$rec-$rec" >>$atmpf
		fi
	done
	echo "$reportline"
done

if [ "$2" != "" ]
then
	parentdir=$2
fi

if [ ! -d $parentdir ]
then
	echo "No directory $parentdir - exiting."
	exit 2
fi

rangefile=$atmpf

if [ ! -f $rangefile ]
then
	echo "Can't read $rangefile - exiting "
	echo "The RIPE DB may help here. Try using wget with s/XXX.XXX.XXX.XXX/your-ip/ as follows:"
	echo "    wget 'https://rest.db.ripe.net/search.json?query-string=XXX.XXX.XXX.XXX&flags=no-filtering&source=RIPE' "
	echo "Or maybe using a hoster name (if it exists in the RIPE DB) is better"
	echo "Bear in mind there's an AUP, so don't flood that."
	exit 1
fi

# plan:
# grep out ranges from input
# generate IPs from ranges to ipaddrs
# then use grep

ranges=`cat $rangefile`

tmpf=`mktemp /tmp/ahrangesXXXX`

for range in $ranges
do
	#echo "range: $range"
	range2list $range $tmpf
done

for rundir in $parentdir/*-201[89]*
do
	echo "Doing $rundir"

	matchingfiles=`grep -l -F -f $tmpf $rundir/cluster*.json`
	matchingcount=$(howmany "$matchingfiles")

	if (( matchingcount==0))
	then
		echo "There are $matchingcount clusters matching in $rundir - skipping"
		continue
	fi

	echo "There are $matchingcount clusters in $rundir matching "

	if [ ! -d $outdir ]
	then
		mkdir -p $outdir
	fi
	if [ ! -d $outdir ]
	then
		echo "Can't make $outdir - exiting"
		exit 1
	else
		mv $tmpf $outdir/allipaddrs.txt
		mv $atmpf $outdir/dnsinfo.txt
	fi

	brundir=`basename $rundir`
	country=${brundir:0:2}
	echo $country
	mkdir -p $outdir/$country
	if [ ! -d $outdir/$country ]
	then
		echo "Can't make $outdir - exiting"
		exit 1
	fi

	for cluster in $matchingfiles
	do
		echo "Copying over info about $cluster"
		cnum=`basename $cluster .json | sed -e 's/cluster//'`
		cp $rundir/cluster$cnum.json $outdir/$country
		copyif $rundir/cluster$cnum.words $outdir/$country
		copyif $rundir/graph$cnum.dot $outdir/$country
		copyif $rundir/graph$cnum.dot.svg $outdir/$country
		copyif $rundir/graph$cnum.dot.png $outdir/$country
		copyif $rundir/cluster$cnum-wordle.png $outdir/$country
		copyif $rundir/cluster$cnum-wordle.svg $outdir/$country
	done

done

echo "Done - Results are in $outdir"

