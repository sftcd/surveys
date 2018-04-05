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
# idea is we have a string/regexp that allows us to extract
# the set of collision info that we might wanna send to an
# asset-holder

# Note that manual examination is needed before makging a
# tarball and sending - the string/regexp might select too
# many clusters

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


usage()
{
	echo "Extract a set of clusters that match a search string/regexp to sending to asset-holder"
	echo "usage: $0 string/regexp"
	echo "    be careful with using quotes correctly to get the effects you want!"
	echo "    results will be in a directory named with a timestamp, e.g. $outdir"
	echo "    you might want to give that a more meaningful name"
	echo "Run this in the directory that contains the cluster*.json files"
	exit 99
}

if (( $# != 1 ))
then
	usage
fi

needle=$1
matchingfiles=`grep -l "$needle" cluster*.json`
matchingcount=$(howmany "$matchingfiles")

if (( matchingcount==0))
then
	echo "There are $matchingcount clusters matching '$needle' - exiting"
	exit 0
fi

echo "There are $matchingcount clusters matching '$needle'"

mkdir -p $outdir
if [ ! -d $outdir ]
then
	echo "Can't make $outdir - exiting"
	exit 1
fi

for cluster in $matchingfiles
do
	cnum=`basename $cluster .json | sed -e 's/cluster//'`
	cp cluster$cnum.json $outdir
	copyif cluster$cnum.words $outdir
	copyif graph$cnum.dot $outdir
	copyif graph$cnum.dot.svg $outdir
	copyif graph$cnum.dot.png $outdir
	copyif cluster$cnum-wordle.png $outdir
	copyif cluster$cnum-wordle.svg $outdir
done

echo "Done - Results are in $outdir"

