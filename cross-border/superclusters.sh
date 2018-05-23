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

# superclusters! finally... a marketing name:-)

# Starting from cross-border.dot, try render a graph for each supercluster
# (each set of linked clusters)

# top of the house
TOP="$HOME/data/smtp/runs"

# the overall cross-border graph is in...
CBG="$TOP/cross-border/cross-border.dot"

# anonymise or not (not => IP addresses as node names in graphs)
anon=true

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o hac: -l country:,anon,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-a|--anon) anon=false; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# The plan: 
#	- break cross-border.dot into connected components
#	- for each
#		- create a graph with subgraphs for each linked cluster
#			- requires renaming nodes from run-specific indices that we usually use
#			  e.g. "1234" will have to go to "XX1234" where XX is the relevant
#			  country code (if IP addresses in use, then this doesn't apply)
#		- add cross-boder edges between the hosts
#			- not sure if those'll be sparse or dense, if the latter we 
#			  may need to abstract 'em somehow

tmpdir=`mktemp -d /tmp/cbgbXXXX`
currdir=$PWD
if [ ! -d $tmpdir ]
then
	echo "Couldn't make temp dir $tmpdir - exiting"
	exit 1
fi
cd $tmpdir

# split into connected components
ccomps -x -o super $CBG
complist=`ls super*`

# We need a name for those, 1st named cluster is what we'll use.
namelist=""

for comp in $complist
do
	# name them
	# echo $comp
	firsty="SC"`grep " -- " $comp | head -1 | awk '{print $1}'`
	if [[ "$firsty" == "" ]]
	then
		echo "Oops - no edges in $comp - skipping"
		continue
	fi
	namelist="$namelist $firsty"
	# extract set of cc/cnum's from $comp
	cnames=`grep " -- " $comp | awk '{print $1 " " $3 }' | sed -e 's/;//'`
	for cname in $cnames
	do
		cc=${cname:0:2}
		cnum=${cname:2}
		#echo "Checking for |$cc| and |$cnum|"
		fname_re="$TOP/$cc-2018*/cluster$cnum.json $TOP/$cc-2019*/cluster$cnum.json"
		fname=""
		for f in $fname_re
		do
			#echo "Checking for $f"
			if [[ "$f" != "" && -f $f ]]
			then
				fname=$f
				#echo "Found $fname"
				break
			fi
		done
		if [[ "$fname" == "" ]]
		then
			echo "Oops - can't find cluster file for $comp - skipping"
			continue
		fi
		echo "Cluster file for $comp/$firsty/$cname is $fname"
	done
done

echo $namelist


# clean up (or say where temp stuff is)
rm -rf $tmpdir
# echo "Left stuff in $tmpdir for you."

# go back to where we came from
cd $currdir

# legacy script below from count-sb.sh - keep it 'cause we'll want some of it
exit 0

# naming convention in $CBG is e.g. IE462 as the node name
needle="$country$cluster"

needle_count=`grep -c -w $needle $CBG`

total_ips=0
total_clusters=0
total_countries=0

declare -A countrycount

if ((needle_count==0))
then
	echo "No sign of $needle in $CBG"
else
	((needle_count-=1))
	echo "Looks like there are $needle_count links to $needle in $CBG"
	links=`grep -w $needle $CBG | grep -v "color" | sed -e 's/--//' | sed -e "s/$needle//"`
	for cluster in $needle $links
	do
		# figure out file name for that cluster
		cc=${cluster:0:2}
		cnum=${cluster:2}
		# see how many IP addresses involved
		#echo "Checking $cnum in $cc"
		fname_re="$TOP/$cc-2018*/cluster$cnum.json"
		csize=`grep '^  "csize":' $fname_re | head -1 | awk '{print $2}' | sed -e 's/,//'`
		echo "       $cc $cnum $csize"
		if ((csize>0))
		then
				total_clusters=$((total_clusters+1))
				total_ips=$((total_ips+csize))
		fi
		if [[ "${countrycount[$cc]}" == "" ]]
		then
			countrycount+=([$cc]="0")
			total_countries=$((total_countries+1))
		else
			countrycount[$cc]=$((countrycount[$cc]+1))
		fi
	done
	echo "Found $total_ips in $total_clusters clusters in $total_countries countries"
fi

