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

# given a country and cluster number, say how many host overall scans
# are linked to that cluster

# top of the house
TOP="$HOME/data/smtp/runs"

# the overall cross-border graph is in...
CBG="$TOP/cross-border/cross-border.dot"

country="IE"
cluster="462" # the router vendor's one

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o hn:c: -l country:,number:,help -- "$@")
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
		-n|--number) cluster="$2"; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

echo "Counting addreesses in cross-border links to cluster $cluster in $country..."

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

