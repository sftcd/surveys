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

# check if any of a supplied list of ips are in some cluster

function usage()
{
	echo ""
	echo "Usage: Check if any of a supplied list of ips are in some cluster"
	echo "$0 [ -i <ip>] [ -c <cidr-range>] [-f <ips-file>] [-r <run-dir>]"
	echo "    -i/-c/-f are mutually exclusive - just do one"
	echo "    if you do specfify more -f wins over -i which wins over -c"
	echo "    (for no particular reason:-)"
	exit 99
}

infiles=""
cide=""
ip=""
ipfile=""
run=""
# default location for runs
def_path="$HOME/data/smtp/runs"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o c:i:f:r:h -l cidr:,ip:,file:,run:,help -- "$@")
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
		-i|--ip) ip="$2"; shift;;
		-c|--cidr) cidr="$2"; shift;;
		-f|--file) ipfile="$2"; shift;;
		-r|--run) run="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# check inputs
if [[ "$run" == "" ]]
then
	echo "No run specified - exiting"
	usage
fi
# is run an abs-path?
absrun=$run
if [[ "${run:0:1}" != / && "${run:0:2}" != ~[/a-z] ]]
then
	absrun="$def_path/$run"
fi
if [ ! -d $absrun ]
then
	echo "Can find run directory $absrun - exiting"
	usage
fi

# a string to explain our search
needlestr=""
needle=""
if [[ "$cidr" != "" ]]
then
	# make list of matching ips in temp file
	IFS='/' twopart=($cidr)
	range=${twopart[1]}
	if ((range !=8 && range!=16 && range!=24))
	then
		echo "We only support ranges that are a multiple of 8 sorry - exiting"
		exit 2
	fi
	dots=$((range/8))
	IFS='.' nums=(${twopart[0]})
	prefix=""
	for ((i=0;i!=dots;i++))
	do
		prefix="$prefix${nums[i]}."
	done
	needlestr="ips in $prefix/$range"
	needle=$prefix
fi	

if [[ "$ip" != "" ]]
then
	needlestr=$ip
	needle=$ip
fi

if [[ "$ipfile" != "" ]]
then
	needlestr="ips in file $ipfile"
	if [ ! -f $ipfile ]
	then
		echo "Can't open $ipfile - exiting"
		exit 3
	fi
	# we assume the content of ip file is sane
	needle=`cat $ipfile`
fi

if [[ "$needlestr" == "" ]]
then
	echo "You gotta specify some ips - exiting"
	usage
fi

echo "Checking for $needlestr in $absrun"

# we want the specific input ips that match when those are
# given, for a cidr block, just that

clusters=$run/cluster*.json

# we can shortcut things if given a file of ips as input
if [[ "$ipfile" != "" ]]
then
	matchingfiles=`grep -l -F -f $ipfile $clusters`
	clusters=$matchingfiles
fi

count=1
freq=100

for cl in $clusters
	do
	for ip in $needle
	do
		match=`grep -l '^  "ip": "'$ip'"' $cl`
		if [[ "$match" != "" ]]
		then
				echo "$ip matches $cl"
		fi
		if ((count%freq==0))
		then
			echo "Did $count checks, last was $ip vs $cl"
		fi
		count=$((count+1))
	done
done
