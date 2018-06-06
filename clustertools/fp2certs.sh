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

# given an fp and a list of cluster files (probably two but maybe more)
# grab one cert from each ip, compare those to see if equal and output
# all the distinct certs

function usage()
{
	echo "$0 -i <list-of-cluster-files> -f <fp>"
	echo "given an fp and a list of cluster files (probably two but maybe more)"
	echo "grab one cert from each ip, compare those to see if equal and output"
	echo "all the distinct certs"
	echo "list-of-cluster-file needs to be a space-sep list in quotes"
	exit 99
}

srcdir=$HOME/code/surveys
infiles=""
fp=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o f:i:h -l fp:,inputs:,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-i|--inputs) infiles="$2"; shift;;
		-f|--fp) fp="$2"; shift;;
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
if [[ "$fp" == "" ]]
then
	echo "You need to provide a fingerprint - exiting "
	exit 1
fi

tmpd=`mktemp -d /tmp/fp2crtXXXX`
for file in $infiles
do
	if [ ! -f $file ]
	then
		echo "$file doesn't exist - skipping"
		continue
	fi
	twoliner=`egrep '(^  "ip":|'$fp')' $file | tail -2`
	pport=`echo $twoliner | awk '{print $1}'`
	port=`echo ${pport:2:3} | sed -e 's/"//'`
	ipaddr=`echo $twoliner | awk '{print $4}' | sed -e 's/"//g' | sed -e 's/,//g'`
	#echo $ipaddr $port
	timeout 10s $srcdir/clustertools/gc.sh $ipaddr $port >/dev/null 2>&1
	if (( $? != 0 ))
	then
		echo "Timeout acquiring cert for $ipaddr-$port"
		if [ -f $ipaddr-$port.cert.txt ]
		then
			# clean up now
			rm -f $ipaddr-$port.cert.txt
		fi
	else
		if [ -f $ipaddr-$port.cert.txt ]
		then
			if [ -s $ipaddr-$port.cert.txt ]
			then
				mv $ipaddr-$port.cert.txt $tmpd
			else
				echo "Got zero size file acquiring cert for $ipaddr-$port"
				# clean up now
				rm -f $ipaddr-$port.cert.txt
			fi
		else
			echo "No cert acquired for $ipaddr-$port"
		fi
	fi
done

uniqcerts=`finddup -d $tmpd  | awk '{print $2}' | sed -e "s/'//g" `

for unic in $uniqcerts
do
	echo "Cert for $unic"
	cat $unic
	echo 
done

# now go back for any that aren't dups - do that by deleting dups
dupcerts=`finddup -d $tmpd  | awk '{ for(i=2; i<NF; i++) printf "%s",$i OFS; if(NF) printf "%s",$NF; printf ORS}' | sed -e "s/'//g" `
rm -f $dupcerts

# cat any left over
anysingletons=`ls $tmpd`
if [[ "$anysingletons" != "" ]]
then
	for file in $tmpd/*
	do
		echo "Cert for $file"
		cat $file
		echo 
	done
fi

#clean up
rm -rf $tmpd

