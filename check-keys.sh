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

# check to see if our ssh and TLS findings are correct, using different s/w from
# zgrab

# for now, this just checks if the relationships in the cluster still do
# exist

# TODO: need to figure out hash input in zgrab first though and that's not
# yet obvious, I'm not seeing the same hash values yet

# TODO: integrate into skey-all.sh

#set -x

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
startdir=`/bin/pwd`

echo "Running $0 at $NOW"

function usage()
{
	echo "$0 - no parameters:-)"
	exit 99
}

srcdir=$HOME/code/surveys

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o s:h -l srcdir:,help -- "$@")
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
		-s|--srcdir) srcdir="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [ "$srcdir" == "" ]
then
	echo "No <code-directory> set"
	usage
fi

if [ ! -d $srcdir ]
then
	echo "$srcdir doesn't exist - exiting"
	usage
fi

ofall="validation-results-$NOW.out"
echo "Starting at $NOW, log in $ofall" 
echo "Starting at $NOW, log in $logf" >$ofall

for file in cluster*.json 
do
	echo "Doing $file"
	echo "Doing $file" >>$ofall
	$srcdir/TwentyTwos.py -i $file >>$ofall 2>&1
	$srcdir/CheckTlSPorts.py -i $file >>$ofall 2>&1
done

# summarise...

summary=`grep "^TwentyTwo" $ofall | sort | uniq | \
			awk -F, '{print $2,$3,$4,$5,$6,$7,"\n"}' | \
			sed 's/cluster//' | sort -n | sed -e 's/.json//' | sed -e 's/ /,/g' | sed -e 's/,,//' `
tmpf=`mktemp /tmp/sshccheck-XXXX`
for word in $summary
do
		echo $word >>$tmpf
done
cat $tmpf 
cat $tmpf >>$ofall
rm -f $tmpf

summary=`grep "^TLSKey" $ofall | sort | uniq | \
			awk -F, '{print $2,$3,$4,$5,$6,$7,"\n"}' | \
			sed 's/cluster//' | sort -n | sed -e 's/.json//' | sed -e 's/ /,/g' | sed -e 's/,,//' `
tmpf=`mktemp /tmp/tlscheck-XXXX`
for word in $summary
do
		echo $word >>$tmpf
done
cat $tmpf 
cat $tmpf >>$ofall
rm -f $tmpf

NOW=$(whenisitagain)
echo "Overall Finished at $NOW" >>$ofall

cd $startdir

