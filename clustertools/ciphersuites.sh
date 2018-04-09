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

# extract ciphersuite values from cluster files

function usage()
{
	echo "Grep out ciphersuites json files."
	echo "$0 -i <space-sep list of files>"
	echo "  list of files should be e.g. \"cluster1.json cluster200.json\" - quotes will be good if >1"
	exit 99
}

infiles=""
needle="cipher_suite"

# this comes from https://testssl.sh/mapping-rfc.txt, which is GPL
# I've no idea if re-use of a file like that is a licensing issue,
# note that I don't distribute that, I download it from install-deps
# to here - I reckon that's ok, if you disagree send a PR:-)
stringsfile="$HOME/code/surveys/clustertools/mapping-rfc.txt"
if [ ! -f $stringsfile ]
then
	echo "You need $stringsfile - get it from https://testssl.sh/mapping-rfc.txt"
	exit 1
fi

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o uf:i:h -l uniq,field:,inputs:,help -- "$@")
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
		-i|--input) infiles="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

nums=1
# how many infiles we dealing with? changes awk thing to print
IFS=' ' farr=(${infiles})
nums=${#farr[@]}

pos=2
if [[ "$nums" != "1" ]]
then
	pos=3
fi

tmpf=`mktemp /tmp/csuite.XXXX`
tmpf1=`mktemp /tmp/csuite.XXXX`

egrep '"'$needle'": ' $infiles | \
	awk '{print $'$pos'}' | \
	grep -v '"",' | \
	sed -e 's/",//' | \
	sed -e 's/"//' | \
	sed -e 's/,$//' | 
	awk '{printf("x%02X\n",$1)}' >$tmpf

while read line
do
	grep $line $stringsfile >>$tmpf1
done <$tmpf

cat $tmpf1 | sort |  uniq -c | sort -n 

rm -f $tmpf $tmpf1
