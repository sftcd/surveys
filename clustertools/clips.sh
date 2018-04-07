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

# list the IPs from a cluster 

function usage()
{
	echo "Grep out a top level field from a json file."
	echo "$0 [-u] [-f <field>] [-i <space-sep list of files>]"
	echo "  -u means to run otput through \"uniq -c\""
	echo "  list of files should be e.g. \"cluster1.json cluster200.json\" - quotes will be good if >1"
	exit 99
}

infiles=""
needle="ip"
douniq="no"

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
		-u|--uniq) douniq="yes" ;;
		-i|--input) infiles="$2"; shift;;
		-f|--field) needle="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$needle" == "" || "$infiles" == "" ]]
then
	echo "missing inputs"
	usage
fi

if [[ "$douniq" == "yes" ]]
then
	egrep '^   ? ?"'$needle'":' $infiles | sed -e's/    /  /' | sed -e's/^  "ip": "//;s/",//' | sort -V | uniq -c
else
	egrep '^   ? ?"'$needle'":' $infiles | sed -e's/    /  /' | sed -e's/^  "ip": "//;s/",//' | sort -V
fi

