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

# Find the biggest "pure" SSH cluster(s)

clusters=cluster*.json
if [[ "$1" != "" ]]
then
	clusters=$1
fi

biggest=0
bfl=""
pure_biggest=0
pure_bfl=""
for file in $clusters
do
	# this finds pure SSH collisions
	#sshcolls=`grep '      "str_colls": "p22==p22;"' $file | wc -l`
	sshkeys=`grep '    "p22": "' $file | sort | uniq -c | tail -1 | awk '{print $1'}`
	p25keys=`grep '    "p25": "' $file | wc -l`
	p110=`grep '    "p110": "' $file | wc -l`
	p143=`grep '    "p143": "' $file | wc -l`
	p443=`grep '    "p443": "' $file | wc -l`
	p587=`grep '    "p587": "' $file | wc -l`
	p993=`grep '    "p993": "' $file | wc -l`
	((othertot=p25+p110+p143+p443+p587+p993))
	if [[ "$sshkeys" != "" ]]
	then
		if (( sshkeys > biggest ))
		then
			biggest=$sshkeys
			bfl=$file
		fi
		if (( othertot == 0 && sshkeys > pure_biggest ))
		then
			pure_biggest=$sshkeys
			pure_bfl=$file
		fi
	fi
done

echo "Overall most SSH key re-uses is $biggest in $bfl"
echo "Overall most pure SSH key re-uses is $pure_biggest in $pure_bfl"
