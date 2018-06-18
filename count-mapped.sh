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

# count how many IPs were zmap'd, how many p25 listeners and percentages

TOP="$HOME/data/smtp/runs"

tot_mapped=0
tot_p25s=0

for rundir in $TOP/??-201[789]*
do
	for log in $rundir/201*.out
	do
		runname=`basename $rundir`
		twolines=`grep -B1 "zmap: completed" $log`
		if [[ "$twolines" != "" ]]
		then
			mapped=`echo $twolines | awk '{print $6}'`
			p25s=`echo $twolines | awk '{print $12}'`
			percent=`echo $twolines | awk '{print $25}'`
			echo "$runname: $mapped mapped and $p25s port25 listeners, being $percent"
			tot_mapped=$((tot_mapped+mapped))
			tot_p25s=$((tot_p25s+p25s))
		fi
	done
done

ov_percent="0.$((tot_p25s*10000/tot_mapped))%"

echo "Total: $tot_mapped mapped and $tot_p25s port25 listeners, being $ov_percent"

