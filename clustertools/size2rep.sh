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

# Report on clusters of size 2 

srcdir=$HOME/code/surveys

# make an array of file names
s2list=(`grep -l 'csize": 2,' cluster*.json`)
# magic way to get length of array as per:
# https://www.cyberciti.biz/faq/finding-bash-shell-array-length-elements/
s2count=${#s2list[@]}

tmpf=`mktemp /tmp/s2c.XXXX`

echo "There are $s2count clusters of size 2."

for ((i=0; i!=s2count; i++))
do
		# symmetry is good enough! even with a "p25=p143" case
		grep str_colls ${s2list[i]} | head -1 >>$tmpf
done

cat $tmpf | sort -V | uniq -c | sort -n

rm $tmpf
