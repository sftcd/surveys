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

# should we try one or all engines/formats?
all=False
seleng=False
if [ "$1" == "--all" ]
then
		all=True
elif [ "$1" == "--sfdp" ]
then
		seleng='sfdp'
elif [ "$1" == "--neato" ]
then
		seleng='neato'
elif [ "$1" == "--dot" ]
then
		seleng='dot'
elif [ "$1" == "--fdp" ]
then
		seleng='fdp'
elif [ "$1" == "--circo" ]
then
		seleng='circo'
elif [ "$1" == "--twopi" ]
then
		seleng='twopi'
elif [ "$#" != "0" ]
then
	echo "usage: $0 [--all|--sftp|--neato|--dot|--fdp|--circo|--twopi]"
	exit 1
fi

# GraphKeyReUse3.py produces a summary file at the end that
# says which graphs couldn't be rendered for some reason
# This script tries again for those

# You should generally run this in the directory containing 
# all the other graphs (outdir from GraphKeyReUse3) as that's
# where the summary.txt file will be put

list=`cat summary.txt | grep "not rendered" | tail -1\
		| sed -e 's/^.*\[//' \
		| sed -e 's/\].*$//' \
		| sed -e 's/, / /g'`

if [ "$list" == "" ]
then
	echo "Nothing to do"
	exit 0
fi

# which graphviz engine
engines="sfdp neato dot fdp circo twopi"
# default to 1st from list above
engine=`echo $engines | cut -d" " -f1`
# which output format
formats="svg png"
# default to 1st from list above
format=`echo $formats | cut -d" " -f1`

if [ "$all" == "True" ]
then
	engine=$engines
	format=$formats
elif [ "$seleng" != "False" ]
then
	engine=$seleng
fi

for eng in $engine
do
	engparms=""
	case $eng in
		neato )
			engparms="-Gepsilon=1.5"
			;;
	esac
	for gr in $list
	do
		for fmt in $format
		do
			# don't re-do already done stuff
			target=graph$gr.dot.$fmt
			if [ ! -f $target ]
			then
				echo "Trying $gr with $eng and $fmt..."
				timeout 120s $eng $engparms -T$fmt graph$gr.dot >$target
				if (( $? != 0 ))
				then
					mv $target failed-$gr.dot.$fmt
				fi
			else
				echo "Skipping $gr..."
				break
			fi
		done
	done
done

minsize=5000
baddies=""

# see who failed everything
for gr in $list
do
	nogood=True
	# note plural here - we check 'em all
	for fmt in $formats
	do
		target=graph$gr.dot.$fmt
		if [ -f $target ]
		then
			size=`ls -l $target | awk '{print $5}'`
			if (( $size > $minsize ))
			then
				nogood=False
			fi
		fi
	done
	if [ "$nogood" == "True" ]
	then
		therealready=`echo $baddies | grep $gr`
		if [[ "$theerealredy" == "" ]]
		then
			baddies+=" "$gr
		fi
	fi
done

echo "At the end, we still didn't manage to do $baddies"
echo ""
echo "The details: (output of 'ls -l graph\$NN.*')"
for gr in $baddies
do
	ls -l graph$gr.*
done
