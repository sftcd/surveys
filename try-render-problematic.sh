#!/bin/bash

# set -x

# should we try one or all engines/formats?
all=False
if [ "$1" == "--all" ]
then
		all=True
fi

# GraphKeyReUse3.py produces a summary file at the end that
# says which graphs couldn't be rendered for some reason
# This script tries again for those

# You should generally run this in the directory containing 
# all the other graphs (outdir from GraphKeyReUse3) as that's
# where the summary.txt file will be put

list=`cat summary.txt | grep "not rendered" \
		| sed -e 's/^.*\[//' \
		| sed -e 's/\].*$//' \
		| sed -e 's/, / /g'`

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
fi

for eng in $engine
do
	for fmt in $format
	do
		for gr in $list
		do
			# don't re-do already done stuff
			target=graph$gr.dot.$fmt
			if [ ! -f $target ]
			then
				echo "Trying $gr..."
				timeout 120s $eng -Tsvg graph$gr.dot >$target
				if (( $? != 0 ))
				then
					mv $target failed-$gr.dot.$fmt
				fi
			else
				echo "Skipping $gr..."
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
		baddies+=" "$gr
	fi
done

echo "At the end, we still didn't manage to do $baddies"
echo ""
echo "The details: (output of 'ls -l graph\$NN.*')"
for gr in $baddies
do
	ls -l graph$gr.*
done
