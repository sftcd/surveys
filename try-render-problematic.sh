#!/bin/bash

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

for gr in $list
do
	# don't re-do already done stuff
	target=graph$gr.dot.svg
	if [ ! -f $target ]
	then
		echo "Trying $gr..."
		timeout --kill-after 30s 120s sfdp -Tsvg graph$gr.dot >$target
		if (( $? != 0 ))
		then
			mv $target failed-$gr.dot.svg
		fi
	else
		echo "Skipping $gr..."
	fi
done

