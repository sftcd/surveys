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

# Make a dot file comparing IP address and fingerprint overlaps
# between clusters of two runs from the same population.

# We've manually done the calls to ipoverlaps.sh and fpoverlaps.sh
# for IE-20171130 and IE-20180316 already. TODO: add those here
# but that's not needed really 'till we do another IE run, in a 
# month or two, so we'll let it be superhacky for now

# shortnames for runs. TODO: Add fullnames as argument, derive shortnames
r1f="$HOME/data/smtp/runs/IE-20171130-000000"
r2f="$HOME/data/smtp/runs/IE-20180316-181141"
r1s="17"
r2s="18"

# node colours
r1ncol="orange"
r2ncol="green"

# edge colours
ipfwdcol="black"
iprevcol="blue"
fpfwdcol="red"
fprevcol="gray"

# working dir. TODO: derive from arguments
wdir="$HOME/data/smtp/runs/ie-17-18"

# output files from fpoverlaps.sh and ipoverlaps.sh
ipfwd="ip$r1s$r2s.out"
iprev="ip$r2s$r1s.out"
fpfwd="fp$r1s$r2s.out"
fprev="fp$r2s$r1s.out"

# node names for r1
r1nodes=`ls -v $r1f/cluster*.json | sed -e 's/.*cluster//' | sed -e 's/\.json//'`
r2nodes=`ls -v $r2f/cluster*.json | sed -e 's/.*cluster//' | sed -e 's/\.json//'`

# output files from here
fullgraph="fg-$r1s$r2s.dot"
subgraph="sg-$r1s$r2s.dot"

# preamble
cat >$fullgraph <<EOF

digraph {
	packMode="array_u";
	graph [compound=true;splines=true;overlap=false]

subgraph r$r1s {
	rank="same"
EOF

for node in $r1nodes
do
	echo "r"$r1s"c"$node [color=$r1ncol style="filled"] >>$fullgraph
done
cat >>$fullgraph <<EOF
	}

	subgraph r$r2s {
		rank="same"

EOF

for node in $r2nodes
do
	echo "r"$r2s"c"$node [color=$r2ncol style="filled"] >>$fullgraph
done

cat >>$fullgraph <<EOF
	}

EOF

# forward FPs
grep -v "Doing" $fpfwd | \
		grep -v "no overlaps with" | \
	  	awk -F'/' '{print "r"'$r1s'"c"$3 " " "r"'$r2s'"c"$6}' | \
	   	sed -e 's/overlaps with \.\./ -> /' | \
		awk '{if (NF==3){print $0} else { print $1 " -> " $3 "\n"; for (i=4;i<=NF;i++) { print $1 " -> r"'$r2s'"c"$i }}}' | \
		awk 'NF>=1{print $0 " [color='$fpfwdcol']"}' | \
	   	sort -n  >>$fullgraph
echo "" >>$fullgraph

# reverse FPs
grep -v "Doing" $fprev | \
		grep -v "no overlaps with" | \
	  	awk -F'/' '{print "r"'$r2s'"c"$4 " " "r"'$r1s'"c"$6}' | \
	   	sed -e 's/overlaps with \.\./ -> /' | \
		awk '{if (NF==3){print $0} else { print $1 " -> " $3 "\n"; for (i=4;i<=NF;i++) { print $1 " -> r"'$r1s'"c"$i }}}' | \
		awk 'NF>=1{print $0 " [color='$fprevcol']"}' | \
	   	sort -n  >>$fullgraph
echo "" >>$fullgraph

# forward IPs
grep -v "Doing" $ipfwd | \
		grep -v "no overlaps" | \
		awk -F'/' '{print $2}' | \
		sed -e 's/cluster//' | \
		sed -e 's/\.json.*clusters//' | \
		awk '{if (NF==2){print "r"'$r1s'"c"$1 " -> r"'$r2s'"c"$2} else { for (i=2;i<=NF;i++) { print "r"'$r1s'"c"$1 " -> r"'$r2s'"c"$i"\n" }}}' | \
		awk 'NF>=1{print $0 " [color='$ipfwdcol']"}' | \
	   	sort -n  >>$fullgraph
echo "" >>$fullgraph

# reverse IPs
grep -v "Doing" $iprev | \
		grep -v "no overlaps" | \
		awk -F'/' '{print $8 " " $14} ' | \
		sed -e 's/cluster//' | \
		sed -e 's/\.json.*clusters//' | \
		awk '{if (NF==2){print "r"'$r2s'"c"$1 " -> r"'$r1s'"c"$2} else { for (i=2;i<=NF;i++) { print "r"'$r2s'"c"$1 " -> r"'$r1s'"c"$i"\n" }}}' | \
		awk 'NF>=1{print $0 " [color='$iprevcol']"}' | \
	   	sort -n  >>$fullgraph
echo "" >>$fullgraph

# postamble
echo "}" >>$fullgraph

# make small graph
# zap any nodes/edges that are only mentioned one or five times!
# one => no edges, just the node
# five => only one pair 

nodes=`grep filled $fullgraph | awk '{print $1}'`
zaps=""
zcount="0"
keeps=""
kcount="0"

for node in $nodes
do
	# count occurrences
	count=`grep -w -c $node $fullgraph`
	#echo "$node occurs $count times"
	if ((count== 1 || count == 5))
	then
		zaps="$node $zaps"
		((zcount++))
	else
		keeps="$node $keeps"
		((kcount++))
	fi
done

echo "zaps: $zcount"
echo "keeps: $kcount"

ztmpf=`mktemp ./zaps.XXXX`
ktmpf=`mktemp ./keep.XXXX`

echo "$zaps" | sed -e 's/ /\n/g' | sed -e '/^$/d' >$ztmpf
echo "$keeps" | sed -e 's/ /\n/g' | sed -e '/^$/d' >$ktmpf

grep -w -v -f $ztmpf $fullgraph >$subgraph

# next one needs pre/postamble etc., but gives good graph:-)
# ... when manually done: TODO: automate
grep -w  -f $ktmpf $fullgraph >k.$subgraph


rm -f $ztmpf $ktmpf
