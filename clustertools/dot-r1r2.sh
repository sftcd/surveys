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

# Make some dot files comparing IP address and fingerprint overlaps
# between clusters of two runs from the same population.
# And whack out a summary at the end too.

# We've manually done the calls to ipoverlaps.sh and fpoverlaps.sh
# for IE-20171130 and IE-20180316 already. TODO: add those here
# but that's not needed really 'till we do another IE run, in a 
# month or two, so we'll let it be superhacky for now

# couple of graphviz snippet functions:

function preamble()
{
# preamble
cat >$1 <<EOF

digraph {
	packMode="array_u";
	graph [compound=true;splines=true;overlap=false]

EOF
}

function subgraph()
{
cat >>$1 <<EOF

	subgraph $2 {
		rank="same"

EOF
}

function endgraph()
{
cat >>$1 <<EOF

	}

EOF
}

function wordcount()
{
	thearr=($1)
	echo ${#thearr[@]}
}

function wordinlist()
{
	echo $1 | grep -w $2
}

function takewordfromlist()
{
	res=`echo $1 | sed -e 's/ '$2' / /'`
	# needle=" $2 "
	#res=${1/$needle}
	echo "$res"
}

function listout()
{
	#echo "listout $1 $2"
	echo "$3" | sed -e 's/ /\n/g' | sed -e 's/^/r'$2'c/' | sort -V >$1 
	sed -i '1d' $1
}

function listevol()
{
	outf=$1
	inf=$2
	ipfp=$3
	from=$4
	to=$5
	nodes=$6

	tmpf=`mktemp /tmp/levol.XXXX`

	for node in $nodes
	do
		if [[ "$ipfp" == "ip" ]]
		then
			needle="cluster$node.json"
			others=`grep "$needle" $inf | awk '{for (i=6;i<=NF;i++){print $i}}'`
		elif [[ "$ipfp" == "fp" ]]
		then
			needle="\/$node overlaps with"
			others=`grep "$needle" $inf | awk '{print $4}' | sed -e 's/.*\///'`
		else
			echo "EEK - odd input to listevol $3"
			exit 2
		fi
		for other in $others
		do
			echo "r$from"c$node" -> r$to"c"$other" >>$tmpf
		done
	done
	cat $tmpf | sort -V >$outf
	rm -f $tmpf
}

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

r1arr=($r1nodes)
r2arr=($r2nodes)
r1count=${#r1arr[@]}
r2count=${#r2arr[@]}

# image format and graphviz tool to use
imgfmt="png"
gvtool=sfdp

# output files from here
fullgraph="fg-$r1s$r2s.dot"
fullgraphimg="fg-$r1s$r2s.$imgfmt"
complexgraph="sg-$r1s$r2s.dot"
complexgraphimg="sg-$r1s$r2s.$imgfmt"
restgraph="zg-$r1s$r2s.dot"
restgraphimg="zg-$r1s$r2s.$imgfmt"

# We want to get the set of clusters that...
# disappear (exist in r1 but no IPs or FPs in r2)
disappeared=""
# appear (not ips or fps in r1 but exist in r2)
appeared=""
# lone-evolvers with only IP changes 
fwdipevol=""
revipevol=""
# lone-evolvers with only FP changes 
fwdfpevol=""
revfpevol=""
# lone-evolvers with IP and FP changes 
fwdbothevol=""
revbothevol=""
# complicated (multiple evolvers) - there's not many so we'll study 'em
fwdcomplexevol=""
revcomplexevol=""

# file names for node list
dc_text="disappeared.txt"
fi_text="fwd-ip.txt"
fp_text="fwd-fp.txt"
fb_text="fwd-both.txt"
ap_text="appeared.txt"
ri_text="rev-ip.txt"
rp_text="rev-fp.txt"
rb_text="rev-both.txt"
fc_text="fwd-complex.txt"
rc_text="rev-complex.txt"

for r1node in $r1nodes
do
	iprec=`grep "cluster$r1node.json" $ipfwd` 
	if [[ $iprec == *"no overlap"* ]]
	then
		fprec=`grep "/$r1node has no overlap" $fpfwd` 
		if [[ $fprec != "" ]]
		then
			disappeared="$r1node $disappeared"
		fi
	fi
done

for r1node in $r1nodes
do
	if [[ $(wordinlist "$disappeared" $r1node) != "" ]]
	then
		#echo "Not checking $r1node - it disappeared"
		continue
	fi
	ipevol="false"
	fpevol="false"
	complex="false"
	iprec=`grep "cluster$r1node.json overlaps with" $ipfwd` 
	if [[ $iprec != "" ]]
	then
		ipevol="true"
		iparr=($iprec)
		fieldcount=${#iparr[@]}
		if ((fieldcount>6))
		then
			#echo "$r1node is complex $fieldcount"
			complex="true"
		fi
	fi
	fprec=`grep "/$r1node overlaps with" $fpfwd` 
	if [[ $fprec != "" ]]
	then
		fpevol="true"
		fparr=($fprec)
		fieldcount=${#fparr[@]}
		if ((fieldcount>4))
		then
			#echo "$r1node is complex $fieldcount"
			complex="true"
		fi
	fi
	if [[ "$complex" == "true" ]]
	then
		#echo "$r1node: $ipevol $fpevol $complex"
		fwdcomplexevol="$r1node $fwdcomplexevol"
	elif [[ "$ipevol" == "true" && "$fpevol" == "true" ]]
	then
		fwdbothevol="$r1node $fwdbothevol"
	elif [[ "$fpevol" == "true" && "$ipevol" == "false" ]]
	then
		fwdfpevol="$r1node $fwdfpevol"
	elif [[ "$fpevol" == "false" && "$ipevol" == "true" ]]
	then
		fwdipevol="$r1node $fwdipevol"
	elif [[ "$fpevol" == "false" && "$ipevol" == "false" ]]
	then
		echo "EEK - error: $r1node: $ipevol $fpevol $complex"
		exit 1
	fi
done


dc_count=$(wordcount "$disappeared")
fi_count=$(wordcount "$fwdipevol")
fp_count=$(wordcount "$fwdfpevol")
fb_count=$(wordcount "$fwdbothevol")
fc_count=$(wordcount "$fwdcomplexevol")
echo "Forward:" 
echo "Disappeared: $dc_count"
echo "Lone IP evol: $fi_count"
echo "Lone FP evol: $fp_count"
echo "Both evol: $fb_count"
echo "Complex: $fc_count"
echo "Total: $((dc_count+fi_count+fp_count+fb_count+fc_count))"
echo "Check: $r1count"
echo 

for r2node in $r2nodes
do
	iprec=`grep "cluster$r2node.json" $iprev` 
	if [[ $iprec == *"no overlap"* ]]
	then
		fprec=`grep "/$r2node has no overlap" $fprev` 
		if [[ $fprec != "" ]]
		then
			appeared="$r2node $appeared"
		fi
	fi
done

for r2node in $r2nodes
do
	if [[ $(wordinlist "$appeared" $r2node) != "" ]]
	then
		continue
	fi
	ipevol="false"
	fpevol="false"
	complex="false"
	iprec=`grep "cluster$r2node.json overlaps with" $iprev` 
	if [[ $iprec != "" ]]
	then
		ipevol="true"
		iparr=($iprec)
		fieldcount=${#iparr[@]}
		if ((fieldcount>6))
		then
			complex="true"
		fi
	fi
	fprec=`grep "/$r2node overlaps with" $fprev` 
	if [[ $fprec != "" ]]
	then
		fpevol="true"
		fparr=($fprec)
		fieldcount=${#fparr[@]}
		if ((fieldcount>4))
		then
			complex="true"
		fi
	fi
	if [[ "$complex" == "true" ]]
	then
		revcomplexevol="$r2node $revcomplexevol"
	elif [[ "$ipevol" == "true" && "$fpevol" == "true" ]]
	then
		revbothevol="$r2node $revbothevol"
	elif [[ "$fpevol" == "true" && "$ipevol" == "false" ]]
	then
		revfpevol="$r2node $revfpevol"
	elif [[ "$fpevol" == "false" && "$ipevol" == "true" ]]
	then
		revipevol="$r2node $revipevol"
	elif [[ "$fpevol" == "false" && "$ipevol" == "false" ]]
	then
		echo "EEK - error: $r2node: $ipevol $fpevol $complex"
		exit 1
	fi
done

ap_count=$(wordcount "$appeared")
ri_count=$(wordcount "$revipevol")
rp_count=$(wordcount "$revfpevol")
rb_count=$(wordcount "$revbothevol")
rc_count=$(wordcount "$revcomplexevol")
echo "Reverse:"
echo "Appeared: $ap_count"
echo "Lone IP evol: $ri_count"
echo "Lone FP evol: $rp_count"
echo "Both evol: $rb_count"
echo "Complex: $rc_count"
echo "Total: $((ap_count+ri_count+rp_count+rb_count+rc_count))"
echo "Check: $r2count"
echo

# cross-check for complexity, e.g. if fwdip x->y and fwdfp x->z
# then it's complex
movers=""
othermovers=""
for cnum in $fwdbothevol
do
	needle1="cluster$cnum.json"
	others1=`grep "$needle1" $ipfwd | awk '{for (i=6;i<=NF;i++){print $i}}'`
	needle2="/$cnum overlaps with"
	others2=`grep "$needle2" $fpfwd | awk '{for (i=4;i<=NF;i++){print $i}}' | sed -e 's/.*\///'`
	if [[ "$others1" != "$others2" ]]
	then
		echo "Mismatch for r17c$cnum: [$others1] [$others2]"
		# tee up a move for that to complex
		movers="$cnum $movers"
		othermovers="$others1 $others2 $othermovers"
	fi
done
for move in $movers
do
	fwdbothevol=$(takewordfromlist "$fwdbothevol" $move)
	fwdcomplexevol="$move $fwdcomplexevol"
done
for omove in $othermovers
do
	revbothevol=$(takewordfromlist "$revbothevol" $omove)
	revipevol=$(takewordfromlist "$revipevol" $omove)
	revfpevol=$(takewordfromlist "$revfpevol" $omove)
	revcomplexevol="$omove $revcomplexevol"
done

# and the other one...
movers=""
othermovers=""
for cnum in $revbothevol
do
	needle1="cluster$cnum.json"
	others1=`grep "$needle1" $iprev | awk '{for (i=6;i<=NF;i++){print $i}}'`
	needle2="/$cnum overlaps with"
	others2=`grep "$needle2" $fprev | awk '{for (i=4;i<=NF;i++){print $i}}' | sed -e 's/.*\///'`
	if [[ "$others1" != "$others2" ]]
	then
		echo "Mismatch for r18c$cnum: [$others1] [$others2]"
		# tee up a move for that to complex
		movers="$cnum $movers"
		othermovers="$others1 $others2 $othermovers"
	fi
done
for move in $movers
do
	revbothevol=$(takewordfromlist "$revbothevol" $move)
	revcomplexevol="$move $revcomplexevol"
done
for omove in $othermovers
do
	fwdbothevol=$(takewordfromlist "$fwdbothevol" $omove)
	fwdipevol=$(takewordfromlist "$fwdipevol" $omove)
	fwdfpevol=$(takewordfromlist "$fwdfpevol" $omove)
	fwdcomplexevol="$omove $fwdcomplexevol"
done

# do some pruning
# anything linked to complex... is complex and take
# out of other lists
for cnum in $fwdcomplexevol
do
	# find the set of peers for this node
	needle1="cluster$cnum.json"
	others1=`grep "$needle1" $ipfwd | awk '{for (i=6;i<=NF;i++){print $i}}'`
	needle2="/$cnum overlaps with"
	others2=`grep "$needle2" $fpfwd | awk '{for (i=4;i<=NF;i++){print $i}}' | sed -e 's/.*\///'`
	for other in $others1 $others2
	do
		#echo "Other: $other"
		#echo "RCE: $revcomplexevol"
		# add to rev complex if not there already
		if [[ $(wordinlist "$revcomplexevol" $other) != "" ]]
		then
			#echo "r$r1s"c"$cnum other r$r2s-$other is already complex"
			foo="bar"
		else
			if [[ $(wordinlist "$revipevol" $other) != "" ]]
			then
				revipevol=$(takewordfromlist "$revipevol" $other)
				revcomplexevol="$other $revcomplexevol"
				#echo "Because of r$r1s"c"$cnum moved r$r2s-$other from revip to complex"
			elif [[ $(wordinlist "$revfpevol" $other) != "" ]]
			then
				revfpevol=$(takewordfromlist "$revfpevol" $other)
				revcomplexevol="$other $revcomplexevol"
				#echo "Because of r$r1s-c$cnum moved r$r2s-$other from revfp to complex"
			elif [[ $(wordinlist "$revbothevol" $other) != "" ]]
			then
				revbothevol=$(takewordfromlist "$revbothevol" $other)
				revcomplexevol="$other $revcomplexevol"
				#echo "Because of r$r1s-c$cnum moved r$r2s-$other from revboth to complex"
			fi
		fi
	done
done

# and same in other direction
for cnum in $revcomplexevol
do
	# find the set of peers for this node
	needle="cluster$cnum.json"
	others1=`grep "$needle" $iprev | awk '{for (i=6;i<=NF;i++){print $i}}'`
	needle2="/$cnum overlaps with"
	others2=`grep "$needle2" $fprev | awk '{for (i=4;i<=NF;i++){print $i}}' | sed -e 's/.*\///'`
	for other in $others1 $others2
	do
		# add to rev complex if not there already
		if [[ $(wordinlist "$fwdcomplexevol" $other) != "" ]]
		then
			#echo "r$r2s"c"$cnum other r$r1s-$other is already complex"
			foo="bar"
		else
			if [[ $(wordinlist "$fwdipevol" $other) != "" ]]
			then
				fwdipevol=$(takewordfromlist "$fwdipevol" $other)
				fwdcomplexevol="$other $fwdcomplexevol"
				#echo "Because of r$r2s-c$cnum moved r$r1s-$other from revip to complex"
			elif [[ $(wordinlist "$fwdfpevol" $other) != "" ]]
			then
				fwdfpevol=$(takewordfromlist "$fwdfpevol" $other)
				fwdcomplexevol="$other $fwdcomplexevol"
				#echo "Because of r$r2s-c$cnum moved r$r1s-$other from revfp to complex"
			elif [[ $(wordinlist "$fwdbothevol" $other) != "" ]]
			then
				fwdbothevol=$(takewordfromlist "$fwdbothevol" $other)
				fwdcomplexevol="$other $fwdcomplexevol"
				#echo "Because of r$r2s-c$cnum moved r$r1s-$other from revboth to complex"
			fi
		fi
	done
done

dc_count=$(wordcount "$disappeared")
fi_count=$(wordcount "$fwdipevol")
fp_count=$(wordcount "$fwdfpevol")
fb_count=$(wordcount "$fwdbothevol")
fc_count=$(wordcount "$fwdcomplexevol")
echo "Forward:" 
echo "Disappeared: $dc_count"
echo "Lone IP evol: $fi_count"
echo "Lone FP evol: $fp_count"
echo "Both evol: $fb_count"
echo "Complex: $fc_count"
echo "Total: $((dc_count+fi_count+fp_count+fb_count+fc_count))"
echo "Check: $r1count"
echo 

ap_count=$(wordcount "$appeared")
ri_count=$(wordcount "$revipevol")
rp_count=$(wordcount "$revfpevol")
rb_count=$(wordcount "$revbothevol")
rc_count=$(wordcount "$revcomplexevol")
echo "Reverse:"
echo "Appeared: $ap_count"
echo "Lone IP evol: $ri_count"
echo "Lone FP evol: $rp_count"
echo "Both evol: $rb_count"
echo "Complex: $rc_count"
echo "Total: $((ap_count+ri_count+rp_count+rb_count+rc_count))"
echo "Check: $r2count"
echo

echo "fwdcomplex: $fwdcomplexevol"
echo "revcomplex: $revcomplexevol"

ctmpf="/tmp/complex.XXXX"
rm -f $cp_text
listevol $ctmpf $ipfwd "ip" $r1s $r2s "$fwdcomplexevol"
cat $ctmpf >>$fc_text
listevol $ctmpf $fpfwd "fp" $r1s $r2s "$fwdcomplexevol"
cat $ctmpf >>$fc_text
cat $fc_text | sort -V | uniq >$ctmpf
mv $ctmpf $fc_text
listevol $ctmpf $iprev "ip" $r2s $r1s "$revcomplexevol"
mv $ctmpf $rc_text
listevol $ctmpf $fprev "fp" $r2s $r1s "$revcomplexevol"
cat $ctmpf >>$rc_text
cat $rc_text | sort -V | uniq >$ctmpf
mv $ctmpf $rc_text


# output remaining to files, before making graphs
listout $dc_text $r1s "$disappeared"
listout $ap_text $r2s "$appeared"

listevol $fi_text $ipfwd "ip" $r1s $r2s "$fwdipevol"
listevol $fp_text $fpfwd "fp" $r1s $r2s "$fwdfpevol"

listevol $ri_text $iprev "ip" $r2s $r1s "$revipevol"
listevol $rp_text $fprev "fp" $r2s $r1s "$revfpevol"

btmpf="/tmp/both.XXXX"
listevol $btmpf $ipfwd "ip" $r1s $r2s "$fwdbothevol"
mv $btmpf $fb_text
listevol $btmpf $fpfwd "fp" $r1s $r2s "$fwdbothevol"
cat $btmpf >>$fb_text
cat $fb_text | sort -V | uniq >$btmpf
mv $btmpf $fb_text
listevol $btmpf $iprev "ip" $r2s $r1s "$revbothevol"
mv $btmpf $rb_text
listevol $btmpf $fprev "fp" $r2s $r1s "$revbothevol"
cat $btmpf >>$rb_text
cat $rb_text | sort -V | uniq >$btmpf
mv $btmpf $rb_text


#echo "Forward:"
#echo "Disappeared $disappeared"
#echo "Lone IP evol $fwdipevol"
#echo "Lone FP evol $fwdfpevol"
#echo "Both evol $fwdbothevol"
#echo "Complex $fwdcomplexevol"
#echo "Reverse:"
#echo "Appeared $disappeared"
#echo "Lone IP evol $revipevol"
#echo "Lone FP evol $revfpevol"
#echo "Both evol $revbothevol"
#echo "Complex $revcomplexevol"


exit

preamble $fullgraph 
subgraph $fullgraph "r$r1s"

for node in $r1nodes
do
	echo "r"$r1s"c"$node [color=$r1ncol style="filled"] >>$fullgraph
done

endgraph $fullgraph
subgraph $fullgraph "r$r2s"

for node in $r2nodes
do
	echo "r"$r2s"c"$node [color=$r2ncol style="filled"] >>$fullgraph
done

endgraph $fullgraph

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

endgraph $fullgraph

# make rest graph

for node in $nodes
do
	# count occurrences
	count=`grep -w -c $node $fullgraph`
	#echo "$node occurs $count times"
	if ((count== 1 || count == 5))
	then
		zaps="$node $zaps"
		((zcount++))
		if ((count == 1 ))
		then
			echo $node >>$unlinked
		fi
		if ((count == 5 ))
		then
			echo $node >>$locallinked
		fi
	else
		keeps="$node $keeps"
		echo $node >>$complexlinked
		((kcount++))
	fi
done

echo "zaps: $zcount"
echo "keeps: $kcount"

ztmpf=`mktemp ./zaps.XXXX`
ktmpf=`mktemp ./keep.XXXX`
kntmpf=`mktemp ./keepn.XXXX`

echo "$zaps" | sed -e 's/ /\n/g' | sed -e '/^$/d' >$ztmpf
echo "$keeps" | sed -e 's/ /\n/g' | sed -e '/^$/d' >$ktmpf

# we need to extend keeps to add in nodes that are mentioned
# in edges
grep -v filled $fullgraph | \
		grep -w -f $ktmpf | \
		sed -e 's/ -> / /g' | \
		sed -e 's/\[col.*//' | \
		sed -e 's/ /\n/' | \
		sed -e 's/ //g' | \
		sort | uniq >$kntmpf


# next one needs pre/postamble etc., but gives good graph:-)
# ... when manually done: TODO: automate
preamble $complexgraph
subgraph $complexgraph "r$r1s"
grep "filled" $fullgraph | grep -w -f $kntmpf -  >>$complexgraph
endgraph $complexgraph 
grep " \-" $fullgraph | grep -w -f $ktmpf -  >>$complexgraph
endgraph $complexgraph 

# TODO: need to take some back out of zaps so...
preamble $restgraph
subgraph $restgraph "r$r1s"
grep "filled" $fullgraph | grep -w -f $ztmpf -  >>$restgraph
endgraph $restgraph 
grep " \-" $fullgraph | grep -w -f $ztmpf -  >>$restgraph
endgraph $restgraph 

# render images
echo "Rendering $fullgraph with $gvtool"
$gvtool -T$imgfmt $fullgraph >$fullgraphimg
$gvtool -T$imgfmt $complexgraph >$complexgraphimg
$gvtool -T$imgfmt $restgraph >$restgraphimg

# Summarise
fwdulcount=`grep "^r$r1s" $unlinked | sort | uniq | wc -l`
revulcount=`grep "^r$r2s" $unlinked | sort | uniq | wc -l`
fwdscount=`grep "^r$r1s" $locallinked | sort | uniq | wc -l`
revscount=`grep "^r$r2s" $locallinked | sort | uniq | wc -l`
fwdccount=`grep filled $complexgraph | grep "^r$r1s" | sort | uniq | wc -l`
revccount=`grep filled $complexgraph | grep "^r$r2s" | sort | uniq | wc -l`
totalcount=`grep -c filled $fullgraph`

echo "Run1 clusters: $r1count"
echo "Run2 clusters: $r2count"
totcheck=$((r1count+r2count))
echo "Total clusters: $totcheck"

echo ""

echo "Run1 clusters: $r1count"
echo "    Unlinked forward: $fwdulcount"
echo "    Simply linked forward: $fwdscount"
echo "    Complex linked forward: $fwdccount"
fwdcheck=$((fwdulcount+ fwdscount+ fwdccount))
if ((r1count != fwdcheck)) 
then
		echo "    EEK error counting (off by $((r1count-fwdcheck))" 
fi

echo "Run2 clusters: $r2count"
echo "    Unlinked reverse: $revulcount"
echo "    Simply linked reverse: $revscount"
echo "    Complex linked revsrse: $revccount"
revcheck=$((revulcount+ revscount+ revccount))
if ((r2count != revcheck)) 
then
		echo "    EEK error counting (off by $((r2count-revcheck)) )" 
fi

echo "Total clusters check: $totalcount"
if ((totalcount!=totcheck))
then
		echo "    EEK - error counting (off by $((totalcount-totcheck)) )"
fi

# cleanup
rm -f $ztmpf $ktmpf $kntmpf
