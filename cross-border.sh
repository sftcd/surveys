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

# Analyse the cross-border fingerprint linkages

# defaults
srcdir=$HOME/code/surveys
resdir=$HOME/data/smtp/runs
crossdir=$HOME/data/smtp/runs/cross-border
statefile=$crossdir/already-done
newdir=""
justgraph="no"

function usage()
{
	echo "usage: $0 [-g] [ -n <new-country-directory>] [-c <cross-border-directory>] [-r <results-directory>] [ -s <state-file>]"
	echo"   -g means to assume fingerprint matching was done and skip to graphing"
	echo "	new-country-directory has no default, use e.g. XX-2018MMDD-HHMMSS where XX is a country-code"
	echo "	cross-border--directory defaults to \$HOME/data/smtp/runs/cross-border/"
	echo "	results-directory defaults to \$HOME/data/smtp/runs"
	echo "	state-file defaults to \$crossborderdir/already-done"
	exit 99
}

declare -A cc_colours=( [IE]="green" \
						[EE]="grey" \
						[PT]="red" \
						[FI]="blue" \
						[LU]="pink" \
						[UY]="lightblue" \
						[NZ]="black" \
					)

function nodecolour()
{
	cc=${1:0:2}
	echo ${cc_colours[$cc]}
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o gc:r:n:s:h -l graph,crossdir:,resdir:,new:,state:,help -- "$@")
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
		-g|--graph) justgraph="true"; shift;;
		-c|--crossdir) crossdir="$2"; shift;;
		-r|--resdir) outdir="$2"; shift;;
		-n|--new) newdir="$2"; shift;;
		-s|--state) statefile="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [[ "$justgraph" != "true" ]]
then
	if [ "$newdir" == "" ]
	then
		echo "You have to supply the new country diretory"
    	usage	
	fi
	if [ ! -d $resdir ]
	then
		echo "Can't find diretory $resdir"
		exit 1
	fi
	if [ ! -d $crossdir ]
	then
		echo "Can't find diretory $crossdir"
		exit 2
	fi
	if [ ! -d $newdir ]
	then
		echo "Can't find diretory $newdir"
		exit 2
	fi
fi

if [ ! -f $statefile ]
then
	# check in $crossdir too
	if [ ! - f $crossdir/$statefile ]
	then
		echo "Can't read $statefile"
		exit 3
	else
		absstatefile=$crossdir/$statefile
	fi
else
	absstatefile=$statefile
fi 

# read state
existing=`cat $absstatefile`
names="$existing"

if [[ "$justgraph" != "true" ]]
then
	newname=`basename $newdir`
	names="$newname $existing"
	donealready=`grep -c $newname $absstatefile`
	if ((donealready >0))
	then
		echo "$newname is already in $absstatefile"
		exit 4
	fi

	echo "Cross-border: adding $newname "
	for dir in $existing 
	do
		if [ -f $newname-$dir ]
		then
			echo "Skipping $newname-$dir - file exists"
		else
			echo "Comparing $newname to $dir"
			$srcdir/clustertools/fpoverlaps.sh -1 $resdir/$newname -2 $resdir/$dir >$newname-$dir 2>&1
		fi
	done
	allgood="yes"
	# end add to state
	if [ "$allgood" == "yes" ]
	then
		echo $newname >>$absstatefile
	fi
fi


namearr=($names)
nnamearr=${#namearr[@]}
tmpf=`mktemp /tmp/cross.XXXX`
for ((i=0; i!=nnamearr; i++))
do
	for ((j=i+1; j!=nnamearr; j++))
	do
		fname="${namearr[j]}-${namearr[i]}"
		if [ -f $fname ]
		then
			#echo "Graphing $fname"
			# short names for nodes
			l1=${namearr[j]}
			s1=${l1:0:2}
			#echo "short1=$s1"
			l2=${namearr[i]}
			s2=${l2:0:2}
			#echo "short1=$s2"

			stuff=`grep -v "no overlap" $fname | \
						grep -v "Doing" | \
						awk -F'/' '{for (i=15;i<=NF;i++){print "'$s1'"$8"-""'$s2'"$i" " }}' | \
						sed -e 's/ overlaps with //'`
			#echo $stuff
			for item in $stuff
			do
				# write node
				n1=`echo $item | sed -e 's/-.*//'`
				n2=`echo $item | sed -e 's/.*-//'`
				echo "		$n1 [color=$(nodecolour $n1), style=filled]"  >>$tmpf
				echo "		$n2 [color=$(nodecolour $n2), style=filled]"  >>$tmpf
				# write edge
				edge=`echo $item | sed -e 's/-/ -- /'`
				echo "		$edge" >>$tmpf
			done
		else
			echo "Skipping $fname - doesn't exist!"
		fi
	done
done

# sort, uniq and add graph headers/footers

# preamble
cat <<EOF
graph crossborder {
	// rankdir="LR"; 
	packMode="array_u";
	graph [compound=true;splines=true;overlap=false]

EOF

# nodes
for cc in "${!cc_colours[@]}"
do
	echo "	subgraph $cc {"
	echo "		rank=\"same\";"
	cat $tmpf | grep "color" | grep $cc | sort -V | uniq 
	echo "	}"
	echo
done

# edges
cat $tmpf | grep -v "color" | sort -V | uniq 

# finish
echo "}"

# clean up
rm -f $tmpf

exit 0

