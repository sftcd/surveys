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


# you gotta add a new country here for now
declare -gA cc_colours=( [IE]="green" \
			[EE]="grey" \
			[PT]="red" \
			[FI]="blue" \
			[LU]="pink" \
			[UY]="lightblue" \
			[NZ]="black" \
			[NA]="yellow" \
			[SI]="gold" \
			[SG]="orange" \
			)

function randomcolour()
{
	str=`tr -dc 'A-F0-9' < /dev/urandom | dd bs=1 count=6 2>/dev/null`
	echo "#$str"
}

function dumpcols()
{
	#declare -p cc_colours
	for cc in "${!cc_colours[@]}"
	do
		echo "$cc, ${cc_colours[$cc]}"
	done
}

lastcol=""

# return the colour of a country - if we don't know the
# country makd up a random colour
function nodecolour()
{
	cc=${1:0:2}
	if [[ "${cc_colours[$cc]}" == "" ]]
	then
		# make random colour
		rcol=$(randomcolour)
		#cc_colours[$cc]=$rcol
		cc_colours+=([$cc]="$rcol")
	fi
	#echo $(dumpcols)
	# read the result from this var - so's we can update it
	lastcol=${cc_colours[$cc]}
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
tmpdot=`mktemp /tmp/cross.XXXX`
tmpdotd=`mktemp -d /tmp/cross.XXXX`
# store the numbers
declare -A cb_counts
# latex temp
latmp=`mktemp /tmp/cross.XXXX`
width=1
for ((i=0; i!=nnamearr; i++))
do
	l2=${namearr[i]}
	s2=${l2:0:2}
	#echo "short1=$s2"
	nodecolour $s2
	s2col=$lastcol
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
			nodecolour $s1
			s1col=$lastcol

			stuff=`grep -v "no overlap" $fname | \
						grep -v "Doing" | \
						awk -F'/' '{print $8" "$15}' | \
						sed -e 's/ overlaps with //' | \
						awk '{for (i=2;i<=NF;i++){print "'$s1'"$1"-'$s2'"$i }}' `
			#echo $stuff
			count=0
			for item in $stuff
			do
				# write node
				n1=`echo $item | sed -e 's/-.*//'`
				n2=`echo $item | sed -e 's/.*-//'`
				if [[ "$s1col"=="black" ]]
				then
					echo "		$n1 [color=$s1col, fontcolor=white, style=filled]"  >>$tmpf
				else
					echo "		$n1 [color=$s1col, style=filled]"  >>$tmpf
				fi
				if [[ "$s2col"=="black" ]]
				then
					echo "		$n2 [color=$s2col, fontcolor=white, style=filled]"  >>$tmpf
				else
					echo "		$n2 [color=$s2col, style=filled]"  >>$tmpf
				fi
				# write edge
				edge=`echo $item | sed -e 's/-/ -- /'`
				echo "		$edge" >>$tmpf
				count=$((count+1))
				# debug stuff
				#echo "stuff=$stuff;n1=$n1;n2=$n2,edge=$edge;count=$count"
			done
			cb_counts+=([$s1$s2]=$count)
		else
			echo "Skipping $fname - doesn't exist!"
		fi
	done
done

# sort, uniq and add graph headers/footers

# preamble
cat >$tmpdot <<EOF
graph crossborder {
	// rankdir="LR"; 
	packMode="array_u";
	graph [compound=true;splines=true;overlap=false]

EOF

# nodes
for cc in "${!cc_colours[@]}"
do
	echo "	subgraph $cc {" >>$tmpdot
	echo "		rank=\"same\";" >>$tmpdot
	cat $tmpf | grep "color" | grep $cc | sort -V | uniq  >>$tmpdot
	echo "	}" >>$tmpdot
	echo >>$tmpdot
done

# edges
cat $tmpf | grep -v "color" | sort -V | uniq  >>$tmpdot

# finish
echo "}" >>$tmpdot

cd $tmpdotd

# split that graph into connected components
ccomps -x -o foo $tmpdot
# figure out which of the foos have most edges
list=`grep -c " -- " foo* | awk -F':' '{print $2":"$1}' | sort -rV | awk -F':' '{print $2}'`
#imglist=`grep -c " -- " foo* | awk -F':' '{print $2":"$1}' | sort -rV | awk -F':' '{print $2".svg"}'`
imglist=""
single=0
# graph each
for file in $list
do
	count=`grep -c " -- " $file`
	if ((count>1))
	then
		sfdp -Tsvg $file >$file.svg
		imglist="$imglist $file.svg"
	else 
		single=$((single+1))
	fi
done
# whack 'em back together
montage $imglist cross-border.png

# max a .tex file with the image and table

cat >$latmp <<EOF
\\documentclass{article}
\\usepackage{graphicx,amsmath,amssymb,url,subfigure}
\\begin{document}
\\begin{figure}
\\centering
	\\includegraphics[width=1.0\\textwidth,keepaspectratio]{cross-border.png}
	\\caption[clustediag]{Cross-border overlaps for clusters with more than one link. Nodes represent clusters. There are an additional $single cases where two clusters in different countries are linked only to one another. (
EOF

for cc in "${!cc_colours[@]}"
do
		echo -n "$cc=${cc_colours[$cc]};" >>$latmp
done

cat >>$latmp <<EOF
)}
	\\label{fig:crossborder}
\\end{figure}

EOF

# and the table
cat >>$latmp <<EOF
\\begin{table}
        \\caption{Counts of cross-border links.}
EOF

echo -n "\\begin{tabular} { | l | " >>$latmp
for cc in "${!cc_colours[@]}"
do
		echo -n "c | " >>$latmp
done
cat >>$latmp <<EOF
}
    \\hline

EOF

echo "" >>$latmp
echo -n "\\hline  - " >>$latmp
for cc in "${!cc_colours[@]}"
do
	echo -n " & " >>$latmp
	printf '%3s' "$cc" >>$latmp
done
echo "\\\\" >>$latmp
for cc1 in "${!cc_colours[@]}"
do
	echo -n "\\hline " >>$latmp
	printf '%3s' "$cc1 " >>$latmp
	for cc2 in "${!cc_colours[@]}"
	do
		echo -n " & " >>$latmp
		if [[ "${cb_counts[$cc1$cc2]}" != "" ]]
		then
			printf '%3s' "${cb_counts[$cc1$cc2]}" >> $latmp
		elif [[ "${cb_counts[$cc2$cc1]}" != "" ]]
		then
			printf '%3s' "${cb_counts[$cc2$cc1]}" >> $latmp
		else 
			printf '%3s' "x" >>$latmp
		fi
	done
	echo "\\\\" >>$latmp
done

cat >>$latmp <<EOF
\\hline
\\end{tabular}
\\label{tab:crossbordercount}
\\end{table}
\\end{document}

EOF

# copy stuff we want from tmpfiles to CWD
cd -
cp $tmpdotd/cross-border.png .
cp $tmpdot cross-border.dot
cp $latmp cross-border.tex

# clean up
rm -f $tmpf $tmpdot $latmp 
rm -rf $tmpdotd

exit 0

