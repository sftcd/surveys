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

# superclusters! finally... a marketing name:-)

# Starting from cross-border.dot, try render a graph for each supercluster
# (each set of linked clusters)

# top of the house
TOP="$HOME/data/smtp/runs"

# srcdir 
SRC="$HOME/code/surveys"

# the overall cross-border graph is in...
CBG="$TOP/cross-border/cross-border.dot"

# latex file
LF="superclusters.tex"

# notes directory
ND="$TOP/cross-border/notes"

# IEEE latex class file (or whatever one you want)
CLASSFILE="$SRC/cross-border/IEEEtran.cls"

# anonymise or not (not => IP addresses as node names in graphs)
anon=true

# default output directory
outdir="thesupers"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o hac:o: -l country:,anon,outdir:help -- "$@")
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
		-a|--anon) anon=false; shift;;
		-o|--outdir) outdir=$2; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

# The plan: 
#	- break cross-border.dot into connected components
#	- for each
#		- create a graph with subgraphs for each linked cluster
#			- requires renaming nodes from run-specific indices that we usually use
#			  e.g. "1234" will have to go to "XX1234" where XX is the relevant
#			  country code (if IP addresses in use, then this doesn't apply)
#		- add cross-boder edges between the hosts
#			- not sure if those'll be sparse or dense, if the latter we 
#			  may need to abstract 'em somehow

tmpdir=`mktemp -d /tmp/cbgbXXXX`
currdir=$PWD
if [ ! -d $tmpdir ]
then
	echo "Couldn't make temp dir $tmpdir - exiting"
	exit 1
fi
cd $tmpdir

# split into connected components
ccomps -x -o super $CBG
complist=`ls super*`

total=`ls super* | wc -l`
count=0


# We need a name for those, 1st named cluster is what we'll use.
namelist=""

cp $CLASSFILE $tmpdir

cat <<EOF >>$LF
\\documentclass[10pt,final,journal,twoside,pdftex]{IEEEtran}
\\usepackage{graphicx,amsmath,amssymb,url,subfigure,mdframed}
\\usepackage[section]{placeins} %Float Barriers
\\usepackage{fancyhdr}
\\pagestyle{fancy}
\\fancyhead{} % clear all header fields
\\renewcommand{\\headrulewidth}{0pt} % no line in header area
\\fancyfoot{} % clear all footer fields
\\fancyfoot[LE,RO]{\\thepage}           % page number in "outer" position of footer line
\\fancyfoot[RE,LO]{NOT FOR RELASE CONTAINS IDENTIFYING INFORMATION} % other info in "inner" position of footer line

\\begin{document}

EOF

if [ -f $ND/intro.tex ]
then
	# cat $ND/intro.tex >>$LF
	echo "\\input $ND/intro" >>$LF
fi


for comp in $complist
do
	# name them
	# echo $comp
	firsty="SC"`grep " -- " $comp | head -1 | awk '{print $1}'`
	if [[ "$firsty" == "" ]]
	then
		echo "Oops - no edges in $comp - skipping"
		continue
	fi
	count=$((count+1))
	echo "Doing $firsty which is $count of $total"
	namelist="$namelist $firsty"
	# extract set of cc/cnum's from $comp
	allcnames=`grep " -- " $comp | awk '{print $1 " " $3 }' | sed -e 's/;//'`
	cnames=`echo $allcnames | sed -e 's/ /\n/g' | sort | uniq`
	fnamelist=""
	for cname in $cnames
	do
		cc=${cname:0:2}
		cnum=${cname:2}
		#echo "Checking for |$cc| and |$cnum|"
		fname_re="$TOP/$cc-2018*/cluster$cnum.json $TOP/$cc-2019*/cluster$cnum.json"
		fname=""
		for f in $fname_re
		do
			#echo "Checking for $f"
			if [[ "$f" != "" && -f $f ]]
			then
				fname=$f
				#echo "Found $fname"
				break
			fi
		done
		if [[ "$fname" == "" ]]
		then
			echo "Oops - can't find cluster file for $comp - skipping"
			continue
		fi
		#echo "Cluster file for $comp/$firsty/$cname is $fname"
		fnamelist="$fnamelist $fname"
	done
	#echo "$comp/$firsty involves $fnamelist"
	# $SRC/cross-border/MultiGraph.py -n $firsty -i "$fnamelist" -o "$firsty-detail.dot"
	# rename connected component file to something useful
	echo "Report on $firsty super-cluster" >$firsty-dets.txt
	echo "Clusters: $cnames" | tr '\n' ' ' >>$firsty-dets.txt 
	echo ""  >>$firsty-dets.txt 
	echo "Fingerprint counts (most common 20): " >>$firsty-dets.txt
	# last few/most common fingerprints
	$SRC/clustertools/fpsfromcluster.sh "$fnamelist" | tail -21 >>$firsty-dets.txt
	echo ""  >>$firsty-dets.txt 
	mv $comp $firsty-ov.dot
	sfdp -Tsvg $firsty-ov.dot >$firsty.svg
	# latex on my laptop doesn't like svg
	sfdp -Tpng $firsty-ov.dot >$firsty.png
	cat <<EOF >>$LF

		\\section{$firsty}\\label{sec:$firsty}
		\\begin{figure}
		\\centering
			\\includegraphics[width=5cm,keepaspectratio]{$firsty.png}
			\\caption[clustediag]{Cross-border supercluster $firsty} 
			\label{fig:$firsty}
		\\end{figure}

		Figure \\ref{fig:$firsty} shows the graph for this supercluster.
EOF

	$SRC/clustertools/ClusterStats.py -i "$fnamelist" -l -t $firsty >>$LF

	if [ -f $ND/$firsty.tex ]
	then
		#cat $ND/$firsty.tex >>$LF
		echo "\\input $ND/$firsty" >>$LF
	fi

	# include cluster specific images where possible
	for fname in $fnamelist
	do
		# have to dervice cc/cnum again from fname
		rundir=`dirname $fname`
		runbase=`basename $rundir`
		cc=${runbase:0:2}
		cnum=`basename $fname .json | sed -e 's/cluster//'`
		# derive image file 
		svgfile=`echo $fname | sed -e 's/\/cluster/\/graph/' | sed -e 's/\.json/\.dot.svg/'`
		pngfile=`echo $fname | sed -e 's/\/cluster/\/graph.dot/' | sed -e 's/\.json/\.dot.png/'`
		wordlefile=`echo $fname | sed -e 's/\.json/-wordle\.png/'`
		cimg="false"
		if [ -f $pngfile ]
		then
			# copy
			cp $pngfile $cc$cnum.png
			cimg="true"
		else
			if [ -f $svgfile ]
			then
				# convert locally
				convert $svgfile $cc$cnum.png
				cimg="true"
			else
				echo "No image for cluster $cnum in run $cc as part of $firsty." >>$LF
			fi
		fi
		if [[ "$cimg" == "true" ]]
		then
			# add image and ref so latex doesn't barf
			cat <<EOF >>$LF

		\\begin{figure}
		\\centering
			\\includegraphics[width=5cm,keepaspectratio]{$cc$cnum.png}
			\\caption[clustediag]{Cluster $cc$cnum, part of $firsty} 
			\label{fig:$cc$cnum}
		\\end{figure}

		Figure \\ref{fig:$cc$cnum} shows the graph for cluster $cnum in run $cc, a part of $firsty.
EOF
		fi

		if [ -f $wordlefile ]
		then
			# local copy
			cp $wordlefile $cc$cnum-wordle.png
			# add image and ref so latex doesn't barf
			cat <<EOF >>$LF

		\\begin{figure}
		\\centering
			\\includegraphics[width=5cm,keepaspectratio]{$cc$cnum-wordle.png}
			\\caption[clustediag]{Cluster $cc$cnum words, part of $firsty} 
			\label{fig:$cc$cnum-words}
		\\end{figure}

		Figure \\ref{fig:$cc$cnum-words} shows the names for cluster $cnum in run $cc.
EOF
		fi

	done



	cat <<EOF >>$LF

	\\begin{figure*}
	\\begin{mdframed}
	\\begingroup
	\\fontsize{8pt}{10pt}\\selectfont
	\\begin{verbatim}
EOF

	cat $firsty-dets.txt >>$LF

	cat <<EOF >>$LF

	\\end{verbatim}
	\\endgroup
	\\end{mdframed}
	\\caption{The 20 most common fingerprints involved in the $firsty supercluster.}
	\\label{fig:$firsty-dets}
	\\end{figure*}

	Figure \\ref{fig:$firsty-dets} shows the 20 most common fingerprints involved in the $firsty supercluster.

EOF

done

cat <<EOF >>$LF
\\end{document}
EOF

# make a pdf
pdflatex $LF
pdflatex $LF

# is outdir an absolute path? if so, $absdir will be "/" or "~"
absdir="${outdir:0:1}" 

fulloutdir=$currdir/$outdir

if [[ "$absdir" == "/" || "$absdir" == "~" ]]
then
	fulloutdir=$outdir
fi

if [ ! -d $fulloutdir ]
then
	mkdir $fulloutdir
fi
if [ ! -d $fulloutdir ]
then
	echo "Oops - can't create/find $fulloutdir - exiting (files may be in $tmpdir)"
	exit 2
fi
mv $tmpdir/* $fulloutdir

# clean up (or say where temp stuff is)
rm -rf $tmpdir
# echo "Left stuff in $tmpdir for you."

# go back to where we came from
cd $currdir

