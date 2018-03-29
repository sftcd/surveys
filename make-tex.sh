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

function convdate()
{
	# we expect that to be <somethingnondecimal>YYYYmmdd-HHMMSS[.out]
	dec=`echo $1 | sed -e 's/[a-zA-Z]//g'` 
	if [[ $dec == -* ]]
	then
	 	dec=${dec:1}
	fi
	d1=`echo $dec | sed -e 's/-.*//'`
	d2=`echo $dec | sed -e 's/.*-//' | sed -e 's/\..*//' | sed 's/.\{2\}/&:/g' | sed -e 's/:$//'`
	date -d"$d1 $d2" +"%Y-%m-%d %H:%M:%S"
}
	
function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
startdir=`/bin/pwd`
srcdir=$HOME/code/surveys/

function usage()
{
	echo "$0 [-r <results-directory>]"
	echo "	results-directory defaults to \$CWD"
	echo "	makes a latex source file and csv file for this run"
	exit 99
}

outdir=.
csizefile="clustersizes.csv"
country="IE"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o hr:c: -l country:,resdir:,help -- "$@")
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
		-r|--resdir) outdir="$2"; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [ ! -d $outdir ]
then
	echo "No directory $outdir"
	usage
fi
cd $outdir

if [ ! -f $csizefile ]
then
	echo "Can't see $outdir/$csizefile - exiting"
	cd $startdir
	exit 1
fi

echo "Running $0 at $NOW"
runname=`basename $PWD`
echo "Run-name is $runname"
csvfile=cs-$runname.csv

# figure out when run started - oldest date in a *.out file name
odfile=`ls -t *.out | tail -1`
startrun=$(convdate $odfile)
#echo $startrun
# try from runname
if [ "$srartrun" == "" ]
then
	startrun=$(convdate $runname)
fi


scandate=`grep "Scandate" *.out | tail -1 |  awk '{print $5" "$6}' | sed -e 's/\..*//'`
#echo $scandate
if [ "$scandate" == "" ]
then
	# fall back to now
	scandate=$(convdate $NOW)
fi

zmapips=`wc -l records.fresh | awk '{print $1}'`
#echo $zmapips
ooc=`grep wrong_country dodgy.json | wc -l`
#echo $ooc
if [[ "$country" == "" && "$ooc" == "0" ]]
then
	# weird check here as I'm depending on the out of country error to tell me what country
	# we wanted - TODO: FIXME
	echo "This is odd - zero out of country and I don't know what country! - exiting"
	exit 2
fi
if [[ "$ooc" == "0" ]]
then
	# cross-check vs. "Bad country" matching *.out
	# possible over-estimate
	ooc=`grep "Bad country" *.out | grep "Asked" | awk '{print $5}' | sort | uniq -c | sort | wc -l`
fi
incountry=$((zmapips-ooc))
#echo $incountry
dodgies=`grep '^  "' dodgy.json | wc -l`
#echo $dodgies
nocryptoseen=$((dodgies-ooc))
#echo $nocryptoseen
if [[ "$country" == "" ]]
then
	country=`grep "Asked for " *.out | awk '{print $11}' | sort | uniq -c | sort -n | tail -1 | awk '{print $2}'`
fi
#echo $country
somecrypto=$((incountry-nocryptoseen))
#echo $somecrypto
pcsome=$((100*somecrypto/incountry))
#echo $pcsome
noncluster=`grep ",n" clustersizes.csv | awk -F, '{print $1}'`
#echo $noncluster
inclusters=$((somecrypto-noncluster))
#echo $inclusters
hark=$((100*inclusters/somecrypto))
#echo $hark
numclusters=`ls cluster*.json | wc -l`
#echo $numclusters

# calculate median and average
median=`cat clustersizes.csv | sed -n -e '/collider/,$p' | grep -v "collider" | grep -v ",n" | sort -V | \
		awk -F, ' { a[i++]=$1; } END { x=int((i+1)/2); if (x < (i+1)/2) print (a[x-1]+a[x])/2; else print a[x-1]; }' `
#echo $median

average=`cat clustersizes.csv | sed -n -e '/collider/,$p' | grep -v "collider" | grep -v ",n" | sort -n | \
		awk -F, ' BEGIN { count=0;total=0}{ total+=$1;count++ } END { print total/count; }' `
#echo $average

# from here down we start to make changes to disk ...

if [ -f $csvfile ]
then
	# make one backup, just in case
	cp $csvfile $csvfile.old
fi

echo "c,s" >$csvfile
cat clustersizes.csv | sed -n -e '/collider/,$p' | grep -v "collider" | grep -v ",n" | awk -F, '{print $1","$2}'  | sort -V >>$csvfile

biggest=`tail -1 $csvfile | awk -F, '{print $1}'`
#echo $biggest

if [ ! -f hpk_summary.txt ]
then
	echo "Gotta re-count hosts/ports/keys sorry... coupla minutes..."
	$srcdir/HostPortKeyCount.py -f all-key-fingerprints.json
fi
totkeys=`tail -1 hpk_summary.txt | awk '{print $2}'`
tothostsports=`tail -2 hpk_summary.txt | head -1 | awk '{print $2}'`
pckeys=$((100*totkeys/tothostsports))

texfile=$runname.tex

cat >$texfile <<EOF
\subsubsection{Results of run $runname}

\begin{figure}
\centering
	\begin{tikzpicture}
	\begin{axis}[xmode=log, xmax=30000, ymax=3000]
	\addplot table[x=c, y expr=\thisrow{s}*\thisrow{c}, col sep=comma]{$csvfile};
	\addplot table[x=c, y=s, col sep=comma]{$csvfile};
	\end{axis}
	\end{tikzpicture}
	\begin{center}
	\centering
	\caption[clustediag]{Clustersize distribution for run $runname \footnotesize\centering circle = number of hosts in clusters of given size;square = number of clusters of given size;x = log clustersize }
	\label{fig:csizes-$runname}
	\end{center}

	\captionof{table}{Overview of run $runname}
	\label{tab:run-$runname}
	\begin{tabular} { | p{4cm} | p{3cm} | }
	\hline
	\hline Country & $country \\\\
	\hline Scan start & $startrun \\\\
	\hline Scan finish & $scandate \\\\
	\hline
	\hline Number of IPs from ZMap & $zmapips \\\\
	\hline Judged \`\`out of county'' & $ooc \\\\
	\hline \`\`In country'' IPs & $incountry \\\\
	\hline
	\hline No crypto seen & $nocryptoseen \\\\
	\hline Some Crypto & $somecrypto \\\\
	\hline Percent with some crypto & $pcsome\% \\\\
	\hline
	\hline Total crypto host/ports & $tothostsports \\\\
	\hline Total unique keys & $totkeys \\\\
	\hline Percent keys vs. max & $pckeys\% \\\\
	\hline
	\hline Keys only seen on one host & $noncluster \\\\
	\hline Hosts in clusters & $inclusters \\\\
	\hline HARK & $hark\% \\\\
	\hline Number of clusters & $numclusters \\\\
	\hline Biggest cluster size & $biggest \\\\
	\hline Median cluster size & $median \\\\
	\hline Average cluster size & $average \\\\
	\hline
	\end{tabular}

\end{figure}

Table \ref{tab:run-$runname} provides the oveview
of this run. 
Cluster sizes are distributed as shown in 
Figure \ref{fig:csizes-$runname}.

EOF

cd $startdir
