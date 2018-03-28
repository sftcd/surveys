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

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)
startdir=`/bin/pwd`

echo "Running $0 at $NOW"

function usage()
{
	echo "$0 [-m] [-s <source-code-directory>] [-r <results-directory>] [-p <inter-dir>] [-c <country>] [-i <ips-src>]"
	echo "	-m means do the maxmind thing"
	echo "	source-code-directory defaults to \$HOME/code/surveys"
	echo "	country must be IE or EE, default is IE"
	echo "	results-directory defaults to \$HOME/data/smtp/runs"
	echo "	inter-directory is a directory with intermediate results we process further"
	echo "	ips-src is a file with json lines like censys.io's (original censys.io input used if not supplied"
	echo "	skips comma-sep list of stages to skip: grab,fresh,cluster,graph"
	exit 99
}

srcdir=$HOME/code/surveys
country="IE"
outdir=$HOME/data/smtp/runs
ipssrc=''
pdir=''
domm='no'
dpath=`grep mmdbpath $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}' | sed -e 's/\/$//'`
mmdbdir=$HOME/$dpath

# this form of assignment allows you to override this by setting an env
# var of this name - usually I dislike this kind of opacity but in this
# case I'll likely wanna play with different b/w on different hosts so
# it seems ok
if [[ "$zmap_parms" == "" ]]
then
	zmap_parms="-B 100K"
fi

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o ms:r:c:i:p:h -l mm,srcdir:,resdir:,country:,ips:,process:,help -- "$@")
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
		-m|--mm) domm="yes" ;;
		-s|--srcdir) srcdir="$2"; shift;;
		-r|--resdir) outdir="$2"; shift;;
		-i|--ips) ipssrc="$2"; shift;;
		-p|--process) pdir="$2"; shift;;
		-c|--country) country="$2"; shift;;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

if [ "$srcdir" == "" ]
then
	echo "No <code-directory> set"
	usage
fi

if [ ! -d $srcdir ]
then
	echo "$srcdir doesn't exist - exiting"
	usage
fi

if [ "$outdir" == "" ]
then
	echo "No <results-diretory> set"
	usage
fi

# check if country is known
cknown=`grep $country $mmdbdir/countrycodes.txt`
if [[ "$country" != "$cknown" ]]
then
	echo "Country $country isn't known"
	exit 87
fi


# place for results - might get changed by pdir
resdir=$outdir/$country\-$NOW
# this is the first one that changes disk
if [ "$pdir" == "" ]
then
	if [ ! -d $outdir ]
	then
		mkdir -p $outdir
	fi
	if [ ! -d $outdir ]
	then
		echo "Can't create $outdir - exiting"
		exit 5
	fi

	# just in case an error causes us to crap out within a second
	while [ -d $resdir ]
	do
		echo "Name collision! Sleeping a bit"
		sleep 5
		NOW=$(whenisitagain)
		resdir=$outdir/$country-$NOW
	done
	if [ ! -d $resdir ]
	then
		mkdir -p $resdir
	fi
else
	# continue processing of partly done directory content
	resdir=$pdir
	if [ ! -d $resdir ]
	then
		echo "No intermediate directory $pdir - exiting"
		exit 8
	fi
fi

cd $resdir
# make life easier
cp $srcdir/Makefile .
logf=$NOW.out
run=$NOW

echo "Starting at $NOW, log in $logf" 
echo "Starting at $NOW, log in $logf" >>$logf

# Variables to have set
unset SKIP_MM
unset SKIP_ZMAP
unset SKIP_GRAB
unset SKIP_FRESH
unset SKIP_CLUSTER
unset SKIP_GRAPH

# files uses as tell-tales
TELLTALE_MM="mm-ips."$country".v4"
TELLTALE_ZMAP="zmap.ips"
TELLTALE_GRAB="input.ips"
TELLTALE_FRESH="records.fresh"
TELLTALE_CLUSTER="collisions.json"
TELLTALE_GRAPH="graph.done"

if [ "$pdir" != "" ]
then
	# figure out where we're at...
	# if we have a $TELLTALE_GRAB then no need to grab
	if [ -f $TELLTALE_MM ]
	then
		SKIP_MM=yes
	fi
	if [ -f $TELLTALE_ZMAP ]
	then
		SKIP_ZMAP=yes
	fi
	if [ -f $TELLTALE_GRAB ]
	then
		SKIP_GRAB=yes
	fi
	# if we have a $TELLTALE_FRESH then no need to fresh
	if [ -f $TELLTALE_FRESH ]
	then
		SKIP_FRESH=yes
	fi
	# if we have a $TELLTALE_CLUSTER no need to cluster
	if [ -f $TELLTALE_CLUSTER ]
	then
		SKIP_CLUSTER=yes
	fi
	# if we have a graphed no need to graph
	if [ -f graphs.done ]
	then
		SKIP_GRAPHS=yes
	fi
fi

# now do each step in the process, where that step is wanted and needed
# Steps:

# -1: IPs from maxmind, 0: zmap for port 25
# if there's a "GRAB" telltale then don't do 
if [ "$SKIP_MM" ]
then
	echo "Skipping maxmind"
	echo "Skipping maxmind" >>$logf
else
	if [[ "$domm" == "yes" ]]
	then
		echo "starting maxmind"
		echo "starting maxmind" >>$logf
		$srcdir/IPsFromMM.py -c $country >>$logf 2>&1 
		echo "maxmind done"
		echo "maxmind done" >>$logf
	fi
fi

if [ "$SKIP_ZMAP" ]
then
	echo "Skipping zmap"
	echo "Skipping zmap" >>$logf
else
	# only if we've done the mm thing
	if [[ "$domm" == "yes" && -f $TELLTALE_MM ]]
	then
		echo "starting zmap"
		echo "starting zmap" >>$logf
		sudo zmap $zmap_parms -p 25 --whitelist-file=$TELLTALE_MM >$TELLTALE_ZMAP 2>>$logf
		ln -s $TELLTALE_ZMAP $TELLTALE_GRAB
		SKIP_GRAB="yes"
		echo "zmap done"
		echo "zmap done" >>$logf
	else
		echo "no zmap whitelist: $TELLTALE_MM"
		echo "no zmap whitelist: $TELLTALE_MM" >>$logf
	fi
fi

# 1. GrabIPs from censys.io original source or from some other json input provided
if [ "$SKIP_GRAB" ]
then
	echo "Skipping grab" 
	echo "Skipping grab" >>$logf
else


	orig_ie=$HOME/data/smtp/IE/ipv4.20171130.json
	orig_file=$orig_ie
	if [ "$country" == "EE" ]
	then
		orig_ee=$HOME/data/smtp/EE/ipv4.20171130.json
		orig_file=$orig_ee
	fi
	if [[ "$domm" != "no" && ! -f $orig_file ]]
	then
		echo "Can't find $orig_ie - exiting"
		exit 6
	fi
	if [[ "$domm" == "no" && "X$ipssrc" == "X" ]]
	then
		infile=$orig_file
	else
		# if $ipssrc is an absolute path, then fine, otherwise it's relatvie to $startdir
		if [[ "${ipsrc:0:1}" == / || "${ipsrc:0:2}" == ~[/a-z] ]]
		then
			# absolute
			infile=$ipssrc
		else
			infile=$startdir/$ipssrc
		fi
	fi

	echo "Grabbing from $infile" 
	echo "Grabbing from $infile" >>$logf
	$srcdir/GrabIPs.py -i $infile -o $TELLTALE_GRAB >>$logf 2>&1
	if [ "$?" != "0" ]
	then
		echo "Error ($?) from GrapIPs.py"
	fi
	NOW=$(whenisitagain)
	echo "Done grabbing at $NOW" 
	echo "Done grabbing at $NOW" >>$logf

fi

# 2. Get Fresh data
if [ "$SKIP_FRESH" ]
then
	echo "Skipping fresh"
	echo "Skipping fresh" >>$logf
else
	echo "Getting fresh records" 
	echo "Getting fresh records" >>$logf 
	# this takes a looooooooooong time - maybe >1 day! 
	$srcdir/FreshGrab.py -i $TELLTALE_GRAB -o $TELLTALE_FRESH -c $country >>$logf 2>&1 
	if [ "$?" != "0" ]
	then
		echo "Error ($?) from FreshGrab.py"
	fi
	echo "Done getting fresh records" 
	echo "Done getting fresh records" >>$logf 
fi

# 3. Find clusters
if [ "$SKIP_CLUSTER" ]
then
	echo "Skipping cluster"
	echo "Skipping cluster" >>$logf
else
	echo "Clustering records" 
	echo "Clustering records" >>$logf 
	# this takes a few minutes at least
	$srcdir/SameKeys.py -i $TELLTALE_FRESH -o $TELLTALE_CLUSTER -c $country >>$logf 2>&1 
	if [ "$?" != "0" ]
	then
		echo "Error ($?) from SameKeys.py"
	fi
	echo "Done clustering records" 
	echo "Done clustering records" >>$logf 
fi

# 4. Generate graphs/reports
if [ "$SKIP_GRAPH" ]
then
	echo "Skipping graphs"
	echo "Skipping graphs" >>$logf
else
	echo "Graphing records" 
	echo "Graphing records" >>$logf 
	# this takes a few minutes at least
	$srcdir/ReportReuse.py -f $TELLTALE_CLUSTER -a -l -o . -c $country >>$logf 2>&1 
	if [ "$?" != "0" ]
	then
		echo "Error ($?) from ReportReuse.py"
	else
		touch $TELLTALE_GRAPH
	fi
	echo "Done graphing records" 
	echo "Done graphing records" >>$logf 
fi
#$srcdir/SameKeys.py $file >$NOW.out 2>&1 

NOW=$(whenisitagain)
echo "Overall Finished at $NOW" >>$logf

cd $startdir

