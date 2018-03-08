#!/bin/bash

set -x

#NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
startdir=`/bin/pwd`

echo "Rnning $0 at $NOW"

BIND=$1
outdir=$2
country=$3

function whenisitagain()
{
	date -u +%Y%m%d-%H%M%S
}

if [ "$BIND" == "" ]
then
	echo "No bindir set"
	exit 1
fi

if [ ! -d $BIND ]
then
	echo "$BIND doesn't exist - exiting"
	exit 2
fi

if [ "$country" != "IE" && "$country" != "EE" ]
then
	echo "Can't do country $country yet, only EE and IE"
	exit 3
fi

if [ "$outdir" == "" ]
then
	exit 4
fi

# for now our baseline is 20171130 from censys
orig_ee=$HOME/data/smtp/EE/ipv4.20171130.json
if [ ! -f $orig_ee ]
then
	echo "Can't find $orig_ee - exiting"
	exit 7
fi
orig_ie=$HOME/data/smtp/IE/ipv4.20171130.json
if [ ! -f $orig_ie ]
then
	echo "Can't find $orig_ie - exiting"
	exit 6
fi

# this is the first one that changes disk
if [ ! -d $outdir ]
then
	mkdir -p $outdir
fi
if [ ! -d $outdir ]
then
	echo "Can't create $outdir - exiting"
	exit 5
fi

# place for results
resdir=$outdir/$country-$NOW

# just in case an error causes us to crap out within a second
while [ -d $resdir ]
do
	echo "Name collision! Sleeping a bit"
	sleep 5
	NOW=whenisitagain
	resdir=$outdir/$country-$NOW
done

mkdir -p $resdir
cd $resdir
echo "Starting at $NOW" >>$NOW.out
# now do the long long thing...
#$BIND/SameKeys.py $file >$NOW.out 2>&1 

NOW=whenisitagain
echo "Overall Finished at $NOW" >>$NOW.out

cd $startdir

