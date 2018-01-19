#!/bin/bash

#set -x

NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`

echo "Rnning $0 at $NOW"

BIND=$HOME/code/surveys
TOP=$HOME/data/smtp

# countries
CCS="IE EE"

outdir=$TOP/runs
mkdir -p $outdir

sdir=`/bin/pwd`

for country in $CCS
do
	files=$TOP/$country/ipv4.201*.json
	for file in $files
	do
		bname=`basename $file .json | sed -e 's/ipv4.//'`
		echo "Doing $bname"
		# it takes a wile to do these
		NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
		# place for results
		resdir=$outdir/$NOW
		# just in case an error causes us to crap out within a second
		while [ -d $resdir ]
		do
			echo "Name collision! Sleeping a bit"
			sleep 5
			NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
			resdir=$outdir/$country-$NOW
		done
		mkdir -p $resdir
		cd $resdir
		echo "Starting at $NOW" >>$bname.out
		# now do the long long thing...
		$BIND/SameKeys.py $file >$bname.out 2>&1 
		NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
		echo "Finished at $NOW" >>$bname.out
	done
done

NOW=`date -u --rfc-3339=s | sed -e 's/ /T/' | sed -e 's/:/-/g'`
echo "Overall Finished at $NOW"

cd $sdir

