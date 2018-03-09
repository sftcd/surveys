#!/bin/bash

# set -x

# grab the records for the IPs involved in a collision cluster
# from the dot file for the graph

gfile=$1
srcfile=$2
outfile=$3

if [[ "$gfile" == "" || "$srcfile" == "" || "$outfile" == "" ]]
then
	echo "usage: $0 <graphfile> <censys-file> <outfile>"
	echo "\trecords in <srcfile> matching IPs from <graphfile> will be appended to <outfile>"
	exit 1
fi

ips=`grep filled $gfile | awk '{print $1}'`
count=0
for ip in $ips
do
		grep '"ip":'$ip $srcfile >>$outfile
		((count=count+1))
done

echo "Grepped for $count IPs"
