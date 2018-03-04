#!/bin/bash

#set -x

# verify our zgrab results for ssh via ssh-keyscan

# read IPs from a .dot file
dotfile=$1

# do the biz
ips=`grep filled $dotfile | awk '{print $1}' | sed -e 's/\"//g'` 
key0=""
totalkeys=0
samecount=0
diffcount=0
for ip in $ips
do
	sshkey=`ssh-keyscan $ip 2>/dev/null`
	# special case 1st time
	if [ "$key0" == "" ]
	then
		key0=`echo $sshkey | awk '{print $3}'`
		echo "Key0 is: $key0"
		((samecount++))
	else
		lastkey=`echo $sshkey | awk '{print $3}'`
		if [ "$lastkey" == "$key0" ]
		then
			((samecount++))
		else
			((diffcount++))
			echo "Odd key: $lastkey"
		fi
	fi
	((totalkeys++))
done
echo "Total keys: $totalkeys Matching: $samecount Different: $diffcount"

