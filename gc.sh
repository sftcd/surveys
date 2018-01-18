#!/bin/bash

# set -x

# Use openssl to dump a server cert 


error="nope"
HOST=$1
if [ "$HOST" == "" ]
then
	error="yep"
fi
PORT=$2
if [ "$PORT" == "" ]
then
	PORT=443
fi
case $PORT in
	25|143|443|993)
		;;
	*)
		error="yep"
		;;
esac

if [ "$error" == "yep" ]
then
	echo "usage: $0 <host> [<port>]"
	echo "    default port: 443,other ports supported 25,143,993"
	exit -1
fi

OUTF=$HOST-$PORT.cert.txt

echo "Getting cert for $HOST:$PORT"
if [ "$PORT" == "443" ]
then
	echo | openssl s_client -connect $HOST:$PORT | openssl x509 -noout -text >$OUTF 2>/dev/null
fi
if [ "$PORT" == "25" ]
then
	echo | openssl s_client -connect $HOST:$PORT -starttls smtp | openssl x509 -noout -text >$OUTF 2>/dev/null
fi
if [ "$PORT" == "143" ]
then
	echo | openssl s_client -connect $HOST:$PORT -starttls imap | openssl x509 -noout -text >$OUTF 2>/dev/null
fi
if [ "$PORT" == "993" ]
then
	echo | openssl s_client -connect $HOST:$PORT | openssl x509 -noout -text >$OUTF 2>/dev/null
fi

echo "Output is in $OUTF"
