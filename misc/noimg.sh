#!/bin/bash

#set -x

# check which .dot files have no accompanying .png 

srcext="dot"
imgext="-sfdp.png"
if [ "$1" != "" ]
then
	imgext=$1
fi

for file in *.$srcext
do
	if [ ! -f $file$imgext ]
	then
			echo $file
	fi
done
