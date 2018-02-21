#!/bin/bash

# check which .dot files have no accompanying .svg 

srcext="dot"
imgext="svg"

for file in *.$srcext
do
	if [ ! -f $file.$imgext ]
	then
			echo $file
	fi
done
