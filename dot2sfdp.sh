#!/bin/bash

srcext="dot"
imgext="svg"
binary="sfdp"
dext="-$binary.$imgext"

for file in *.$srcext
do
	echo "Doing $file"
	outf=`basename $file`$dext
	$HOME/bin/$binary -T$imgext $file >$outf 2>/dev/null
done
