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

# count how many IPs were zmap'd, how many p25 listeners and percentages

TOP="$HOME/data/smtp/runs"

portstrings="p22 p25 p110 p143 p443 p587 p993"
akfile="fingerprints.json"
# some older scans (NZ in particular) have 1-line fingerprints.json
# files that won't work here (we'll get counts of 0), so to fix that
# do: cat fingerprints.json | json_pp >fingerprints_pp.json
# and then this script will read the latter file and count correctly
akfile_pp="fingerprints-pp.json"

# ok this is hacky (well, it is me:-), but we'd like a 2D array for 
# counts, so we'll declare an assoc array with the index being the
# combo of runname and port, e.g. counts["PT-20180403-005552,p25"]
# would contain a counter

declare -A overall_arr
declare -A empties_arr
declare -A nonempties_arr
declare -A dodgy_arr

for rundir in $TOP/??-201[89]*
do
	runname=`basename $rundir | awk -F'-' '{print $1"-"$2}'`
	for port in $portstrings
	do
		overall_arr["$runname,$port"]=0
		empties_arr["$runname,$port"]=0
		nonempties_arr["$runname,$port"]=0
	done
done

for rundir in $TOP/??-201[89]*
do
	runname=`basename $rundir | awk -F'-' '{print $1"-"$2}'`
	echo "Checking $rundir"
	f2c=$akfile
	if [ -f $rundir/$akfile_pp ]
	then
		f2c=$akfile_pp
	fi
	if [ -f $rundir/$f2c ]
	then
		for port in $portstrings
		do
			overall=`grep -c '"'$port'"[ ]*: {' $rundir/$f2c`
			empties=`grep -c '"'$port'"[ ]*:[ ]* {}' $rundir/$f2c`
			nonempties=$((overall-empties))
			overall_arr["$runname,$port"]=$overall
			empties_arr["$runname,$port"]=$empties
			nonempties_arr["$runname,$port"]=$nonempties
			#echo "$runname: has $overall IPs with $nonempties doing crypto on $port and $empties without"
		done 
		dcount=`grep   '"ip"' $rundir/dodgy.json  | grep , | sed -e 's/ //g' | sort | uniq | wc -l`
		#dcount=`grep -c '^    "ip":' $rundir/dodgy.json`
		if [[ "$dcount" == "0" ]]
		then
			# the NZ run has another format for some reason
			dcount=`grep -c '^      "ip" :' $rundir/dodgy.json`
			if [[ "$dcount" == "0" ]]
			then
				# another try...
				dcount=`grep   '"ip"' $rundir/dodgy.json  | grep , | sed -e 's/ //g' | sort | uniq | wc -l`
			fi
		fi
		dodgy_arr[$runname]=$dcount
	fi
done

# Ok, we'll do output as a latex table...
cat <<EOF

	\\begin{table*}
    	\\centering
        \\caption{Counts of ports with crypto}
        \\begin{tabular} { | l | r | r | r | r | r | r | r | r | r | r | r |}
        \\hline
        \\hline Run & 22 & 25 & 110 & 143 & 443 & 587 & 993 & TLS total & Crypto-IP & No-crypto-IP & Total-IPs \\\\
        \\hline

EOF

# totals
declare -A totals

grandportstotal=0
grandsomecryptototal=0
grandnocryptototal=0
grandtotal=0

for port in $portstrings
do
	totals[$port]=0
done

# print it out
for rundir in $TOP/??-201[89]*
do
	runname=`basename $rundir | awk -F'-' '{print $1"-"$2}'`
	echo -n "\\hline $runname "
	portstotal=0
	for port in $portstrings
	do
		#echo -n "$runname,$port," 
		#echo -n ${overall_arr["$runname,$port"]}
		#echo -n ","
		#echo -n ${empties_arr["$runname,$port"]}
		#echo -n ","
		#echo -n ${nonempties_arr["$runname,$port"]}
		#echo
		totals[$port]=$((${totals[$port]}+${nonempties_arr["$runname,$port"]}))
		if [[ "$port" != "p22" ]]
		then
			# count TLS services totals
			portstotal=$((portstotal+${nonempties_arr["$runname,$port"]}))
		fi
		# latex table line
		echo -n " & ${nonempties_arr["$runname,$port"]}"
	done
	# same for all so p25 will do
	iptotal=$((${overall_arr["$runname,p25"]} + ${dodgy_arr[$runname]} ))
	echo -n " & $portstotal & ${overall_arr["$runname,p25"]} & ${dodgy_arr[$runname]} & $iptotal"
	grandportstotal=$((grandportstotal+portstotal))
	grandsomecryptototal=$((grandsomecryptototal+${overall_arr["$runname,p25"]}))
	grandnocryptototal=$((grandnocryptototal+${dodgy_arr[$runname]}))
	grandtotal=$((grandtotal+$iptotal))
	echo "\\\\"
done

echo "\\hline"
echo -n "\\hline Totals "
for port in $portstrings
do
	echo -n " & ${totals[$port]}"
done
echo -n " & $grandportstotal & $grandsomecryptototal & $grandnocryptototal & $grandtotal"
echo "\\\\"
echo "\\hline"

# end of table
cat <<EOF

        \\end{tabular}
    	\\label{tab:countports}
		\\end{table*}

EOF
