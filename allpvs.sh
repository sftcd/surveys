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

# do all protocol versions...

TOP="$HOME/data/smtp/runs"
SRCDIR="$HOME/code/surveys"

PLACE=$PWD

SO=pvno.tex
SE=pvno.err

if [ -f $SO ]
then
	mv $SO $SO.old
fi

if [ -f $SE ]
then
	mv $SE $SE.old
fi

FSE=$PLACE/$SE

# preamble for tex file...
cat >$SO <<EOF

\\subsection{TLS Versions}

\\begin{table}
        \\centering
        \\caption{TLS Versions seen on various ports}
        \\begin{tabular} { | l | l | r | r | r | r |}

EOF

# do 5 countries per table as that fits in a column ok
runcount=0
overalls=""
for rundir in $TOP/??-201[89]*
do
	tmpo=`mktemp /tmp/tmpoXXXX`
	runname=`basename $rundir | awk -F'-' '{print $1"-"$2}'`
	echo "Doing $runname"
	cd $rundir
	$SRCDIR/ProtocolVersions.py >$tmpo 2>>$FSE
	# overall lines for later
	ol=`grep "^Total" $tmpo | sed -e 's/Total/'$runname'/'`
	overalls="$overalls\n$ol \\\\ \\hline"
	cat $tmpo >>$PLACE/$SO 
	rm -f $tmpo
	echo "" >>$PLACE/$SO
	runcount=$((runcount+1))
	if [[ "$runcount" == "5" ]]
	then
		cat >>$PLACE/$SO <<EOF

    \\end{tabular}
    \\label{tab:tlsversions}
\\end{table}

\\begin{table}
        \\centering
        \\caption{TLS Versions seen on various ports}
        \\begin{tabular} { | l | l | r | r | r | r |}

EOF
	fi
done
cd $PLACE

cat >>$SO <<EOF

    \\end{tabular}
    \\label{tab:tlsversions2}
\\end{table}

EOF

# generate the totals table too...

# accumulate totals and percents
sslv3_tot=`cat $SO | grep "^Total" | awk '{sum+=$3}END{print sum}'`
tls10_tot=`cat $SO | grep "^Total" | awk '{sum+=$5}END{print sum}'`
tls11_tot=`cat $SO | grep "^Total" | awk '{sum+=$7}END{print sum}'`
tls12_tot=`cat $SO | grep "^Total" | awk '{sum+=$9}END{print sum}'`
tot_tot=`cat $SO | grep "^Total" | awk '{sum+=$11}END{print sum}'`
sslv3_pc="0.$((sslv3_tot*10000/tot_tot))\\%"
tls10_pc="0.$((tls10_tot*10000/tot_tot))\\%"
tls11_pc="0.$((tls11_tot*10000/tot_tot))\\%"
tls12_pc="0.$((tls12_tot*10000/tot_tot))\\%"

cat >>$SO <<EOF
\begin{table}
        \centering
        \caption{TLS Versions seen overall}
        \begin{tabular} { | l | r | r | r | r | r |}
        \hline
		Run & SSLv3 & TLSv1.0 & TLSv1.1 & TLSv1.2 & Total \\\\ \hline

EOF

echo $overalls >>$SO

cat >>$SO <<EOF
		Total & $sslv3_tot & $tls10_tot & $tls11_tot & $tls12_tot & $tot_tot \\\\ \\hline
		Percent & $sslv3_pc & $tls10_pc & $tls11_pc & $tls12_pc & 100\% \\\\ \\hline

    \\end{tabular}
    \\label{tab:tlsversionsoverall}
\\end{table}

EOF
