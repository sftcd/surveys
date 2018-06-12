#!/bin/bash

# make a latex table of smells

echo "Run & Mixed & AS & SSH & Unlikely-MH & Possible MH & No-Info & Total \\\\"

index=0
for file in *smells.txt
do
	
	runs[$index]=`echo $file | awk -F- '{print $1"-"$2}'`
	mixed[$index]=`tail -7 $file | head -1 | awk '{print $2}'`
	ases[$index]=`tail -6 $file | head -1 | awk '{print $2}'`
	sshes[$index]=`tail -5 $file | head -1 | awk '{print $2}'`
	st[$index]=`tail -4 $file | head -1 | awk '{print $3}'`
	pm[$index]=`tail -3 $file | head -1 | awk '{print $3}'`
	ns[$index]=`tail -2 $file | head -1 | awk '{print $3}'`
	tot[$index]=`tail -1 $file | awk '{print $3}'`
	pct[$index]=$((st[index]*100/tot[index]))
	index=$((index+1))
done

# last line totals summary
mitot=0
astot=0
sshtot=0
sttot=0
pmtot=0
nstot=0
tottot=0


for ((i==0;i!=index;i++))
do
	echo "\\hline ${runs[$i]} & ${mixed[$i]} & ${ases[$i]} & ${sshes[$i]} & ${st[$i]} (${pct[$i]}\\%) & ${pm[$i]} & ${ns[$i]} & ${tot[$i]} \\\\" 
	mitot=$((mitot+mixed[i]))
	astot=$((astot+ases[i]))
	sshtot=$((sshtot+sshes[i]))
	sttot=$((sttot+st[i]))
	pmtot=$((pmtot+pm[i]))
	nstot=$((nstot+ns[i]))
	tottot=$((tottot+tot[i]))
done	

opct=$((sttot*100/tottot))

	echo "\\hline"
	echo "\\hline Totals & $mitot & $astot & $sshtot & $sttot ($opct\\%) & $pmtot & $nstot & $tottot \\\\"

