#!/usr/bin/python

# this starts to classify the output file we got back from
# CensysIESMTP.py

import sys
import json

file_path="./iesmtp.json"

with open(file_path) as f:
    f1=open('iesmtp-some-security.json', 'w')
    f2=open('iesmtp-no-security.json', 'w')
    f3=open('iesmtp-exception.json', 'w')
    count=0
    for line in f:
        j_content = json.loads(line)
    	p25=j_content['p25']
    	try:
            if p25['smtp']['starttls']['tls']['signature']['valid'] == True :
                f1.write(json.dumps(j_content) + '\n')
            else :
                f2.write(json.dumps(j_content) + '\n')
        except :
            f3.write(json.dumps(j_content) + '\n')
        count=count+1
        #if count==10:
            #break
