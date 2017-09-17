#!/usr/bin/python

import sys
import json
import requests

from CensysApiKey import UID, SECRET

API_URL = "https://www.censys.io/api/v1"

res = requests.get(API_URL + "/data", auth=(UID, SECRET))
if res.status_code != 200:
	print "error occurred: %s" % res.json()["error"]
	sys.exit(1)
for name, series in res.json()["raw_series"].iteritems():
	print series["name"], "was last updated at", series["latest_result"]["timestamp"]
