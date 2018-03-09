#!/usr/bin/python

# a python script intended to be run from cron, perhaps weekly

# censys.io sample API code from https://censys.io/api

# you need specific permission to use the export API
# I'm just figuring out how to get it to work still
# so don't believe this code:-)

import os
import time
import sys
import json
import requests
import censys.export
import censys.query

# grab a url to a file name
def DownloadFile(url,filename):
    r = requests.get(url)
    with open(filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024): 
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
    return 

# what country would you like there?
country="IE"
if len(sys.argv)==2:
    country=sys.argv[1]

# top of our storage tree
TOP="/home/stephen/data/smtp/"+country+"/"

if not os.path.isdir(TOP):
    print "Don't have a place for",country,"stuff - exiting"
    os._exit(1)


# CensysApiKey.py should have lines like these with your a/c 
# specific values, that your find at: https://censys.io/account
# UID = "9b611dbd-366b-41b1-a50e-1a024004609f"
# SECRET = "wAUW4Ax9uyCkD7JrgS1ItJE5nHQD5DnR"
from CensysApiKey import UID, SECRET

# something for the log...
print "Running ",sys.argv[0:],"at",time.asctime(time.localtime(time.time()))

# figure out latest ipv4 from which to run
# get schema and tables for a given dataset
q = censys.query.CensysQuery(UID,SECRET)
tables=q.get_series_details("ipv4")['tables']
latest=tables[-1]
print "Running query for " + country + " based SMTP speakers on", latest

# destination of our data...
fname=TOP+latest+".json"

if not os.path.isfile(fname):
    print "Fetching",fname
    # ready to make a query for that
    c = censys.export.CensysExport(UID,SECRET)
    # Start new Job - all Irish smtp speakers
    res = c.new_job('select * '
                'from ' + latest + ' where ' 
                'location.country_code="'+country+'" and '
                'p25.smtp.starttls.banner IS NOT NULL') 
    job_id = res["job_id"]
    # Wait for job to finish and fetch results
    job_res = c.check_job_loop(job_id)
    if job_res['status']=='success':
        # on success, there's a URL to go pick up the json file with
        # in theory there can be >1 URL here but I've only seen one so far
        urls=job_res['download_paths']
        url=urls[0]
        if len(urls) != 1:
            print "Warning: More than one url there, but I'm just taking the first",urls
        tfname=fname+"."+str(time.time())
        try:
            print "Downloading",url,"to",tfname
            DownloadFile(url,tfname)
            os.rename(tfname,fname)
        except Exception:
            print "Error downloading ",fname,"Maybe some content in ",tfname
else:
    print "Already had ",fname,"not fetching again"
print "Finished ",sys.argv[0:],"at",time.asctime(time.localtime(time.time()))
