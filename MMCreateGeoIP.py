#script for making GeipCountrywhois csv for input to zmap
import os
import pandas as pd

indir=os.environ['HOME']+'/code/surveys/mmdb/GeoLite2-Country-CSV_20220308/'
v4file=indir+'GeoLite2-Country-Blocks-IPv4.csv'
localefile = indir+'GeoLite2-Country-Locations-en.csv'
outfile = indir+'GeoIPCountryWhois.csv'

v4file = pd.read_csv(v4file)
#print(v4file.head)
v4file = v4file.drop(v4file.columns[[2,3,4,5]], axis=1)
#print(v4file.head)
geoip = pd.read_csv(localefile)
geoip = geoip.drop(geoip.columns[[1,2,3,6]], axis=1)
#print(geoip.head)
final_csv = v4file.merge(geoip, how='left', on="geoname_id")
final_csv.to_csv(outfile, index=False)

