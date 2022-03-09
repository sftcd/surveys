import re
import json
import jsonpickle
import copy
import os, sys, socket
import geoip2.database


# maxmind useful functions
mmdbpath = 'code/surveys/mmdb/'
mmdbir = os.environ['HOME'] + '/' + mmdbpath
print(mmdbir)

def mm_setup():
    global asnreader
    global cityreader
    global countryreader
    global countrycodes

    asnreader = geoip2.database.Reader(mmdbir + 'GeoLite2-ASN.mmdb')
    cityreader = geoip2.database.Reader(mmdbir + 'GeoLite2-City.mmdb')
    countryreader = geoip2.database.Reader(mmdbir + 'GeoLite2-Country.mmdb')
    countrycodes = []
    with open(mmdbir + 'countrycodes.csv') as ccf:
        for line in ccf:
            cc = line.strip()
            countrycodes.append(cc)
        ccf.close

def mm_info(ip):
    rv = {}
    rv['ip'] = ip
    try:
        asnresponse = asnreader.asn(ip)
        rv['asndec']=asnresponse.autonomous_system_number
        rv['asn']=asnresponse.autonomous_system_organization
        cityresponse=cityreader.city(ip)
        countryresponse=countryreader.country(ip)
        print(asnresponse)
        print(cityresponse)
        rv['lat']=cityresponse.location.latitude
        rv['long']=cityresponse.location.longitude
        print("\n\n")
        print(countryresponse)
        rv['cc']=cityresponse.country.iso_code

        if cityresponse.country.iso_code != countryresponse.country.iso_code:
            rv['cc-city']=cityresponse.country.iso_code
    
    except Exception as e:
        print(sys.stderr, "mm_info exception for: " + ip + str(e))
        rv['asndec']='unknown'
        rv['asn']=-1
        rv['cc']='unknown'
        rv['cc-city']='unknown'
    
    return rv

def mm_ipcc(ip, cc):
    if cc == "XX":
        return True
    if cc not in countrycodes:
        return False
    countryresponse = countryreader.country(ip)
    if cc == countryresponse.country.iso_code:
        return True
    else:
        return False
    



mm_setup()
