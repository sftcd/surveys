#!/usr/bin/python

# censys.io sample API code from https://censys.io/api

import censys.certificates

# CensysApiKey.py should have lines like these with your a/c 
# specific values, that your find at: https://censys.io/account
# UID = "9b611dbd-366b-41b1-a50e-1a024004609f"
# SECRET = "wAUW4Ax9uyCkD7JrgS1ItJE5nHQD5DnR"

from CensysApiKey import UID, SECRET

print UID

certificates = censys.certificates.CensysCertificates(UID, SECRET)
fields = ["parsed.subject_dn", "parsed.fingerprint_sha256", "parsed.fingerprint_sha1"]

for c in certificates.search("validation.nss.valid: true"):
    print c["parsed.subject_dn"]
