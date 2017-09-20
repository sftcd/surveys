#!/usr/bin/python

# censys.io sample API code from https://censys.io/api

# you need specific permission to use the export API
# I'm just figuring out how to get it to work still
# so don't believe this code:-)

import censys.export

# CensysApiKey.py should have lines like these with your a/c 
# specific values, that your find at: https://censys.io/account
# UID = "9b611dbd-366b-41b1-a50e-1a024004609f"
# SECRET = "wAUW4Ax9uyCkD7JrgS1ItJE5nHQD5DnR"

from CensysApiKey import UID, SECRET

c = censys.export.CensysExport(UID,SECRET)

# Start new Job - all Irish smtp speakers
# works
#res = c.new_job('select * from ipv4.20170915 where ip="185.24.233.211"')

# fails - get invalid timestamp value after ~20s
# "u'invalidQuery: Invalid timestamp value: 1485270009142000000'} "
#res = c.new_job('select * from ipv4.20170914 where location.country_code="IE" and p25.smtp.starttls.banner IS NOT NULL')

# works we get 12580
#res = c.new_job('select count(ip) from ipv4.20170914 where location.country_code="IE" and tags contains "smtp"')

# fails with a weird error "Cannot query the cross product of repeated fields 
# p995.pop3s.tls.tls.certificate.parsed.extensions.subject_alt_name.other_names.value and tags"
#res = c.new_job('select * from ipv4.20170914 where location.country_code="IE" and tags contains "smtp"')

# try select specific columns
# same timestamp failure if we select p25
# res = c.new_job('select * from ipv4.20170914 where p25.smtp.starttls.timestamp <= "1505579075" and location.country_code="IE" and p25.smtp.starttls.banner IS NOT NULL')

# same old...
#res = c.new_job('select * from ipv4.20170914 where ' 
                #'location.country_code="IE" and '
                #'p25.smtp.starttls.banner IS NOT NULL and '
                #'p25.smtp.starttls.timestamp < TIMESTAMP("2017-12-31 23:59:59.999999") and '
                #'p25.smtp.starttls.timestamp > TIMESTAMP("2017-01-01 00:00:00")')

# res = c.new_job('select p21.*, p20000.*, p7547.*, p80.*, p443.*, p23.*, p445.*, p143.*, p53.*, autonomous_system.*, p1911.*, p22.*, ipint.*, location.*, metadata.*, tags.*, p102.*, p993.*, p502.*, ip.*, p47808.*, p25.smtp.starttls.starttls, p25.smtp.starttls.banner, p25.smtp.starttls.tls.*, p25.smtp.starttls.metadata, p25.smtp.starttls.timestamp, p25.smtp.starttls.ehlo from ipv4.20170914 where ' 

# Try get everything except the p225.smtp.starttls.timestamp... This one gets
# invalidQuery: 0.0 - 0.0: Unable to determine schema of SELECT * in this query.
#res = c.new_job('select '
                #'ip, autonomous_system.*, ipint.*, location.*, metadata.*, tags.*, '
                #'p1911.*, p22.*, '
                #'p21.*, p20000.*, p7547.*, p80.*, p443.*, p23.*, p445.*, p143.*, p53.*, '
                #'p102.*, p993.*, p502.*, p47808.*, '
                #'p25.smtp.starttls.starttls, p25.smtp.starttls.banner, p25.smtp.starttls.tls.*, '
                #'p25.smtp.starttls.metadata, p25.smtp.starttls.timestamp, p25.smtp.starttls.ehlo '
                #'from ipv4.20170914 where ' 
                #'location.country_code="IE" and '
                #'p25.smtp.starttls.banner IS NOT NULL')


                #'p110.pop3.starttls.tls.certificate.parsed.extensions.signed_certificate_timestamps.timestamp '
                #'   < TIMESTAMP("2017-12-31 23:59:59.999999") and '
                #'p110.pop3.starttls.tls.certificate.parsed.extensions.signed_certificate_timestamps.timestamp '
                #'   > TIMESTAMP("2017-01-01 00:00:00")')

# Attempt to partition the set in case the bug depends on the
# result-size, ~7500 with "IS NOT NULL" in the case below but 
# same old error happens for both subsets
# Noteworthy that it's a different value that trips us up
# this time
# first one is error when "IS NOT NULL" for https
# invalidQuery: Invalid timestamp value: 1501499263544000000
# second one is error when "IS NULL" for https
# invalidQuery: Invalid timestamp value: 1477924637155000000
# second timestamp value repeated with 2nd run of test
# and same again some days later
#                                        1477924637155000000
res = c.new_job('select * '
                'from ipv4.20170914 where ' 
                'location.country_code="IE" and '
                'p25.smtp.starttls.banner IS NOT NULL and '
                'p443.https.tls.version IS NULL')

job_id = res["job_id"]


# Wait for job to finish and fetch results
print c.check_job_loop(job_id)

