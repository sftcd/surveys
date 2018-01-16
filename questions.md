# Quesions to ask our smtp data

Plan is to enhance Classify.py to answer these questions...


1. What names go with the record (LATER)
1. Which have detectable good DNS names
1. What product was in use
1. Which did/didn't  do SMTP/TLS on port25
1. Which were using browser-trusted certs
1. Which were using self-signed certs only
1. Which were using expired certs (self-signed or not)
1. Which were using up-to-date/out-of-date software (LATER)

1. How many postfix did/didn't do tls
1. How many named,non-postfix did/didn't do tls
1. How many non-postfix did/didn't do tls

More questions will arise as we go

Questions.py implements the above for now.
