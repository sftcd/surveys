# Quesions to ask our smtp data

Plan is to enhance Classify.py to answer these questions...

1. Which are really "local"
1. Which can/can't do SMTP/TLS on port25
1. Which are using self-signed certs only
1. Which are using expired certs (self-signed or not)
1. Which are using up-to-date/out-of-date software

More questions will arise as we go

Make a decision tree of the lot answering those questions
starting with port 25 data. 

Preserve original data in outputs.

Allow multiple input file for different scans (by date)

- Local (Irish or Estonian)
	- no TLS at all
	- some TLS
		- valid, (crypto, expiry, good-naming) browser trusted
		- valid but lesser-known-root
		- invalid (can fail in >1 way):
			- crypto
			- expired
			- bad name
			- self-signed
			- other
- Non-local

Conditions in terms of censys structure:

- name is:
	- extract from ???
- local
	- based on 'ip'
	- name in .ie
- some-TLS
- browser-trusted
- invalid-crypto
- expired
- bad name
- self-signed

