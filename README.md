# surveys

Code for various crypto-survey related stuff. 

My first article based on this code is [here](https://eprint.iacr.org/2018/299).

## Overview

The current code collects and collates server cryptographic keys (SSH and TLS)
and sees which of those are the same. 

- ```install-deps.sh``` is a first cut at an installer for dependencies

- Then we need to select a list of IPv4 addresses, eiter from a previous
run or from MaxMind

- ```skey-all.sh``` is our script to orchestrate things

- The local ```Makefile``` can be used for bits'n'pieces in various ways

- Most of the main code is the top directory of the repo for now. That
includes:

	IPsFromMM.py
	GrabIPs.py
	FreshGrab.py
	SameKeys.py
	ReportReuse.py
	CheckTLSPorts.py
	Fix443SAN.py
	HostPortKeyCount.py
	KeyTypes.py
	SurveyFuncs.py
	TwentyTwos.py


- The ```misc``` directory has various bits and pieces knocked up along the way
  in case they prove handy later.

## Using it

First you need a set of input IPv4 addresses to scan. Generate those
yourself using zmap. (Details TBD, gotta check some stuff out wrt the
mmdb.)

Then you want to run ```skey-all.sh``` under nohup as it might take a
day or so to do the full scan if you've many IP addresses. (TBD, some
more guidance:-)

Note to self: ensure you do this from a host that can make outbound
port 25 connections - if it can't, you'll miss out on those! (And I
wonder if I can, will so many raise some red flags?)

