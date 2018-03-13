# surveys

Code for various crypto-survey related stuff. 

## Overview

The current code collects and collates keys and sees which of those
are the same. Needs proper documentation - that'll happen shortly
is the plan:-) 

- ```install-deps.sh``` is a first cut at an installer for dependencies
- ```skey-all.sh``` is a script to orchestrate things
- ```Makefile``` can be used for bits'n'pieces in various ways
- The ```misc``` directory has various bits and pieces knocked up along
the way in case they prove handy later.

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

