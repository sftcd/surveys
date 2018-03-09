# Our two populations are servers in IE and EE (according to
# maxmind) who listen on port 25.

# Copyright (C) 2018 Stephen Farrell, stephen.farrell@cs.tcd.ie
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

SRCDIR=${HOME}/code/surveys
DATADIR=${HOME}/data/smtp/runs

# 'skey-all.sh' will tee up a full run of all key survey tools.
# It might take a day or two to complete as we don't want to
# keep any network busy, so we'll trickle along slowly.
cname="IE"

# Our initial inputs are from Censys.io, taken in November 2017

# 'GrabIPs.py' will take the baseline inputs and extract out
# the ip addresses in a form usable to... 

# GrabIPs.py extracts IPs from older inputs

# FreshGrap.py uses that then calls zgrab to gather fresh data

# SameKey.py figures out what key sharing clusters exist
# use fname=cesys.io output or output of FreshGrab.py

# GraphKeyReuse3.py generates .dot files and graphs for all
# the clusters found
# inputs for GraphKeyReuse3.py
colf="collisions.json"
gdir="."

all: help
	
help: justcleaning

clean: graphclean

fullrun:
	${SRCDIR}/skey-all.sh ${SRCDIR} ${DATADIR} ${cname}

samekeys:
	# add proper option handling "-i <file>" here
	$(SRCDIR)/SameKeys.py ${fname}

graphs:
	$(SRCDIR)/GraphKeyReuse3.py -f ${colf} -l -o ${gdir}

justcleaning:
	@echo "Targets are:"
	@echo "Orchestration:"
	@echo "\tsetuprun: cname defaults to IE can be set to EE"
	@echo "\grabips: needs \"rname=<runname>\" on command line"
	@echo "\tsamekeys: needs \"fname=<file>\" on command line"
	@echo "\tgraphs: clean up after GraphKeyReuse3.py (has defaults)"
	@echo "We do cleaning as well:"
	@echo "\tgraphclean: clean up after GraphKeyReuse3.py"
	@echo "\tcollclean: clean up after SameKey.py"
	@echo "But also makes graphs..."
	@echo "Read the source if you want more info"

collclean:
	@rm -f all-key-fingerprints.json
	@rm -f clustersizes.csv
	@rm -f collisions.json
	@rm -f dodgy.json
	@rm -f fingerprints.json

graphclean:
	@rm -f summary.txt
	@rm -f graph*.dot graph*.dot.svg
	@rm -f failed*.svg
