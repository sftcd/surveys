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

# 'skey-all.sh' will tee up a full run of all key survey tools.
# It might take a day or two to complete as we don't want to
# keep any network busy, so we'll trickle along slowly.
#

# defaults - can be overridden on command line with make
fname="records.fresh"
srcdir=${HOME}/code/surveys
datadir=${HOME}/data/smtp/runs
cname="IE"
colf="collisions.json"
gdir="."

# note this may be a system or $HOME/bin thing, depending if you've
# built graphviz locally, which seems better in some ways, even if
# it's still flakey
#dotcmd='neato'
# sftp is neater but slower, don't think the epsilon thing 
# below helps there either but it doesn't hurt (so far)
dotcmd='sfdp'
# this helps neato, but will be ignored or barf for others
dotparms="-Gepsilon=1.5"

# how to make a .svg from a .dot
# if you don't want a timeout, then try this, but graphviz is buggy
# and a memory hog sometimes so I'd leave in the timeout call
%.dot.svg: %.dot
	- timeout --preserve-status 120s ${dotcmd} -Tsvg ${dotparms} $(<) >$(@)

DOTS=$(wildcard *.dot)

SVGS=$(patsubst %.dot,%.dot.svg, $(DOTS))

images: $(SVGS)
	find . -name '*.dot.svg' -size 0 -exec rm {} \;

CLUSTERS=$(wildcard cluster*.json)

WORDS=$(patsubst %.json,%.words,$(CLUSTERS))

%.words: %.json
	- ${srcdir}/clustertools/wordle.sh $(<) 

words: $(WORDS) 


all: help
	
help: justcleaning

clean: graphclean collclean logclean wordclean

fullrun:
	${srcdir}/skey-all.sh ${srcdir} ${datadir} ${cname}

clusters:
	$(srcdir)/SameKeys.py -c ${cname} -i ${fname} -o ${colf}

graphs:
	$(srcdir)/ReportReuse.py -f ${colf} -o ${gdir} -a -r

justcleaning:
	@echo "Targets are:"
	@echo "Orchestration:"
	@echo "\tfullrun: "
	@echo "\tclusters:figure out collisions"
	@echo "\tgraphs: clean up after ReportReuse.py (has defaults)"
	@echo "We do cleaning as well:"
	@echo "\tgraphclean: clean up after ReportReuse.py"
	@echo "\tcollclean: clean up after SameKey.py"
	@echo "\tlogclean: clean up log files"
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
	@rm -f graph.done
	@rm -f cluster*.json

wordclean:
	@rm -f *-wordle.png
	@rm -f cluster*.words

logclean:
	@rm -f *.out
