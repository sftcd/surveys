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

all: help
	
help: justcleaning

clean: graphclean logclean

fullrun:
	${srcdir}/skey-all.sh ${srcdir} ${datadir} ${cname}

clusters:
	$(srcdir)/SameKeys.py -i ${fname} -o ${colf}

graphs:
	$(srcdir)/ReportReuse.py -f ${colf} -l -o ${gdir}

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

logclean:
	@rm -f *.out
