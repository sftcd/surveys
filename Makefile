SRCDIR=${HOME}/code/surveys
colf="collisions.json"
gdir="."

all: justcleaning

samekeys:
	$(SRCDIR)/SameKeys.py ${fname}

graphs:
	$(SRCDIR)/GraphKeyReuse3.py -f ${colf} -l -o ${gdir}

justcleaning:
	@echo "This Makefile is mostly for cleaning."
	@echo "Targets are:"
	@echo "\tgraphclean: clean up after GraphKeyReuse3.py"
	@echo "\tcollclean: clean up after SameKey.py"
	@echo "\tsamekeys: needs \"fname=<file>\" on command line"

clean: graphclean

collclean:
	@rm -f all-key-fingerprints.json
	@rm -f clustersizes.csv
	@rm -f collisions.json
	@rm -f dodgy.json
	@rm -f fingerprints.json

graphclean:
	@rm -f summary.txt
	@rm -f graph*.dot graph*.dot.svg
