
all: justcleaning

justcleaning:
	@echo "This Makefile is just for cleaning."
	@echo "Targets are:"
	@echo "\tgraphclean: clean up after GraphKeyReuse3.py"
	@echo "\tcolclean: clean up after SameKey.py"

clean: graphclean

collclean:
	@rm -f all-key-fingerprints.json
	@rm -f clustersizes.csv
	@rm -f collisions.json
	@rm -f dodgy.json
	@tm -f fingerprints.json

graphclean:
	@rm -f summary.txt
	@rm -f graph*.dot graph*.dot.svg
