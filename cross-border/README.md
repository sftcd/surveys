
# Cross-Border Scripts

The scripts in here relate to cross-border links.

Cross-border is a bit of a misnomer though, as we really mean "cross run,"
it just so happens that our runs are country-based, but that needn't be
the case in general. We do depend on the naming convention used for 
country-runs, where the directory containing the cluster files is called
```XX-YYYYMMDD-HHMMSS``` where XX is a country code and the rest is a
timestamp.

- [cross-border.sh](cross-border.sh) can be used to add a new country to the
  pile - note that this is stateful, the ```already_done``` file records the
  set of runs/countries already included. The main outputs here are the
  following files:

	- ```cross-border.dot``` a graphviz dot file that shows all the cross
	border links between clusters
	- ```cross-border.png``` an image that renders the set of cross-border
	connections that aren't simply a single link between two clusters. (That's
	essentially the set of connected components of the graph above that
	have more than one edge.)
	- ```crooss-border.tex``` - a standalone latex document that has a 
	figure with the above image and a table with the pairwise counts of 
	cross-border links.

- [count-cb.sh](count-cb.sh) takea a country code and cluster number
  as input and counts up the number of IP addresses in the set of 
  cross-border clusters linked to that cluster, if any. That's based
  on the directory naming convention described above.

- [superclusters.sh](superclusters.sh) This one (a work-in-progress)
  generates graphs for each supercluster (set of linked cross-border
  clusters), with either IP addresses as nodes, or anonymised indices.
  These clusters are named based on the first named cluster in each,
  e.g. names are like SCXXNNN where the first cluster mentioned in
  the graphviz file for the supercluster if the NNN'th cluster in 
  the run for country XX. 
