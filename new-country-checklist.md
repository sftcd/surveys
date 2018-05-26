
# Things to do when adding a new country run...

For now, (20180424) I'm not adding new run results to the
[article](https://eprint.iacr.org/2018/299) as it's likely better to spend time
on investigating mitigations for IE clusters. But I'll be running some in the
background (LU is done - similar story wrt results, UY starting as I type) and
we'll see if results warrant updates in the short or medium term. When I do
want to integrate additional runs, then...

## On the scanning host...

1. Do the run

		$ nohup skey-all.sh -mm -c XX -r . >skey.out 2>&1 &
		... come back much later ...

1. Grab/Backup the run files to the analysis host:

		$ scp -r $SCANHOST:$SCANTOP/$run $BUPDIR/$run 

1. Scrub the files from the scanning host.

## On the analyis host...

1. See if we've finally got an SSH v. other cross-protocol case...

		$ check-no-ssh-cross-protocol.sh

1. ```make-tex.sh``` to generate latex table details, which gives us HARK and
	some other numbers

1. ```make images```

	1. Give ```try-render-problematic.sh --neato``` a shot
	1. use ```make -n images``` to see what didn't get done
	1. See what's left over, try fix via e.g. manually via ```neato``` with other args
	1. Delete empty/failed image files
	1. Take a peek...

1. ```make words```

	1. Take a peek...

1. Cross-border checks:

	1. cross-border.sh  -n <newdir>
	1. supercluster.sh

1. Checks/stats:

	1. biggest22.sh - gives some numbers used in article
 
1. Make album

	1. scp svg's to album host, e.g. to ```runs``` directory below DocRoot
	1. ditch any failed or empty svg files
	1. ```make -f ../Makefile``` to make pngs and run album
	1. ```cd ..; album``` to re-run album in parent dir
	1. manually fixup index.html in parent - from index.html.old
	1. backup new index.html to index.html.old

1. For any interesting clusters...

	1. ```ClusterStats.py``` 
	1. ```bt-ports.sh```
	1. etc...

1. If updating article...

	1. Mention new country in abstract
	1. Mention new country in intro
	1. Add any super-nice graphs/clusters worth a mention to results section
	1. Add column to ```collected-res.tex``` table based on output from ```make-tex.sh```
	1. Add subfigure to ```collected-res.tex``` size graphs based on output from ```make-tex.sh```
	1. Add country to list of outputs
	1. Update cross-border details to subsection of results, and note new interesting linkages...
	1. Add detail to most-used SSH keys subsection
	1. Add anything worthwhile to discussion/future
	1. Iterate on page layout and iv-vs-full length as needed

