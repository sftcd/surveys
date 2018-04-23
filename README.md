# surveys

Code for various crypto-survey related stuff. 

My first article based on this code is [here](https://eprint.iacr.org/2018/299).
The graphs for the runs in that article are [here](https://down.dsg.cs.tcd.ie/runs/).


## Overview

The current code collects and collates server cryptographic keys (SSH and TLS)
from hosts in a specified country that listen on port 25 (so are mail servers)
and then sees which of those are re-using keys for SSH or TLS ports. The standard
ports that are checked for server keys are: 22, 25, 110, 143, 443, 587 and 993.

- ```install-deps.sh``` is a first cut at an installer for dependencies
- Then you need to select a list of IPv4 addresses, eiter from a previous
run or from MaxMind for some country code, e.g. "IE".
- ```skey-all.sh``` is the script to orchestrate things
- Most of the main code is the top directory of the repo for now. That
includes the main python scripts as described below.
- The ```clustertools``` directory has additional scripts to analyse clusters.
- The ```misc``` directory has various bits and pieces knocked up along the way
  in case they prove handy later. Those should be ignorable.

## Using it

1. Pick a host from which to scan. Ensure you do this from a host that can make
   outbound port 25 connections - if it can't, you'll miss out on those! 
   It's polite to make a web page and DNS TXT record that can be found from
   your scanning host's IP address, in case someone wants to yell at you for
   scanning.

1. Pick a top level directory where you're going to run things, let's call that
   ```$TOP```. Usually I use ```$HOME/data/smtp/runs/``` but it should work
elsewhere. The main script will create per-run directories below that, in which
the various scan and log files will be created.

1. I assume that this repo's main directory has been added to your ```$PATH``` but
refer to it as ```$REPO``` as necessary below.

1. Install dependencies:

		$ install-deps.sh 
		... lots of output ...

1. Update the MaxMind database if it's been a while since you ran the install.
   The latest databases for that are kept in the ```$REPO/mmdb/``` directory.

		$ mm_update.sh
		... lots of output ...

1. Pick a country and start the scan. You need the two-letter code for that,
   e.g., "IE"  and to tell the ```skey-all.sh``` script, and to use MaxMind
(```-mm```) to generate a list of prefixes. You also need to tell the script
where to put the output (```-r .``` in this case). Once this is working ok, then
you'll want to run it via nohup, as it takes a long time.
And since ZMap requires root permissions you should have setup things so 
that the ```sudo zmap...``` call in this script works.  

		$ cd $TOP
		$ nohup skey-all.sh -c IE -mm -r . >skey.out 2>&1 &
		$ 

	You'll see a directory created below ```$TOP``` to contain
	the run files, that'll be names something like ```IE-20180423-161002```

1. Go out for the evening... It *might* all just work:-)

## Scanning Stages in more detail...

1. The first stage of the scan uses the ```IPsFromMM.py``` script that
	extracts prefixes for the country of interest from the MaxMind DB.

1. Once that's done the next stage uses the installed ```zmap``` command to get
   the IPs from those prefixes that are listening on port 25.  If you're
	impatient, you can watch progress in a log file that's in the run directory.
	With the same example you'd be doing this:

		$ tail -f IE-20180423-161002/20180423-161002.out
		 4:33 3% (2h44m left); send: 38600 148 p/s (140 p/s avg); recv: 169 2 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:34 3% (2h44m left); send: 38748 147 p/s (140 p/s avg); recv: 169 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:35 3% (2h44m left); send: 38888 139 p/s (140 p/s avg); recv: 170 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:36 3% (2h44m left); send: 39036 147 p/s (141 p/s avg); recv: 172 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:37 3% (2h44m left); send: 39192 145 p/s (141 p/s avg); recv: 172 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:38 3% (2h44m left); send: 39338 145 p/s (141 p/s avg); recv: 174 1 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.44%
		 4:39 3% (2h44m left); send: 39481 142 p/s (141 p/s avg); recv: 175 0 p/s (0 p/s avg);......

	The "2h44m left" timing that ZMap produces is pretty accurate. The "recv: 175" on the last 
	line means that ZMap has found 175 port 25 listeners. For the rest, see the ZMap man page.

	The ZMap stage of the scan will cause the creation of files like these:

		-rw-rw-r-- 1 user user  1156 Apr 23 16:02 mm-ips.IE.v6
		-rw-rw-r-- 1 user user  8152 Apr 23 16:02 mm-ips.IE.v4
		-rw-rw-r-- 1 user user  3537 Apr 23 16:02 Makefile
		-rw-rw-r-- 1 user user  5140 Apr 23 16:12 zmap.ips
		-rw-rw-r-- 1 user user 84107 Apr 23 16:12 20180423-161002.out

	The first two are IPv4 and IPv6 prefixes MaxMind figures are for the
	country you want to scan. (The IPv6 prefixes aren't used as of now, sorry.) The
	```Makefile``` allows you to do scan stages one by one, more on that below.
	```zmap.ips``` contains the accumulated IPv4 addresses that'll be used in
	later scan stages. The log file is as before. The last two will grow as
 	the scan proceeds.

1. Eventually the scan will move on to the ZGrab stage. This uses
	the ```FreshGrab.py``` script.
	If you're very impatient and want to see if stuff works then you
	can stop the scan and then move on to the next stage based on 
	whatever IP addresses have already been gathered so far. 
	Once you've gathered a couple of hundred IPv4 addresses you 
	should find some clusters in the data. (Well, that was a guess
	but worked ok for one country with 200 IPs:-)

	To stop the scan you'll do something like:

		$ kill %1
		[1]+  Terminated              nohup skey-all.sh -c IE -mm -r . > skey.out 2>&1  (wd: ~/data/foo)

	You'll want to check that ZMap is really stopped, as it runs as
	root and mightn't be terminated by the above. If it's not stopped
	then something like this should kill it:

		$ sudo killall zmap

1. If you want to proceed, then you can link or copy the ```zmap.ips``` file
	to a file called ```input.ips``` which is used for the next stage. (The
	```skey-all.sh``` script has a bunch of such file names it uses as
	telltales to decide what stages to skip or do next - see the ```$TELLTALE_xx```
	env. vars. in the script to figure it out.) To move on with just the
	current set of IPv4 addresses in ```zmap.ips`` do the following:

		$ cd IE-20180423-161002
		$ ln -s zmap.ips input.ips
		$ nohup skey-all.sh -c IE -p . >skey.out 2>&1 &

	Note we used ```-p .``` in the above as we're now in the IE-20180423-161002 directory,
	and we don't need to say to use MaxMind as that's "done."

	That'll start using ZGrab to accumulate banner information for the
	set of IPs in ```input.ips``` - when that's done there should be 
	one line per IP in the ```records.fresh``` file (which has a *large*
	JSON blob per-line.) Tailing the output log at this stage will
	produce lines like:

		...
		Freshly grabbing... did: 5 most recent ip XXX.XXX.XXX.XXX average time/ip: 8.27766857147
		Freshly grabbing... did: 10 most recent ip XX.XXX.XXX.XXX average time/ip: 7.2583016634
		...

	As you can see this is *much* slower than ZMap - partly because it has to
	be, partly because we put in a default 100ms wait between scans to be nice.
	This one is likely to take a day or so to run.

	The ```records.fresh``` file is modelled on, and quite close to, the censys.io 
	JSON format - for each port scanned it includes a JSON structure that is the
	output from ZGrab, e.g. for port 22, there is a 'p22' element.

	In case you're curious, yes you could just plonk a set of IP addresses in
	```input.ips``` and proceed to scan those from there. You'll still need
	to provide a country though, as the next stage will throw away addresses	
	that appear to be in the wrong country, according to MaxMind. (I'm not
	sure if this happens because of lack of mmdb freshness, routing or
	hosting changes or what but it does happen.)

1. The next stage is to analyse the contents of ```records.fresh``` and 
	generate the clusters. That uses the ```SameKeys.py``` script and may
	take an hour or so depending on the size of the scan. That stage
	also does some DNS lookups of names found in banners. (Yeah, it'd 
	have been better to do those in the previous stage, but that's not
	how my current code works sorry;-) 

	While doing this the log file will contain things like:

		Reading fingerprints and rdns, did: 5 most recent ip XXX.XXX.XXX.XXX average time/ip: 0.689786990484 last time: 0.953353881836
		Reading fingerprints and rdns, did: 10 most recent ip XX.XXX.XXX.XXX average time/ip: 0.565797372298 last time: 0.796704053879
		Reading fingerprints and rdns, did: 15 most recent ip XXX.XXX.X.XXX average time/ip: 0.52644918859 last time: 1.09521102905
		Reading fingerprints and rdns, did: 20 most recent ip XX.XXX.XXX.XXX average time/ip: 0.542455241794 last time: 0.283885955811
		Reading fingerprints and rdns, did: 25 most recent ip XXX.XX.XXX.XXX average time/ip: 0.493393659592 last time: 0.230369091034
		...

	Eventually, it'll end with something like:

		Checking colisions, did: 100 found: 7970 remote collisions
		Checking colisions, did: 200 found: ... 
		...
		Saving collisions, did NNNn:  found: MMM IP's with remote collisions
			overall: MMM
			good: MMM
			bad: MMM
			remote collisions: MMM
			no collisions: MMM
			most collisions: MMM for record: MMM
			non-merged total clusters: MMM
			merged total clusters: MMM
			Scandate used is: 2018-04-23 16:09:31.183936+00:00
		Done clustering records

	The main output from that stage is the ```collisions.json``` file which is usually
	quite big and contains all the fingerprint objects for hosts that are in clusters.
	(Some additional JSON files are generated as well that aren't particularly useful at
	this point - those are ```fingerprints.json``` and ```all-key-fingerprints.json```
	and may be removed in future - they were useful intermediate results at an early
	stage of coding.) 

	The fingerprint structure is a class defined in the general library file
	```SurveyFuncs.py``` - basically it contains the basic identifying information
	for a host (IP and AS), hashes of keys seen for a host, naming information
	gathered from banners, certificates and reverse DNS;  port meta-data, and (when
	complete) lists the other  hosts that are linked to this record and details of
	how they are linked.

	Records from records.fresh that are discarded for whatever reason
	are written to ```dodgy.json``` - reasons may include that there are no cryptographic
	protocols seen at all on the host, or the specific IP address is judged to be out-of-country.
	The content here is an array or the JSON structures with all the details from ```records.fresh```.

	This stage can also be done using the ```make clusters cname="FI"``` target. Be
	sure to provide the correct country name as shown.

1. The last stage of the scan is to generate graphviz graphs and individual cluster
	file (e.g. ```cluster1.json```) for the clusters which
	is usually fairly quick. That uses the ```ReportReuse.py``` script and the
	log will contain things like:

		Graphing records
		....
		collisions: MMM
			total clusters: MMM
			graphs not rendered: []
		Dorender= False
		Done graphing records

	This stage can also be done using the ```make graphs``` target.

	The ```clusterNNN.json``` files contain all the fingerprint structures for that
	cluster. The related ```graphNNN.dot``` flle contains the graphviz representation
	of the cluster, by default with the IP address replaced by the index of the 
	host in the overall run.

1. To generate the graph svg files (which isn't done by default) then:

		$ make images
		timeout --preserve-status 120s 'sfdp' -Tsvg "-Gepsilon=1.5" graph5.dot >graph5.dot.svg
		timeout --preserve-status 120s 'sfdp' -Tsvg "-Gepsilon=1.5" graph1.dot >graph1.dot.svg
		...
	
	If you get an error like this:

		Error: remove_overlap: Graphviz not built with triangulation library

	Then you'll need a newer version of graphviz, sorry. 

## clustertools scripts

Documenting these is still a work-in-progres. As are a bunch of these
scripts - these tend to be written in response to specific questions
asked of the data. I'd expect this might mature more over time.

In the meantime, check the code, but here are some hints:

- anyoldips.sh: check if any of a supplied list of ips are in some cluster
- biggest22.sh: Find the clusters with the most re-used SSH key and the cluster that the biggest  "pure" SSH cluster
- bt-ports.sh:  see what's browser trusted for TLS ports for all ciusters in CWD
- check-no-ssh-cross-protocol.sh: We'd like to know that there are (still) no cases where an SSH host-key is also used for TLS. 
- ciphersuites.sh: extract ciphersuite values from cluster files
- clips.sh: list the IPs from a cluster 
- clnames.sh: extract some name related values from a cluster file
- ClusterAnonOthers.py: This is to handle cases where we send a tarball to an AS asset-holder that
	involves >1 ASN - we zap the names and IP addresses for other ASNs that
	are mentioned. We do leave the fingerprints, and ASNs.
- ClusterBadCiphersuites.py
- clusterfake.json
- ClusterGetCerts.py
- ClusterPortBT.py
- ClusterStats.py
- dot-r1r2.sh
- fpoverlaps.sh
- fpsfromcluster.sh
- fvs.sh
- gc.sh
- ipoverlaps.sh
- ipsdiff.sh
- make-tex.sh
- rndclust.sh
- size2rep.sh
- wordle.sh

## Misc points

- When running ```make``` the default country is "IE" so to provide a country
  name, e.g. to re-do ```collisions.json``` then do the following:

		$ make clusters cname="FI"

	The same thing works for other env. vars. used in the Makefile, read the
	file to see what you can play with that way.

- There is a bunch of specific scripting to handle the 2017 scans that were
  exported from censys.io. That can be ignored but is needed for now in case we
need to re-do some analysis. That did happen at one stage where we need to fix
a problem with port 587 - see the ```Fix442ASN.py``` script for details.

- The ```ah-tb.sh``` script is used to extract a set of clusters that match
  some regexp associated with an asset-holder. That can be an address prexix or
ASN.

- The ```check-keys.sh``` script is used to re-check/validate clusters by using
  different code to ensure that our main scanning code isn't generating bogus
clusters. That makes use of ```TwentyTwos.py``` and ```CheckTLSPorts.py``` both
of which are implemented differently from ZGrab and our other clustering code.
Typically running this shows some changes in larger clusters due to hosts not
being contactable, but it also shows some real key changes especially if run
some time after the initial run.

- The ```try-render-problematic.sh``` script attempts to handle cases where
graphviz rendering fails - which happens with more complex graphs in a not
quite predictable manner. This basically tries a bunch of graphviz options
and different output formats which can sometimes result in successful 
rendering of graphs that fail to be rendered in the normal course of
events.

- The ```Makefile``` here is not intended for use with ```make``` in the
  ```$REPO``` directory but rather for use in a run directory. (We should
probably rename it sometime.) The ```clusters```, ```graphs``` and
```images``` targets have been described above and are useful. There
are also some ```clean``` targets - check those out with ```make -n````
before using them and be caureful to have backups if you need to not
lose data that takes a while to re-generate. 

## TODOs:

As of 20180423 I still need to...

- add HOWTO for graphviz version that doesn't say: "Error: remove\_overlap: Graphviz not built with triangulation library"
- provide some sample data



