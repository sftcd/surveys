# surveys

This used to be the main README for this repo. This directory just has
bits and pieces assembled along the way in case they turn out useful
sometime. You should mostly ignore it all.

# Stuff to ignore below here...

Code for various survey-related stuff

Note that this very much in flux as I figure out what's interesting. I 
promise to put manners on the code soon as I know what I want it do to:-)
Getting there though...

Initial work is based on using the [censys.io](https://censys.io/) API

## Cron job

```CensysSMTP-cron.py``` is set to pull a weekly view of the SMTP speakers,
in my case from IE and EE (the latter for comparison).

## Analysis

As a first cut, I've analysed the mail speakers into the following classes:

- "good-looking" : Talks SMTPTLS with certs that chain to a browser-trusted root 
- "medium-looking" : Talks STARTTLS ok but without a cert like the above (maybe a local root)
- "self-signed" : Talks STARTTLS ok but with a self-signed cert 
- "bad-sig" : bad signature on certificate somewhere
- "bad-looking" : doesn't manage to talk STARTTLS for some reason
- "dunno" : doesn't fit the above

```Classify.py``` takes a filename (produced by CensysSMTP-cron for examplle) as input and splits that file into
those classes i.e. good, badsig, medium, selfsigned, bad, and dunno, and 
produces basic counts. Those files are dropped into an "outs" 
directory below the ```$CWD``` for now.

Later, we can try do some stats etc.

## A run for Sep 29th for Ireland and Estonia

<pre>
For SMTP speakers apparently in Ireland:

     1852   good
     2713   badsig
     2116   medium
     1010   selfsigned
     4670   bad
      135   dunno

    12496   total

For SMTP speakers apparently in Estonia:

      832   good
     4196   badsig
     3415   medium
     2047   selfsigned
     1921   bad
       59   dunno

    12470   total
</pre>

