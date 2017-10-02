# surveys

Code for various survey-related stuff

Initial work is based on using the [censys.io](https://censys.io/) API

## Cron job

```CensysSMTP-cron.py``` is set to pull a weekly view of the SMTP speakers,
in my case from IE and EE (the latter for comparison).

## Analysis

Initially, I want to analyse the mail speakers into the following classes:

- good-looking
- medium-looking
- self-signed
- bad-looking
- dunno 
- exceptions (in the try/catch sense)

First cut will be to define these as: 

- "good-looking" : Talks SMTPTLS with certs that chain to a browser-trusted root 
- "medium-looking" : Talks STARTTLS ok but without a cert like the above (maybe a local root)
- "self-signed" : Talks STARTTLS ok but with a self-signed cert 
- "bad-looking" : doesn't manage to talk STARTTLS for some reason
- "dunno" : doesn't fit the above
- "exceptions" : something else my code didn't catch, figure it out later (zero of those for now)

```Classify.py``` takes a filename ("f") as input and splits that file into
those classes i.e. good, medium, selfsigned, bad, dunno and exceptions, and 
produces basic counts. Those files are dropped into an "outs" 
directory below the ```$CWD``` for now.

Later, we can try do some stats etc.

## A run for Sep 29th for Ireland and Estonia

<pre>
For SMTP speakers apparently in Ireland:

     1852   good
     4178   medium
     1219   selfsigned
     4670   bad
      577   dunno

    12496   total

For SMTP speakers apparently in Ireland:

      832   good
     7420   medium
     2085   selfsigned
     1921   bad
      212   dunno

    12470   total
</pre>

