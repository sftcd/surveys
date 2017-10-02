# surveys

Code for various survey-related stuff

Initial work is based on using the [censys.io](https://censys.io/) API

## Cron job

CensysSMTP-cron.py is set to pull a weekly view of the SMTP speakers,
in my case from IE and EE (the latter for comparison).

## Analysis

Initially, I want to analyse the mail speakers into the following classes:

- good-looking
- medium-looking
- bad-looking
- dunno 
- exceptions (in the try/catch sense)

First cut will be to define these as: 

- "good-looking" : Talks SMTPTLS with certs that chain to a browser-trusted root 
- "medium-looking" : Talks STARTTLS ok but without a cert like the above
- "bad-looking" : doesn't manage to talk STARTTLS for some reason
- "dunno" : doesn't fit the above
- "exceptions" : something else my code didn't catch, figure it out later

Classify.py takes a filename ("f") as input and split that file into
those classes i.e. good, medium, bad, dunno and exceptions, and will
produce some basic counts. Those files are dropped into an "outs" 
directory below the CWD for now.

Later, we can try do some stats etc.


