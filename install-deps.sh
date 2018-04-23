#!/bin/bash

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

#set -x

startdir=`/bin/pwd`

# this script will install the various bits'n'pieces needed to get this
# survey stuff working
# kinda loosely tested on a relatively clean ubuntu 16.04 - YMMV

# This assumes you're a sudoer and likely works better if you don't have
# to constantly enter the sudo password

# This isn't efficiently idempotent - it'll redo the lot each time

# start out in good state
sudo apt-get update
sudo apt-get -y upgrade

# maybe we got this script some weird way...
sudo apt-get -y install git unzip
if [ ! -d $HOME/code ]
then
	mkdir -p $HOME/code
fi 
if [ ! -d $HOME/code/surveys ]
then
	cd $HOME/code
	git clone https://github.com/sftcd/surveys
else
	# may as well do an update
	cd $HOME/code/surveys
	git pull
fi

# make a place for stuff..
for subdir in runs IE EE 
do
	if [ ! -d $HOME/data/smtp/$subdir ]
	then
		mkdir -p $HOME/data/smtp/$subdir
	fi
done

# zmap is an install
sudo apt-get -y install zmap

# maxmind - enough to just use our update tool
./mm_update.sh

# install pip
sudo apt-get -y install python-pip graphviz

sudo -H pip install --upgrade pip
 
# install python modules needed, these are currently imported modules
# but seems like some are built-in or dragged-in via dependencies, we
# leave the list as-in anyway as it does no harm other than some 
# warnings
sudo -H pip install  testresources
sudo -H pip install  argparse
sudo -H pip install  datetime
sudo -H pip install  python-dateutil
sudo -H pip install  geoip2
sudo -H pip install  graphviz
sudo -H pip install  jsonpickle
sudo -H pip install  pympler
sudo -H pip install  pytz
sudo -H pip install  netaddr
sudo -H pip install  cryptography
sudo -H pip install  wordcloud

# these are imports that I don't think need a pip install
# but not sure:-)
#sudo -H pip install  gc
#sudo -H pip install  copy
#sudo -H pip install  os
#sudo -H pip install  sys
#sudo -H pip install  json
#sudo -H pip install  socket
#sudo -H pip install  subprocess
#sudo -H pip install  time
#sudo -H pip install  tempfile
# golang, zmap and zgrab 
# ubuntu's golang version isn't currently recent enough, need to go for
# a stable version from upstream

# better get wget
sudo apt-get -y install wget

if [ ! -d /usr/lib/go-1.10 ]
then
mkdir -p $HOME/code/golang
	cd $HOME/code/golang
	GOTARBALL=go1.10.linux-amd64.tar.gz
	GOURL=https://dl.google.com/go/$GOTARBALL
	wget $GOURL
	tar xzvf $GOTARBALL
	sudo mv go /usr/lib/go-1.10
	sudo ln -sf /usr/lib/go-1.10 /usr/lib/go
	sudo ln -sf /usr/lib/go-1.10/bin/go /usr/bin/go

	# add GOPATH to .bashrc
	donealready=`grep GOPATH $HOME/.bashrc`
	if [[ "$donealready" == "" ]]
	then
		echo "export GOPATH=$HOME/go" >>$HOME/.bashrc
	fi

	export GOPATH=$HOME/go

fi

# got get stuff
go get github.com/zmap/zgrab
cd $GOPATH/src/github.com/zmap/zgrab
go build
# put it on PATH
sudo ln -sf $HOME/go/src/github.com/zmap/zgrab/zgrab /usr/local/bin

# get ciphersuite stuff
cd $HOME/code/surveys/clustertools
wget https://testssl.sh/mapping-rfc.txt

# clean up
cd $starddir
echo "Done! (I hope:-)"
