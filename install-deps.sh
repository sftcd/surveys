#!/bin/bash
startdir=`/bin/pwd`

# this script will install the various bits'n'pieces needed to get this
# survey stuff working

# kinda loosely tested on a relatively clean ubuntu 16.04 - YMMV

sudo apt-get update
sudo apt-get -y upgrade

sudo apt-get -y install wget
sudo apt-get -y install git unzip

if [ ! -d $HOME/code ]
then
	mkdir -p $HOME/code
fi 
if [ ! -d $HOME/code/surveys ]
then
	cd $HOME/code
	git clone -b rahul-01 https://github.com/sethr07/surveys.git
else
	# may as well do an update
	cd $HOME/code/surveys
	git pull
fi

for subdir in runs IE EE 
do
	if [ ! -d $HOME/data/smtp/$subdir ]
	then
		mkdir -p $HOME/data/smtp/$subdir
	fi
done

sudo apt-get -y install zmap

./mm_update.sh

sudo -H pip install  testresources
sudo -H pip install  pandas
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

if [ ! -d /usr/lib/go-1.10 ]
then
mkdir -p $HOME/code/go
	cd $HOME/code/go
	GOTARBALL=go1.15.5.linux-amd64.tar.gz
	GOURL=https://golang.org/dl/$GOTARBALL
	wget $GOURL
	tar xzvf $GOTARBALL
	sudo mv go /usr/lib/go-1.15.5
	sudo ln -sf /usr/lib/go-1.15.5/usr/lib/go
	sudo ln -sf /usr/lib/go-1.15.5/bin/go /usr/bin/go

	# add GOPATH to .bashrc
	donealready=`grep GOPATH $HOME/.bashrc`
	if [[ "$donealready" == "" ]]
	then
		echo "export GOPATH=$HOME/go" >>$HOME/.bashrc
	fi
	export GOPATH=$HOME/go
fi




# got get stuff
go get github.com/zmap/zgrab2
cd $GOPATH/src/github.com/zmap/zgrab2
go build
# put it on PATH
sudo ln -sf $HOME/go/src/github.com/zmap/zgrab/zgrab /usr/local/bin

cd $starddir
echo "Done! (I hope:-)"
