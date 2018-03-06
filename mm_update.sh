#!/bin/bash

# grab and explode updated versions of maxmind's free DBs

set -x

# for testing
#skipwget=false
#if [ "$1" == "SkipWget" ]
#then
	#skipwget=true
#fi

# just configure that directory in one place
DESTDIR=`grep mmdbdir $HOME/code/surveys/SurveyFuncs.py  | head -1 | awk -F\' '{print $2}'`
# for testing
#DESTDIR=$PWD/db

TMPD=`mktemp -d /tmp/mmdbXXXX`

pushd $TMPD

for db in City Country ASN
do
	tarball="GeoLite2-$db.tar.gz"
	url="http://geolite.maxmind.com/download/geoip/database/$tarball"
	echo "Getting $url"
	#if (( $skipwget ))
	#then
		wget -q $url
	#else
		#echo "Skipping wget $url as requsted"
	#fi
	if [ "$?" != "0" ]
	then
		echo "Failed to download $url"
	else
		tar xzvf $tarball
		dbdate=`ls -d "GeoLite2-$db"_* | awk -F"_" '{print $2}'`
		dirname="GeoLite2-$db"_"$dbdate"
		fname="GeoLite2-$db"
		cp $dirname/$fname.mmdb $DESTDIR$fname-$dbdate.mmdb
		# update link
		ln -sf $DESTDIR$fname-$dbdate.mmdb $DESTDIR$fname.mmdb
	fi
done

popd
# clean up
rm -rf $TMPD
echo "Done"


