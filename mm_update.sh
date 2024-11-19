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

function usage()
{
	echo "$0 [-k <licence-key] [-o <output-directory>] [-h <help>]"
	echo "	-k means is the licence key for the mm database"
	echo "	output-directory defaults ./mmdb"
  echo "	help displays this message"
	exit 99
}

function downloadBinaryDB() 
{
  echo "Downloading mm $1 binary database"
  wget -O $output/mmdb.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$1&license_key=$key&suffix=tar.gz"
  tar -xzf $output/mmdb.zip -C $output
  rm $output/mmdb.zip
  sortOutput
  echo "Finished downloading mm $1 binary database"
}

function sortOutput() 
{
  # Remove nested directory, move all files in subdirectories to output directory
  find $output -mindepth 2 -type f -print -exec mv {} $output \;
  # Remove nested directory
  find $output -mindepth 1 -maxdepth 1 -type d -print -exec rm -rf {} \;
}

key=""
output="./mmdb"

while getopts "k:o:h" opt; do
  case $opt in
    k)
      key=$OPTARG
      ;;
    o)
      output=$OPTARG
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
  esac
done


if [ -z "$key" ]; then
  echo "No licence key specified"
  usage
fi

if [ ! -d "$output" ]; then
  mkdir -p $output
fi

if [ ! -d "$output" ]; then
  echo "Could not create output directory $output"
  exit 99
fi

echo "Clearing folder $output"
rm -rf $output/*

echo "Updating mm database"
echo "Licence key: $key"
echo "Output directory: $output"

echo "Downloading mm country database"
wget -O $output/mmdb.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=$key&suffix=zip"
unzip -o $output/mmdb.zip -d $output
rm $output/mmdb.zip
sortOutput
echo "Finished downloading mm country database"

downloadBinaryDB ASN
downloadBinaryDB City
downloadBinaryDB Country

echo "Removing unnecessary files"
rm $output/*.txt

echo "Finished downloading"

filepath=$output/GeoLite2-Country-Locations-en.csv
echo "Creating countrycodes.txt"

tail -n +2 $filepath | while read line; do
  echo $line | awk -F "\"*,\"*" '{print $5}' >> $output/countrycodes.txt
done

echo "Finished creating countrycodes.txt"
