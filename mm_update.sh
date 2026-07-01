#!/bin/bash

# Copyright (C) 2018,2026 Stephen Farrell, stephen.farrell@cs.tcd.ie
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

# set -x

function usage()
{
	echo "$0 [-k <licence-key] [-a account-id] [-o <output-directory>] [-n] [-h]"
	echo "	-k key - the licence key for the mm database"
	echo "	-a account - the licence key for the mm database"
	echo "	-n - don't re-do downloads"
	echo "	-o output-directory - defaults ./mmdb"
    echo "	-h displays this message"
	exit 99
}

function flattenOutput()
{
  # Remove nested directory, move all files in subdirectories to output directory
  find "$output" -mindepth 2 -type f -print -exec mv {} "$output" \;
  # Remove nested directory
  find "$output" -mindepth 1 -maxdepth 1 -type d -print -exec rm -rf {} \;
}

function downloadBinaryDB()
{
  if [[ "$download" == "yes" ]]
  then
    echo "Downloading mm $1 binary database"
    curl -J -L -u "$ACCOUNT_ID:$LICENSE_KEY" -o "$output/mmdb-$1-CSV.zip" \
            "https://download.maxmind.com/geoip/databases/GeoLite2-$1-CSV/download?suffix=zip"
    curl -J -L -u "$ACCOUNT_ID:$LICENSE_KEY" -o "$output/mmdb-$1.tgz" \
            "https://download.maxmind.com/geoip/databases/GeoLite2-$1/download?suffix=tar.gz"
    echo "Finished downloading mm $1 binary database"
  fi
  unzip -o "$output/mmdb-$1-CSV.zip" -d "$output"
  tar -C "$output" -xzvf "$output/mmdb-$1.tgz"
}

key=""
output="./mmdb"
download="yes"

while getopts "a:k:no:h" opt; do
  case $opt in
    a)
      ACCOUNT_ID=$OPTARG
      ;;
    k)
      LICENSE_KEY=$OPTARG
      ;;
    o)
      output=$OPTARG
      ;;
    n)
      download="no"
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


if [ -z "$LICENSE_KEY" ]; then
  echo "No licence key specified"
  usage
fi
if [ -z "$ACCOUNT_ID" ]; then
  echo "No account ID specified"
  usage
fi
if [ -z "$output" ]; then
  echo "No output directory specified"
  usage
fi

if [ ! -d "$output" ]; then
  mkdir -p "$output"
fi
if [ ! -d "$output" ]; then
  echo "Could not create output directory $output"
  exit 99
fi

echo "Updating mm database"
echo "Licence key: $key"
echo "Output directory: $output"

if [[ "$download" == "yes" ]]
then
    echo "Downloading mm country database"
    curl -J -L -u "$ACCOUNT_ID:$LICENSE_KEY" -o "$output"/mmdb-Country-CSV.zip \
        "https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip"
    unzip -o "$output"/mmdb-Country-CSV.zip -d "$output"
    echo "Finished downloading mm country database"
fi

downloadBinaryDB ASN
downloadBinaryDB City
downloadBinaryDB Country
echo "Finished downloading"

flattenOutput

filepath="$output"/GeoLite2-Country-Locations-en.csv
echo "Creating countrycodes.txt"

tail -n +2 "$filepath" | while read -r line; do
  echo "$line" | awk -F "\"*,\"*" '{print $5}' >> "$output"/countrycodes.txt
done

echo "Finished creating countrycodes.txt"
