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

set -euo pipefail

function usage() {
    cat <<EOF
Usage: $0 [-k <license-key>] [-o <output-directory>] [-h]

    -k <license-key>     MaxMind License Key (can also be provided via env MAXMIND_LICENSE_KEY)
    -o <output-directory>  Directory to store mmdb files (default: ./mmdb)
    -h                    Show this help message and exit
EOF
    exit 1
}

output="./mmdb"
key="${MAXMIND_LICENSE_KEY:-}"

while getopts "k:o:h" opt; do
    case "$opt" in
        k) key="$OPTARG" ;;
        o) output="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$key" ]; then
    echo "[ERROR] No MaxMind license key specified."
    usage
fi

mkdir -p "$output"
rm -rf "${output:?}/"*

echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Starting GeoLite2 update"
echo "  License Key: $key"
echo "  Output Dir : $output"

echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Downloading GeoLite2-Country-CSV..."
wget -qO "$output"/country.zip \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=${key}&suffix=zip"
unzip -q -o "$output"/country.zip -d "$output"
rm -f "$output"/country.zip
find "$output" -mindepth 2 -type f -exec mv {} "$output"/ \;
find "$output" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} \;

download_binary_db() {
    local edition="$1"
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Downloading GeoLite2-${edition}-tar.gz..."
    wget -qO "$output"/"${edition,,}".tar.gz \
      "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-${edition}&license_key=${key}&suffix=tar.gz"
    tar -xzf "$output"/"${edition,,}".tar.gz -C "$output"
    rm -f "$output"/"${edition,,}".tar.gz
    find "$output" -mindepth 2 -type f -exec mv {} "$output"/ \;
    find "$output" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} \;
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Finished GeoLite2-${edition}"
}

download_binary_db ASN
download_binary_db City
download_binary_db Country

echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Generating countrycodes.txt..."
csv_file=$(find "$output" -maxdepth 1 -name 'GeoLite2-Country-Locations-*.csv' | head -n1)
if [ -f "$csv_file" ]; then
    tail -n +2 "$csv_file" | awk -F',' '{ gsub(/"/,""); print $5 }' > "$output"/countrycodes.txt
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Generated $output/countrycodes.txt"
else
    echo "[WARN] CSV file not found; skipping countrycodes.txt generation"
fi

echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] GeoLite2 update complete."
