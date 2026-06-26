#!/bin/bash

# Copyright (C) 2026 Stephen Farrell, stephen.farrell@cs.tcd.ie
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
#
# use debvm-create/debvm-run to make or run a VM for use with
# https://github.com/sftcd/survey runs
#
# this script will create the VM image if that isn't found and
# will run the VM if the image is there already
#
# before running this copy some SSH public key into a local file called
# `authorized_keys` or else set the SSHPARM variable below
#
# to log in when the VM is running:
# ssh -o NoHostAuthenticationForLocalhost=yes -i <your-priv> -p 2222 user@127.0.0.1
#
# on 1st log in, you probably want to run the `install-deps.sh`
# script from the survey git repo
#
# the main point of this is to isolate all the many dependencies into 
# the VM so they don't pollute your base macnine

# set -x

: ${FSFILE:="survey-vm.ext4"}
: ${RELEASE:="testing"}
: ${SSHPARM:=" -k ./authorized_keys "}
: ${SHARED_DIR:="$HOME/data/smtp/test-runs/"}

create="no"
run="yes"

# if no file system then make one and exit
if [ ! -f $FSFILE ]
then
    create="yes"
    run="no"
fi

if [[ "$1" == "create" ]]
then
    create="yes"
    run="no"
fi

if [[ "$create" == "yes" ]]
then
    debvm-create --size 10G --release=$RELEASE --output $FSFILE $SSHPARM -- \
      --include=net-tools,iputils-ping,knot-dnsutils,bind9-dnsutils,wget \
      --include=login,ca-certificates,git,vim \
      --include=python3,python3-pip,curl \
      --include=command-not-found,passwd,sudo,make \
      --include=linux-image-generic --hook-dir=/usr/share/mmdebstrap/hooks/9pmount \
      --hook-dir=/usr/share/mmdebstrap/hooks/useradd \
      --customize-hook='echo "nameserver 1.1.1.1" > "$1"/etc/resolv.conf'

    echo "Made $FSFILE - run me ($0) again to boot that."
    echo "In some places you may need to set the DNS recursive, via, e.g.:"
    echo "    ~# resolvectl dns enp0s2 1.1.1.1"
fi


if [[ "$run" == "yes" ]]
then
    echo "Login with e.g.:"
    echo "    $ ssh -o NoHostAuthenticationForLocalhost=yes -i ~/.ssh/new-eddsa.priv -p 2222 user@127.0.0.1"
    # start with SSH - you should've added an authorized keys file
    debvm-run -i $FSFILE -s 2222 -g -- -m 2G -display none  \
        -virtfs local,security_model=none,path=$SHARED_DIR,mount_tag=guest_tag
fi

