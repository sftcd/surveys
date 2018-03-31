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

# set -x

# Pick a random cluster

count=`ls cluster*.json | wc -l`
echo "Total clusters: $count"

# ok to be fair this isn't uniformly picked, but it's good enough for
# what we're doing here
#echo "Randomly picked: $(((RANDOM % count)+1))"

# well, this url says this is better, and it's good enough so...
# https://stackoverflow.com/questions/2556190/random-number-from-a-range-in-a-bash-script
randclus=$(python -S -c "import random; print random.randrange(1,$count)")
echo "Randomly picked: $randclus"
