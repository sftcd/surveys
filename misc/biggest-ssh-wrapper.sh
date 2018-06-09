#!/bin/bash

        for dir in *-201*-*
        do
        	echo $dir
        	cd $dir
        	biggest22.sh
        	cd ..
        done

