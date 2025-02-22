#!/bin/bash

if [ -d build ];
then
	echo "Deleting build directory..."
	rm -rf build
	echo "Directory build was deleted"	

	mkdir build
	cd build
	cmake ..
	make 
	cd ..
	cp proxies.txt build/
else
	mkdir build
        cd build
        cmake ..
        make
        cd ..
        cp proxies.txt build/
fi
