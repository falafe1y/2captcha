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
	cp http.txt build/ && cp socks5.txt build/ && cp script.py build/
else
	mkdir build
        cd build
        cmake ..
        make
        cd ..
        cp http.txt build/ && cp socks5.txt build/ && cp script.py build/
fi
