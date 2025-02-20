#!/bin/bash

mkdir build
cd build
cmake ..
make 
cd ..
cp http.txt build/ && cp socks5.txt build/

