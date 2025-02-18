# Proxy server
## Description
(!) This project is an interview task and no more (!)

There is a server and a list of proxies. The server forwards client requests to a proxy 
selected using a round-robin algorithm and returns the response back to the user.

Works on Linux only

# Installation
First, install the dependencies:

- For Ubuntu (Debian):
    ```
    sudo apt update
    sudo apt install c++
    sudo apt install libboost-all-dev
    sudo apt install libcurl4-openssl-dev
    sudo apt install cmake
    ```

    or

    ```
    sudo apt update
    sudo apt update c++ libboost-all-dev libcurl4-openssl-dev cmake
    ```

- For Arch (Manjaro etc.):

    ```
    sudo pacman -Syu
    sudo pacman -S g++
    sudo pacman -S cmake
    sudo pacman -S curl
    sudo pacman -S openssl
    sudo pacman -S boost boost-libs
    ```

    or

    ```
    sudo pacman -Syu
    sudo pacman g++ cmake curl openssl boost boost-libs
    ```

Okay, secondly, clone this repository:

```
git clone git@github.com:falafe1y/2capthca.git
```

or via HTTPS:

```
git clone https://github.com/falafe1y/2capthca.git
```

Next, go to the root directory of the project and run the bash script for installation:

```
cd 2captcha
./install.sh
```

If the installation was successful, a directory called "build" should appear in the root 
directory, which you need to go to. There will be two executable files inside - **server** and 
**client**. Run server in one terminal, and client in another (when launching the client, you 
must specify the target site):

```
# First terminal
cd build
./server
```

```
# Second terminal
cd build
./client https://ip.oxylabs.io
```

If you see something like this:
```
Connected...
URL from client: https://ip.oxylabs.io
Proxy protocol: http
------------------
Response from proxy:

REMOTE_ADDR = 54.205.235.55
REMOTE_PORT = 65258
REQUEST_METHOD = GET
REQUEST_URI = /
REQUEST_TIME_FLOAT = 1739662425.7612944
REQUEST_TIME = 1739662425
HTTP_HOST = ip.oxylabs.io
HTTP_ACCEPT = */*
```

or this:
```
Connected...
URL from client: https://ip.oxylabs.io
Proxy protocol: socks5
------------------
Response from proxy:

REMOTE_ADDR = 18.188.12.76
REMOTE_PORT = 51715
REQUEST_METHOD = GET
REQUEST_URI = /
REQUEST_TIME_FLOAT = 1739662428.3189354
REQUEST_TIME = 1739662428
HTTP_HOST = ip.oxylabs.io
HTTP_ACCEPT = */*
```

then everything is done correctly. It's a success!
