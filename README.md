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
    sudo apt-get update
    sudo apt-get upgrade
    sudo apt-get install python3
    sudo apt-get install g++
    sudo apt-get install libboost-all-dev
    sudo apt-get install libcurl4-openssl-dev
    sudo apt-get install cmake
    ```

    or

    ```
    sudo apt update
    sudo apt-get install pytnon3 g++ libboost-all-dev libcurl4-openssl-dev cmake
    ```

- For Arch (Manjaro etc.):

    ```
    sudo pacman -Syu
    sudo pacman -S python3
    sudo pacman -S g++
    sudo pacman -S cmake
    sudo pacman -S curl
    sudo pacman -S openssl
    sudo pacman -S boost boost-libs
    ```

    or

    ```
    sudo pacman -Syu
    sudo pacman -S python3 g++ cmake curl openssl boost boost-libs
    ```

Okay, secondly, clone this repository:

```
git clone git@github.com:falafe1y/2capthca.git
```

or via HTTPS:

```
git clone https://github.com/falafe1y/2capthca.git
```
In the _client.cpp_ file, change the IP address of the server on which the _server.cpp_ binary file is running.

![image](https://github.com/user-attachments/assets/78433d2a-98df-48c4-bb8b-cb26c57e3543)

Next, go to the root directory of the project and run the bash script for installation:

```
cd 2captcha
./install.sh
```

If the installation was successful, a directory called "build" should appear in the root 
directory, which you need to go to. There will be two executable files inside - **server** and 
**client**. Run server in one terminal, and client in another (when launching the client, you 
must specify auth data and target site):

```
# First terminal
cd build
./server
```

```
# Second terminal
cd build
./client login password https://ip.oxylabs.io
```

If you see something like this in "client" terminal:
```
Response from the server:

213.55.242.106
```

then everything is done correctly. It's a success!
