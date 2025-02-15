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
    sudo apt install libboost-all-dev
    sudo apt install libcurl4-openssl-dev
    sudo apt install cmake
    ```

- For Arch (Manjaro etc.):

    ```
    sudo pacman -Syu
    sudo pacman -S cmake
    sudo pacman -S curl
    sudo pacman -S openssl
    sudo pacman -S boost boost-libs
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
./server
```

```
# Second terminal
./client https://example.com
```
