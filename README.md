# VUT IPK Project 1

Our goal in this project was to implement a basic server in C/C++ language which communicates trough the HTTP protocol. This server provides informations such as server cpu name, hostname and current cpu load. Server correctly processes the HTTP headers/requests and creates correct HTTP answers. Answers are in type text/plain. Communication with server can be done from web browser and also with tools like wget and curl.

## Prerequisites

This server runs on Linux Ubuntu 20.04 LTS  (https://ubuntu.com/).

## Written in

* [C language](https://en.wikipedia.org/wiki/C_(programming_language))

## Usage

1. To start the server you have to type make to your CMD to compile the server using the Makefile, which creates the hinfosvc executable. 
2. After the first step you can start the server by typing "./hinfosvc xxxx" to your CMD where xxxx stands for port where the server will be listening on and waiting for requests or you can just type "make run" and server will be started with default port 8080.

```
$ make
$ ./hinfosvc xxxx
$ make run
```
* Server can process three requests:
* (servername stands for the name of the server like "localhost", "xxxx" stands for the port where the server is listening on.)

```
$ curl http://servername:xxxx/hostname
```
1. Returns the network name of the computer, including the domain, for example: merlin.fit.vutbr.cz
```
$ curl http://servername:xxxx/cpu-name
```
2. Returns processor information, such as: Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz
```
$ curl http://servername:xxxx/load
```
3. Returns current load information, such as: 11%
```
$ curl http://servername:xxxx/asdf
```
4. In case of wrong or unknown header/request server returns error 404 for bad request being recieved.

<!-- CONTACT -->
## Contact

Marián Keszi - xkeszi00 - xkeszi00@vutbr.cz

Project Link: [https://github.com/MarianK7/IPK](https://github.com/MarianK7/IPK)

<p align="right">(<a href="#top">back to top</a>)</p>
