# VUT IPK Project2 - Packet sniffer

Our goal in this project was to implement a program wich will sniff packets from the network.
Program had to be implemented in C/C++ or C# language. 
Program accepts specific arguments wich define what kind of packets we want to sniff, on what port we want to sniff, how many packets we want to be sniffed,...

## Written in

* [C++ language](https://en.wikipedia.org/wiki/C%2B%2B)

## Supported packets types

- TCP
- UDP
- ICMPv4
- ICMPv6
- ARP

# Usage

- Recomended to run program with root acess `sudo`

```
$ make - to build program
$ ./ipk-sniffer [OPTIONS]
```

# Options

```
[] - requried
{} - optional

[ -i iterface | --interface interface ] - Defines name of the interface on which we will be sniffing.
{-p ­­port} - Defines port on wich we will be sniffing.
{[--tcp|-t] [--udp|-u] [--arp] [--icmp]} - Defines which types of packets we want to sniff.
{-n num} - Defines number of packets to be sniffed.
{-h | --help} - Prints help message.
```

# Example usage

```
$ ./ipk-sniffer -i eth0 -p 23 --tcp -n 2
$ ./ipk-sniffer -i eth0 --udp
$ ./ipk-sniffer -i eth0 -n 10      
$ ./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp
$ ./ipk-sniffer -i eth0 -p 22
$ ./ipk-sniffer -i eth0
$ ./ipk-sniffer --help
```

# Example sniffer output

```
timestamp: 2021-03-19T18:42:52.362+01:00
src MAC: 00:1c:2e:92:03:80
dst MAC: 00:1b:3f:56:8a:00
frame length: 512 bytes
src IP: 147.229.13.223
dst IP: 10.10.10.56
src port: 4093
dst port: 80

0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
0x0030:  19 20 c7 cd 00 00 99 17  f1 60 7a bc 1f 97 2e b7  . ...... .`z.....
0x0040:  a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39  ....Z._. .q..Tg;9
0x0050:  4e 31 c5 5c 5f b5 37 ed  bd 66 ee ea b1 2b 0c 26  N1.\_.7. .f...+.&
0x0060:  98 9d b8 c8 00 80 0c 57  61 87 b0 cd 08 80 00 a1  .......W a.......
```

# Project files

```
./Makefile
./README.md
./manual.pdf
./ipk-sniffer.cpp
```

<!-- CONTACT -->
## Contact

Marián Keszi - xkeszi00 - xkeszi00@vutbr.cz

Project Link: [https://github.com/MarianK7/IPK](https://github.com/MarianK7/IPK)

<p align="right">(<a href="#top">back to top</a>)</p>
