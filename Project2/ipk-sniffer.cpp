#include <stdio.h>
#include <string.h>
#include <iostream>
#include <pcap.h>
#include <chrono>
#include <iomanip>
#include <signal.h>
#include <netinet/ip.h>      
#include <net/ethernet.h>    
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>

using namespace std::chrono;

bool interfaceSet = false; // bool var to controll if interface arg was not set but other args were passed
bool interfacePresent = false; // bool var to controll if interface passed in args is available
bool udp = false; // bool var for check if udp packets have to be sniffed
bool tcp = false; // bool var for check if tcp packets have to be sniffed
bool icmp = false; // bool var for check if icmp packets have to be sniffed
bool arp = false; // bool var for check if arp packets have to be sniffed
std::string protFilter = ""; // string var for protocol filter
std::string interfaceArg = ""; // string var for interface arg
pcap_t *device; // pcap_t var for device
int port = -1; // int var for port
int packetCount = 1; // default value for packet count is set to 1


// Code inspired by https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c
struct mac_filter
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

// Function for printing help
void printHelp()
{
    std::cout << "Usage: ipk-sniffer [OPTION]...\n"
              << "\n"
              << "Options: \n"
              << "  -i, --interface [INTERFACE]\n"
              << "      Interface to sniff on\n"
              << "  -p [PORT NUMBER]\n"
              << "      Port to sniff on\n"
              << "  -n [PACKETS COUNT]\n"
              << "      Number of packets to sniff\n"
              << "  -u, --udp\n"
              << "      Sniff UDP packets\n"
              << "  -t, --tcp\n"
              << "      Sniff TCP packets\n"
              << "  --icmp\n"
              << "      Sniff ICMP packets\n"
              << "  --arp\n"
              << "      Sniff ARP packets\n"
              << "  -h, --help\n"
              << "      Print this help\n"
              << std::endl;
              exit(0);
}

// Function inspired by https://stackoverflow.com/questions/3727421/expand-an-ipv6-address-so-i-can-print-it-to-stdout
void printIpv6(const struct in6_addr *addr)
{
    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           (int)addr->s6_addr[0], (int)addr->s6_addr[1],
           (int)addr->s6_addr[2], (int)addr->s6_addr[3],
           (int)addr->s6_addr[4], (int)addr->s6_addr[5],
           (int)addr->s6_addr[6], (int)addr->s6_addr[7],
           (int)addr->s6_addr[8], (int)addr->s6_addr[9],
           (int)addr->s6_addr[10], (int)addr->s6_addr[11],
           (int)addr->s6_addr[12], (int)addr->s6_addr[13],
           (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}

// Function inspired by https://www.programcreek.com/cpp/?CodeExample=hex+dump
void printPacketContent(const void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
                printf("  %s\n", buff);

            printf("0x%04x ", i);
        }

        printf(" %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0)
    {
        printf("   ");
        i++;
    }
    printf("  %s", buff);
    printf("\n");
}

// Function for handling CTRL + C signal sent by user
void signalHandler(int signum)
{
    std::cout << "\nSignal " << signum << " received. Exiting..." << std::endl;
    pcap_close(device);
    exit(signum);
}

// Function for creating filter format for pcap_compile
void creaateFilter()
{
    if (port != -1)
    {
        if (udp)
        {
            // printf("udp and port %d\n", port);
            protFilter += "(udp port " + std::to_string(port) + ") or ";
        }
        if (tcp)
        {
            // printf("tcp and port %d\n", port);
            protFilter += "(tcp port " + std::to_string(port) + ") or ";
        }
        if (icmp)
        {
            protFilter += "(icmp) or (icmp6) or ";
        }
        if (arp)
        {
            protFilter += "(arp) or ";
        }
    }
    else
    {
        if (udp)
        {
            protFilter += "(udp) or ";
        }
        if (tcp)
        {
            protFilter += "(tcp) or ";
        }
        if (icmp)
        {
            protFilter += "(icmp) or (icmp6) or ";
        }
        if (arp)
        {
            protFilter += "(arp) or ";
        }
    }

    protFilter = protFilter.substr(0, protFilter.size() - 3);
}

// function inspired by https://www.programcreek.com/cpp/?CodeExample=get+timestamp
void GetStrTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    auto now_milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%S");

    // add milliseconds to timestamp string
    ss << '.' << std::setfill('0') << std::setw(3) << now_milliseconds.count() << 'Z';

    printf("timestamp: %s", ss.str().c_str());
}

// Callback function for pcap_loop, which handles recieved packets. Function check whether the packet is sent from IPV4 or IPV6 than checks for the protocol and prints the information about the packet to the console.
void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    GetStrTimestamp(); // prints timestamp
    printf("\n");

    auto size = header->len;
    struct mac_filter *p = (struct mac_filter *)packet;
    const struct iphdr *ipHeader = (struct iphdr *)(packet + sizeof(struct ethhdr));
    u_short ipLen = (ipHeader->ihl) * 4;
    const struct ether_header *etherHeader = (struct ether_header *)packet;
    const struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipLen);
    const struct ip6_hdr *ip6Header = (struct ip6_hdr *)(packet + sizeof(struct ethhdr));
    const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + ipLen);
    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));


    if (etherHeader->ether_type == htons(ETHERTYPE_IP))
    {
        switch (ipHeader->protocol)
        {
        case 1: // ICMPv4 IPV4
            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

            printf("frame length: %d bytes\n", size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));

            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");
            break;
        case 6: // TCP IPV4
            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

            printf("frame length: %d bytes\n", size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("src port: %d\n", ntohs(tcpHeader->th_sport));
            printf("dst port: %d\n", ntohs(tcpHeader->th_dport));

            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");
            break;
        case 17: // UDP IPV4
            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

            printf("frame length: %d bytes\n", size);
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            printf("src port: %d\n", ntohs(udpHeader->uh_sport));
            printf("dst port: %d\n", ntohs(udpHeader->uh_dport));

            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");
            break;
        default:
            break;
        }
    }
    else if (etherHeader->ether_type == htons(ETHERTYPE_IPV6))
    {
        switch (ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt)
        {
        case 6: // TCP IPV6
            tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + ipLen);

            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

            printf("frame length: %d bytes\n", size);
            printIpv6(&ip6Header->ip6_src);
            printIpv6(&ip6Header->ip6_dst);
            printf("src port: %d\n", ntohs(tcpHeader->th_sport));
            printf("dst port: %d\n", ntohs(tcpHeader->th_dport));

            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");
            break;
        case 17: // UDP IPV6
            udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + ipLen);

            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

            printf("frame length: %d bytes\n", size);
            printIpv6(&ip6Header->ip6_src);
            printIpv6(&ip6Header->ip6_dst);
            printf("src port: %d\n", ntohs(udpHeader->uh_sport));
            printf("dst port: %d\n", ntohs(udpHeader->uh_dport));
            
            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");
            break;
        case 58: // ICMPv6 IPV6
            printf(
                "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
                p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
            printf(
                "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
                p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);
            printIpv6(&ip6Header->ip6_src);
            printIpv6(&ip6Header->ip6_dst);
            printf("frame length: %d bytes\n", header->len);

            printf("\n");
            printPacketContent(packet, header->len);
            printf("\n");

            break;
        default:
            break;
        }
    }
    else if (etherHeader->ether_type == htons(ETHERTYPE_ARP))
    {
        struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header) + ipLen);
        char srcIP[16], destIP[16];
        inet_ntop(AF_INET, &(arp->arp_spa), srcIP, sizeof(srcIP));
        inet_ntop(AF_INET, &(arp->arp_tpa), destIP, sizeof(destIP));
        
        printf(
            "src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
            p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]);
        printf(
            "dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
            p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]);

        printf("src IP: %s\n", srcIP);
        printf("dst IP: %s\n", destIP);
        printf("frame length: %d bytes\n", size);
        printf("\n");
        printPacketContent(packet, header->len);
        printf("\n");
    }
}

// Function prints all interfaces that are available at the moment and their description
void printInterfaces(pcap_if_t *allInterfaces)
{
    while (allInterfaces->next != NULL)
    {
        printf("Name: %s   Description: %s \n", allInterfaces->name, allInterfaces->description);
        allInterfaces = allInterfaces->next;
    }
    pcap_freealldevs(allInterfaces);
    exit(0);
}

// Function which gets all the available interfaces
pcap_if_t *getInterfaces()
{
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *allInterfaces;
    if (pcap_findalldevs(&allInterfaces, errbuff) == -1)
    {
        fprintf(stderr, "ERROR: No interfaces available. INFO: %s\n", errbuff);
        exit(1);
    }
    return allInterfaces;
}

// Function which checks if the interdface passed in argument is in the available interfaces, if not prints error and exits.
void interfaceActive(std::string passedInterface, pcap_if_t *allInterfaces)
{
    while (allInterfaces->next != NULL)
    {
        if (strcmp(passedInterface.c_str(), allInterfaces->name) == 0)
        {
            interfacePresent = true;
        }
        allInterfaces = allInterfaces->next;
    }
    if (interfacePresent == false)
    {
        pcap_freealldevs(allInterfaces);
        fprintf(stderr, "ERROR: Interface %s not found in active interfaces.\n", passedInterface.c_str());
        exit(1);
    }
}

// Function for parsing the arguments passed in command line
void parseArgs(int argc, char *argv[])
{
    std::string arg;
    pcap_if_t *allInterfaces = getInterfaces();

    if (argc < 2) // No argument was set, print all available interfaces and exit
    {
        printInterfaces(allInterfaces);
    }

    for (int i = 1; i < argc; i++)
    {
        arg = std::string(argv[i]);
        if (arg == "-h" || arg == "--help")
        {
            printHelp();
        }
        else if (arg == "-i" || arg == "--interface")
        {
            interfaceSet = true;
            try
            {
                interfaceArg = std::string(argv[i + 1]);
            }
            catch (std::exception const &)
            {
                printInterfaces(allInterfaces);
            }
            interfaceActive(interfaceArg, allInterfaces);
        }
    }
    if (interfaceSet == false) // interface arg was not set but other args were passed
    {
        printInterfaces(allInterfaces);
    }

    for (int i = 1; i < argc; i++)
    {
        arg = std::string(argv[i]);
        if (arg == "-i" || arg == "--interface")
        {
            i++;
        }
        else if (arg == "-t" || arg == "--tcp")
        {
            tcp = true;
        }
        else if (arg == "-u" || arg == "--udp")
        {
            udp = true;
        }
        else if (arg == "--icmp")
        {
            icmp = true;
        }
        else if (arg == "--arp")
        {
            arp = true;
        }
        else if (arg == "-n")
        {
            try
            {
                packetCount = std::stoi(std::string(argv[i + 1]));
                if (packetCount < 0)
                {
                    fprintf(stderr, "ERROR: Invalid packet count: %d.\n", packetCount);
                    exit(1);
                }
                i++;
            }
            catch (std::exception const &)
            {
                fprintf(stderr, "ERROR: Invalid packet count: %d.\n", packetCount);
                exit(1);
            }
        }
        else if (arg == "-p")
        {
            try
            {
                port = std::stoi(std::string(argv[i + 1]));
                if (port < 0 || port > 65535)
                {
                    fprintf(stderr, "ERROR: Invalid port number: %d.\n", port);
                    exit(1);
                }
                i++;
            }
            catch (std::exception const &)
            {
                fprintf(stderr, "ERROR: Invalid port number: %d.\n", port);
                exit(1);
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Invalid argument passed %s.\n", arg.c_str());
            exit(1);
        }
    }

    if (!tcp && !udp && !icmp && !arp) // No protocol was set, set all to true so all packets will be sniffed
    {
        tcp = true;
        udp = true;
        icmp = true;
        arp = true;
    }
}

int main(int argc, char **argv)
{
    char errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask; // The netmask of our sniffing device
    bpf_u_int32 net;  // The IP of our sniffing device

    signal(SIGINT, signalHandler);

    parseArgs(argc, argv);
    creaateFilter();

    /* Code inspired by https://www.tcpdump.org/pcap.html
    
    This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:

    1. Redistribution must retain the above copyright notice and this list of conditions.
    2. The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.

    Insert 'wh00t' for the BSD license here wh00t
    
    */

    if (pcap_lookupnet(interfaceArg.c_str(), &net, &mask, errbuff) == PCAP_ERROR)
    {
        fprintf(stderr, "ERROR: Couldn't get netmask for device %s: %s\n", interfaceArg.c_str(), errbuff);
        exit(1);
    }
    if ((device = pcap_open_live(interfaceArg.c_str(), BUFSIZ, 1, 1000, errbuff)) == NULL)
    {
        pcap_close(device);
        fprintf(stderr, "ERROR: Couldn't open device %s: %s\n", interfaceArg.c_str(), errbuff);
        exit(1);
    }
    if (pcap_datalink(device) != DLT_EN10MB)
    {
        fprintf(stderr, "ERROR: Device %s is not an Ethernet device.\n", interfaceArg.c_str());
        exit(1);
    }
    if (protFilter != "")
    {
        bpf_program filter;
        if (pcap_compile(device, &filter, protFilter.c_str(), 0, net) == PCAP_ERROR)
        {
            pcap_close(device);
            fprintf(stderr, "ERROR: Couldn't parse filter %s: %s\n", protFilter.c_str(), pcap_geterr(device));
            exit(1);
        }
        if (pcap_setfilter(device, &filter) == PCAP_ERROR)
        {
            pcap_close(device);
            fprintf(stderr, "ERROR: Couldn't set filter %s: %s\n", protFilter.c_str(), pcap_geterr(device));
            exit(1);
        }
    }
    if (pcap_loop(device, packetCount, handlePacket, nullptr) == PCAP_ERROR)
    {
        pcap_close(device);
        fprintf(stderr, "ERROR: Couldn't read packets from device %s: %s\n", interfaceArg.c_str(), pcap_geterr(device));
        exit(1);
    }
    pcap_close(device);
    exit(0);
}