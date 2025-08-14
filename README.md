# SYN Flood Tool (ANSI C)

> **Educational & Blue Team Training Use ONLY**  
> **Author:** Dr. Burak BAYSAN (Forensic Computing / Cybersecurity Educator)

---

## Table of Contents
- [Overview](#overview)
- [Legal & Ethical Notice](#legal--ethical-notice)
- [Features](#features)
- [How It Works](#how-it-works)
  - [IP & TCP Header Construction](#ip--tcp-header-construction)
  - [Checksum Calculation](#checksum-calculation)
- [Usage](#usage)
  - [Requirements](#requirements)
  - [Compilation](#compilation)
  - [Running](#running)
- [Code Structure](#code-structure)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [References](#references)
- [License](#license)
- [Contact](#contact)

---

## Overview

This tool demonstrates the mechanics of a TCP SYN flood attack at the packet level. It constructs raw IP and TCP SYN packets and sends them in a continuous loop to a specified target host and port. The tool is **restricted to RFC1918 (Private) address ranges** for safety and ethical reasons.

## Legal & Ethical Notice

**WARNING:**
- This program is a **teaching tool** for isolated lab networks.
- **Running this on the public internet is illegal and unethical.**
- **You must run as root/admin** to use raw sockets.
- Use **only in authorized, controlled, and isolated environments**.
- The author and project contributors **assume NO liability** for misuse.

## Features

- **Raw Socket Packet Crafting**: Manually builds IP and TCP SYN packets.
- **Randomized Source Port & Sequence Number**: Simulates authentic attack traffic patterns.
- **Spoofed Source IP (RFC1918)**: Example defaults to `192.168.1.100`.
- **Infinite SYN Flood Loop**: Continuously sends packets to the target.
- **Educational Comments**: Code is extensively documented for learning purposes.

## How It Works

### IP & TCP Header Construction

- The program defines custom structs for IPv4 and TCP headers.
- Fields are set according to protocol standards.
- The IP header includes version, header length, TTL, protocol, and source/destination IP addresses.
- The TCP header includes randomized source port, sequence number, SYN flags, and window size.

### Checksum Calculation

- Both headers require valid checksums.
- The custom `checksum()` function computes 16-bit checksums for IP and TCP headers.

---

## Usage

### Requirements

- **Platform:** Linux/Unix (raw sockets required)
- **Privileges:** Run as `root` or with `sudo`
- **Compiler:** `gcc` or compatible ANSI C compiler

### Compilation

```sh
gcc -o drbb_synflood drbb_synflood.c
```

### Running

```sh
sudo ./drbb_synflood <target_ip> <target_port>
```

**Example:**
```sh
sudo ./drbb_synflood 192.168.1.200 80
```

---

## Code Structure

- **ipheader struct**: IPv4 header fields.
- **tcpheader struct**: TCP header fields.
- **checksum function**: Calculates checksums for IP and TCP headers.
- **pseudo_header struct**: Used for TCP checksum calculation.
- **main function**: Handles argument parsing, socket creation, header construction, checksum calculation, and packet sending loop.

---

## Customization

- **Source IP**: Change the spoofed IP in the following line:
  ```c
  ip->iph_sourceip = inet_addr("192.168.1.100"); // Spoofed source IP
  ```
  You may randomize within RFC1918 ranges for more realism.

- **Flood Rate**: Add a sleep or delay in the sending loop to control the flood rate, e.g. `usleep(1000);`

- **Port Range Flood**: Modify the loop to iterate over a port range for broader testing.

- **Logging**: Add counters or verbose output for analysis.

---

## Troubleshooting

- **Socket creation failed**: Ensure you are root (`sudo`), and your system supports raw sockets.
- **No packets received**: Verify target is reachable and within RFC1918 address range.
- **Segmentation fault**: Check for buffer sizes and pointer arithmetic mistakes.
- **IP_HDRINCL error**: Your kernel or network stack may restrict raw packet crafting.

---

## References

- [TCP/IP Illustrated, Volume 1](https://www.amazon.com/TCP-Illustrated-Protocols-Addison-Wesley-Professional/dp/0321336313)
- [Linux Raw Sockets](https://man7.org/linux/man-pages/man7/raw.7.html)
- [IP and TCP Header Structure (Wikipedia)](https://en.wikipedia.org/wiki/IPv4#Header)
- [C Programming for Hackers](https://www.cprogramming.com/tutorial/c-tutorial.html)

---

## License

This project is **open-source** and intended **exclusively for education and ethical defense**.  
**Any misuse is strictly prohibited.**

---

## Contact

**Dr. Burak BAYSAN**  
Forensic Computing / Cybersecurity Educator  
[LinkedIn](https://www.linkedin.com/in/drburakbaysan)

---

> **Disclaimer:**  
> This tool is for learning and defense. Never use offensively or outside your own isolated lab.
