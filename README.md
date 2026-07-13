# Raw Packet Sniffer

An educational packet sniffer for Linux, written with Python's built-in socket and struct modules. It does not use external packet-capture libraries such as Scapy or Npcap.

The program captures Ethernet frames, parses IPv4, TCP, and UDP headers, and displays TCP/UDP payloads as readable ASCII text when possible or as hexadecimal data otherwise.

> Use this tool only on networks and systems that you own or are explicitly authorized to inspect. Packet payloads can contain session data and other sensitive information.

## Requirements

- Linux, such as Ubuntu
- Python 3
- Permission to open raw sockets: root or the CAP_NET_RAW capability

The program uses Linux-specific AF_PACKET sockets, so it does not run on Windows or macOS without a different capture implementation.

## Run

Find the name of your network interface:

~~~bash
ip link
~~~

Start the sniffer on the selected interface:

~~~bash
sudo python3 sniffer.py enp0s3
~~~

The interface name varies by computer; common examples are enp0s3, eth0, and wlan0. If no interface is supplied, the program attempts to listen on all available interfaces:

~~~bash
sudo python3 sniffer.py
~~~

Press Ctrl+C to stop capturing packets.

## Captured information

For every Ethernet frame:

- Destination and source MAC addresses
- EtherType, such as IPv4, ARP, or IPv6

For IPv4 packets:

- Source and destination IP addresses
- IP protocol number and name, such as ICMP, TCP, or UDP
- Byte range of the IP header

For TCP or UDP packets:

- Source port
- Destination port
- Application payload

## Quick experiments

To observe an unencrypted HTTP request, run the sniffer and then use another terminal:

~~~bash
curl http://neverssl.com/
~~~

TCP packets sent to destination port 80 may contain readable request lines such as GET / HTTP/1.1. If your browser automatically upgrades HTTP to HTTPS, the content will be encrypted and readable HTTP text will not be available.

To observe ICMP traffic:

~~~bash
ping 1.1.1.1
~~~

The output will show IP Protocol: ICMP (1). This example does not separately parse the ICMP header, so its header and data are displayed as payload.

## How it works

AF_PACKET with SOCK_RAW receives raw Ethernet frames from the Linux kernel. The Ethernet header occupies the first 14 bytes:

| Byte range | Field |
| --- | --- |
| 0-5 | Destination MAC |
| 6-11 | Source MAC |
| 12-13 | EtherType |

When the EtherType is 0x0800, the IPv4 header begins immediately after the Ethernet header. struct.unpack() converts binary header fields into Python integers and byte strings, while socket.inet_ntoa() converts four raw IP bytes into a readable IPv4 address such as 192.168.1.1.

The IPv4 IHL field defines the variable IP header length. The TCP header begins at the end of the IP header and has its own Data Offset field; the UDP header is always 8 bytes. The bytes following these headers are treated as payload.

## Limitations

- A different capture implementation is required on non-Linux operating systems.
- VLAN-tagged Ethernet frames are not parsed.
- Packets are displayed independently; the program does not reassemble, order, or deduplicate TCP streams.
- Encrypted HTTPS/TLS payloads cannot reveal readable HTTP content.
- This tool is intended for learning packet structure. Use Wireshark or tcpdump for production packet analysis.
