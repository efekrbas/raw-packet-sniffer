#!/usr/bin/env python3
import socket
import struct
import sys

ETH_P_ALL = 0x0003
ETHERNET_HEADER_LENGTH = 14

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
}

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def mac_address(raw_mac):
    return ":".join(f"{byte:02x}" for byte in raw_mac)


def hexdump(data, width=16):
    """Return data as hexadecimal rows of the requested width."""
    lines = []

    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        lines.append(f"{offset:04x}  {hex_bytes}")

    return "\n".join(lines)


def print_payload(payload):
    """
    Display the payload as text when it contains printable ASCII and line
    breaks only; otherwise, display it as hexadecimal.
    """
    if not payload:
        print("Payload:          None")
        return

    is_ascii_text = all(
        32 <= byte <= 126 or byte in (9, 10, 13)
        for byte in payload
    )

    print("-" * 60)
    print(f"Payload length:   {len(payload)} bytes")

    if is_ascii_text:
        print("Payload (ASCII):")
        print(payload.decode("ascii", errors="replace"))
    else:
        print("Payload (HEX):")
        print(hexdump(payload))


def parse_ethernet_header(packet):
    if len(packet) < ETHERNET_HEADER_LENGTH:
        return None

    destination, source, eth_type = struct.unpack(
        "!6s6sH",
        packet[:ETHERNET_HEADER_LENGTH]
    )

    return {
        "destination_mac": mac_address(destination),
        "source_mac": mac_address(source),
        "eth_type": eth_type,
        "protocol": ETHERTYPES.get(eth_type, "Unknown / Other"),
    }


def parse_ipv4_header(packet):
    """
    The Ethernet header occupies bytes 0 through 13.
    The IPv4 header begins at byte 14.

    The IHL field specifies the IP header length in 32-bit words:
    IHL=5 means 5 * 4 = 20 bytes.

    Therefore, the IP header:
      starts at: 14
      ends at:   14 + (IHL * 4)

    socket.inet_ntoa() converts four raw bytes, such as
    b'\xc0\xa8\x01\x01', into a readable IPv4 address such as 192.168.1.1.
    """
    ip_start = ETHERNET_HEADER_LENGTH

    if len(packet) < ip_start + 20:
        return None

    version_and_ihl = packet[ip_start]
    version = version_and_ihl >> 4
    ihl = version_and_ihl & 0x0F
    ip_header_length = ihl * 4
    ip_header_end = ip_start + ip_header_length

    if version != 4 or ihl < 5 or len(packet) < ip_header_end:
        return None

    (
        _,
        _,
        total_length,
        _,
        flags_and_fragment,
        _,
        protocol_number,
        _,
        source_raw,
        destination_raw,
    ) = struct.unpack("!BBHHHBBH4s4s", packet[ip_start:ip_start + 20])

    if total_length < ip_header_length:
        return None

    # IPv4 total length includes its header. Do not read beyond the capture.
    ip_packet_end = min(len(packet), ip_start + total_length)
    fragment_offset = flags_and_fragment & 0x1FFF

    return {
        "source_ip": socket.inet_ntoa(source_raw),
        "destination_ip": socket.inet_ntoa(destination_raw),
        "protocol_number": protocol_number,
        "protocol": IP_PROTOCOLS.get(protocol_number, "Unknown / Other"),
        "header_start": ip_start,
        "header_end": ip_header_end,
        "header_length": ip_header_length,
        "packet_end": ip_packet_end,
        "fragment_offset": fragment_offset,
    }


def parse_tcp_header(packet, tcp_start, ip_packet_end):
    """
    The TCP header starts immediately after the IP header.
    Its first 20 bytes are fixed; the Data Offset field gives the actual
    TCP header length.
    """
    if ip_packet_end < tcp_start + 20:
        return None

    source_port, destination_port, _, _, offset_byte, _, _, _, _ = struct.unpack(
        "!HHLLBBHHH",
        packet[tcp_start:tcp_start + 20]
    )

    tcp_header_length = (offset_byte >> 4) * 4
    tcp_header_end = tcp_start + tcp_header_length

    if tcp_header_length < 20 or tcp_header_end > ip_packet_end:
        return None

    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "header_length": tcp_header_length,
        "payload_start": tcp_header_end,
        "payload_end": ip_packet_end,
    }


def parse_udp_header(packet, udp_start, ip_packet_end):
    """
    The UDP header is always 8 bytes:
    source port (2), destination port (2), length (2), and checksum (2).
    """
    if ip_packet_end < udp_start + 8:
        return None

    source_port, destination_port, udp_length, _ = struct.unpack(
        "!HHHH",
        packet[udp_start:udp_start + 8]
    )

    if udp_length < 8:
        return None

    # UDP length includes its header and its payload.
    udp_end = min(ip_packet_end, udp_start + udp_length)

    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "header_length": 8,
        "payload_start": udp_start + 8,
        "payload_end": udp_end,
    }


def main():
    sniffer = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(ETH_P_ALL)
    )

    if len(sys.argv) > 1:
        interface = sys.argv[1]
        sniffer.bind((interface, 0))
        print(f"Listening on {interface}. Press Ctrl+C to stop.")
    else:
        print("Listening on all available interfaces. Press Ctrl+C to stop.")

    try:
        while True:
            packet, address = sniffer.recvfrom(65535)
            ethernet = parse_ethernet_header(packet)

            if ethernet is None:
                continue

            print("\n" + "=" * 60)
            print(f"Interface:        {address[0]}")
            print(f"Packet length:    {len(packet)} bytes")
            print(f"Destination MAC:  {ethernet['destination_mac']}")
            print(f"Source MAC:       {ethernet['source_mac']}")
            print(f"EtherType:        0x{ethernet['eth_type']:04x}")
            print(f"Protocol:         {ethernet['protocol']}")

            if ethernet["eth_type"] != 0x0800:
                continue

            ipv4 = parse_ipv4_header(packet)
            if ipv4 is None:
                print("Invalid or incomplete IPv4 header.")
                continue

            print("-" * 60)
            print(f"Source IP:        {ipv4['source_ip']}")
            print(f"Destination IP:   {ipv4['destination_ip']}")
            print(f"IP protocol:      {ipv4['protocol']} ({ipv4['protocol_number']})")
            print(f"IP header bytes:  {ipv4['header_start']}-{ipv4['header_end'] - 1}")

            transport_start = ipv4["header_end"]
            payload_start = transport_start
            payload_end = ipv4["packet_end"]

            # Non-initial IP fragments may not contain a TCP or UDP header.
            if ipv4["fragment_offset"] != 0:
                print("Note: IP fragment; TCP/UDP header was not parsed.")

            elif ipv4["protocol_number"] == 6:
                tcp = parse_tcp_header(packet, transport_start, ipv4["packet_end"])

                if tcp is None:
                    print("Invalid or incomplete TCP header.")
                    continue

                print("-" * 60)
                print("Transport protocol: TCP")
                print(f"Source port:      {tcp['source_port']}")
                print(f"Destination port: {tcp['destination_port']}")

                payload_start = tcp["payload_start"]
                payload_end = tcp["payload_end"]

            elif ipv4["protocol_number"] == 17:
                udp = parse_udp_header(packet, transport_start, ipv4["packet_end"])

                if udp is None:
                    print("Invalid or incomplete UDP header.")
                    continue

                print("-" * 60)
                print("Transport protocol: UDP")
                print(f"Source port:      {udp['source_port']}")
                print(f"Destination port: {udp['destination_port']}")

                payload_start = udp["payload_start"]
                payload_end = udp["payload_end"]

            payload = packet[payload_start:payload_end]
            print_payload(payload)

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    finally:
        sniffer.close()


if __name__ == "__main__":
    main()
