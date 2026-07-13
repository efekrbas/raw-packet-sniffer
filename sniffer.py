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
    """Veriyi 16 baytlık satırlar halinde hexadecimal gösterir."""
    lines = []

    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        lines.append(f"{offset:04x}  {hex_bytes}")

    return "\n".join(lines)


def print_payload(payload):
    """
    Payload yalnızca yazdırılabilir ASCII karakterleri ve satır sonlarını
    içeriyorsa metin olarak, aksi durumda hexadecimal olarak gösterilir.
    """
    if not payload:
        print("Payload:          Yok")
        return

    is_ascii_text = all(
        32 <= byte <= 126 or byte in (9, 10, 13)
        for byte in payload
    )

    print("-" * 60)
    print(f"Payload boyutu:   {len(payload)} bayt")

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
        "protocol": ETHERTYPES.get(eth_type, "Bilinmeyen / Diğer"),
    }


def parse_ipv4_header(packet):
    """
    Ethernet başlığı 0-13. baytlardadır.
    IPv4 başlığı 14. bayttan başlar.

    IHL alanı IP başlığı uzunluğunu 32-bit kelime sayısı olarak verir:
    IHL=5 -> 5 * 4 = 20 bayt.

    Bu nedenle IP başlığı:
      başlangıç: 14
      bitiş:     14 + (IHL * 4)

    socket.inet_ntoa(), b'\\xc0\\xa8\\x01\\x01' gibi 4 ham baytı
    '192.168.1.1' biçimindeki okunabilir IPv4 adresine çevirir.
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

    # IPv4 toplam uzunluğu IP başlığını da içerir.
    # Yakalanan paketin sonunu aşmamak için min() kullanılır.
    ip_packet_end = min(len(packet), ip_start + total_length)
    fragment_offset = flags_and_fragment & 0x1FFF

    return {
        "source_ip": socket.inet_ntoa(source_raw),
        "destination_ip": socket.inet_ntoa(destination_raw),
        "protocol_number": protocol_number,
        "protocol": IP_PROTOCOLS.get(protocol_number, "Bilinmeyen / Diğer"),
        "header_start": ip_start,
        "header_end": ip_header_end,
        "header_length": ip_header_length,
        "packet_end": ip_packet_end,
        "fragment_offset": fragment_offset,
    }


def parse_tcp_header(packet, tcp_start, ip_packet_end):
    """
    TCP başlığı IP başlığının bittiği yerde başlar.
    İlk 20 bayt TCP'nin sabit başlık bölümüdür; Data Offset alanı gerçek
    TCP başlık uzunluğunu belirtir.
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
    UDP başlığı sabit 8 bayttır:
    kaynak port (2), hedef port (2), uzunluk (2), checksum (2).
    """
    if ip_packet_end < udp_start + 8:
        return None

    source_port, destination_port, udp_length, _ = struct.unpack(
        "!HHHH",
        packet[udp_start:udp_start + 8]
    )

    if udp_length < 8:
        return None

    # UDP uzunluğu, UDP başlığı + UDP payload'ını kapsar.
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
        print(f"{interface} dinleniyor. Çıkmak için Ctrl+C.")
    else:
        print("Tüm erişilebilir arayüzler dinleniyor. Çıkmak için Ctrl+C.")

    try:
        while True:
            packet, address = sniffer.recvfrom(65535)
            ethernet = parse_ethernet_header(packet)

            if ethernet is None:
                continue

            print("\n" + "=" * 60)
            print(f"Arayüz:          {address[0]}")
            print(f"Paket boyutu:    {len(packet)} bayt")
            print(f"Hedef MAC:       {ethernet['destination_mac']}")
            print(f"Kaynak MAC:      {ethernet['source_mac']}")
            print(f"EthType:         0x{ethernet['eth_type']:04x}")
            print(f"Protokol:        {ethernet['protocol']}")

            if ethernet["eth_type"] != 0x0800:
                continue

            ipv4 = parse_ipv4_header(packet)
            if ipv4 is None:
                print("IPv4 başlığı geçersiz veya eksik.")
                continue

            print("-" * 60)
            print(f"Kaynak IP:       {ipv4['source_ip']}")
            print(f"Hedef IP:        {ipv4['destination_ip']}")
            print(f"IP Protokol:     {ipv4['protocol']} ({ipv4['protocol_number']})")
            print(f"IP başlığı:      bayt {ipv4['header_start']}–{ipv4['header_end'] - 1}")

            transport_start = ipv4["header_end"]
            payload_start = transport_start
            payload_end = ipv4["packet_end"]

            # İlk olmayan IP parçalarında TCP/UDP başlığı bulunmayabilir.
            if ipv4["fragment_offset"] != 0:
                print("Not: IP fragmenti; TCP/UDP başlığı ayrıştırılmadı.")

            elif ipv4["protocol_number"] == 6:
                tcp = parse_tcp_header(packet, transport_start, ipv4["packet_end"])

                if tcp is None:
                    print("TCP başlığı geçersiz veya eksik.")
                    continue

                print("-" * 60)
                print(f"Taşıma Protokolü: TCP")
                print(f"Kaynak Port:     {tcp['source_port']}")
                print(f"Hedef Port:      {tcp['destination_port']}")

                payload_start = tcp["payload_start"]
                payload_end = tcp["payload_end"]

            elif ipv4["protocol_number"] == 17:
                udp = parse_udp_header(packet, transport_start, ipv4["packet_end"])

                if udp is None:
                    print("UDP başlığı geçersiz veya eksik.")
                    continue

                print("-" * 60)
                print(f"Taşıma Protokolü: UDP")
                print(f"Kaynak Port:     {udp['source_port']}")
                print(f"Hedef Port:      {udp['destination_port']}")

                payload_start = udp["payload_start"]
                payload_end = udp["payload_end"]

            payload = packet[payload_start:payload_end]
            print_payload(payload)

    except KeyboardInterrupt:
        print("\nPaket yakalama durduruldu.")
    finally:
        sniffer.close()


if __name__ == "__main__":
    main()