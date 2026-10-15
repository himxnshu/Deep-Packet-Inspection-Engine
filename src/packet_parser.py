"""
Network Packet Parser for Layers 2, 3, 4, and 7.
File: src/packet_parser.py

This module decodes raw bytes from a PCAP file through the standard networking stack:
  Layer 2 (Ethernet): MAC addresses, EtherType (IPv4 / IPv6 / ARP)
  Layer 3 (IPv4):     Source/Destination IP, TTL, Protocol (TCP / UDP)
  Layer 4 (TCP/UDP):  Ports, TCP sequence/ack numbers, TCP flags (SYN, ACK, etc.)
  Layer 7 (Payload):  Raw bytes containing TLS ClientHello, HTTP request, DNS query, etc.
"""

from dataclasses import dataclass
import struct
from typing import Optional, Tuple

from pcap_reader import RawPacket
from types_dpi import ip_to_str


# ============================================================================
# PROTOCOL & ETHERTYPE CONSTANTS
# ============================================================================

class Protocol:
    """IP Layer Protocol Numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    """Ethernet Frame Types."""
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


class TCPFlags:
    """TCP Control Flags."""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


# ============================================================================
# PARSED PACKET DATA STRUCTURE
# ============================================================================

@dataclass
class ParsedPacket:
    """Structured representation of all decoded packet layers."""
    # Timestamps (from PCAP packet header)
    timestamp_sec: int = 0
    timestamp_usec: int = 0

    # Layer 2: Ethernet
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0

    # Layer 3: IPv4
    has_ip: bool = False
    ip_version: int = 0
    src_ip_int: int = 0       # 32-bit big-endian integer
    dest_ip_int: int = 0      # 32-bit big-endian integer
    src_ip: str = ""          # "192.168.1.100"
    dest_ip: str = ""         # "142.250.185.206"
    protocol: int = 0
    ttl: int = 0

    # Layer 4: Transport (TCP / UDP)
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0

    # TCP specific metadata
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Layer 7: Application Payload
    payload_length: int = 0
    payload: bytes = b""


# ============================================================================
# PACKET PARSER ENGINE
# ============================================================================

class PacketParser:
    """Decodes binary network packet data into a ParsedPacket object."""

    @staticmethod
    def mac_to_string(mac_bytes: bytes) -> str:
        """Format 6 raw MAC bytes into a readable 'aa:bb:cc:dd:ee:ff' string."""
        return ":".join(f"{b:02x}" for b in mac_bytes)

    @staticmethod
    def ip_to_string(ip: int) -> str:
        """Format 32-bit integer into standard IPv4 dotted-decimal string."""
        return ip_to_str(ip)

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        """Return human-readable protocol name."""
        if protocol == Protocol.ICMP:
            return "ICMP"
        if protocol == Protocol.TCP:
            return "TCP"
        if protocol == Protocol.UDP:
            return "UDP"
        return f"Protocol({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        """Convert TCP flag bits into space-separated string (e.g. 'SYN ACK')."""
        parts = []
        if flags & TCPFlags.SYN: parts.append("SYN")
        if flags & TCPFlags.ACK: parts.append("ACK")
        if flags & TCPFlags.FIN: parts.append("FIN")
        if flags & TCPFlags.RST: parts.append("RST")
        if flags & TCPFlags.PSH: parts.append("PSH")
        if flags & TCPFlags.URG: parts.append("URG")
        return " ".join(parts) if parts else "NONE"

    @classmethod
    def parse(cls, raw: RawPacket, parsed: Optional[ParsedPacket] = None) -> Optional[ParsedPacket]:
        """
        Main entry point: parse a RawPacket (Ethernet -> IPv4 -> TCP/UDP -> Payload).
        Returns None if packet is malformed or shorter than an Ethernet header.
        """
        if parsed is None:
            parsed = ParsedPacket()

        parsed.timestamp_sec = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data = bytes(raw.data)
        length = len(data)

        # 1. Parse Ethernet Header (14 bytes)
        if not cls._parse_ethernet(data, length, parsed):
            return None
        offset = 14

        # 2. Parse IPv4 Header (if Ethernet type is IPv4: 0x0800)
        if parsed.ether_type == EtherType.IPv4:
            ip_ok, offset = cls._parse_ipv4(data, length, parsed, offset)
            if not ip_ok:
                return None

            # 3. Parse Transport Layer (TCP or UDP)
            if parsed.protocol == Protocol.TCP:
                tcp_ok, offset = cls._parse_tcp(data, length, parsed, offset)
                if not tcp_ok:
                    return None
            elif parsed.protocol == Protocol.UDP:
                udp_ok, offset = cls._parse_udp(data, length, parsed, offset)
                if not udp_ok:
                    return None

        # 4. Extract Application Payload (remaining bytes)
        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload = b""

        return parsed

    @classmethod
    def _parse_ethernet(cls, data: bytes, length: int, parsed: ParsedPacket) -> bool:
        """
        Parse Ethernet Frame:
        Bytes 0-5:   Destination MAC
        Bytes 6-11:  Source MAC
        Bytes 12-13: EtherType (e.g. 0x0800 for IPv4)
        """
        if length < 14:
            return False
        parsed.dest_mac = cls.mac_to_string(data[0:6])
        parsed.src_mac = cls.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack("!H", data[12:14])[0]
        return True

    @classmethod
    def _parse_ipv4(cls, data: bytes, length: int, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        """
        Parse IPv4 Header:
        Byte 0:     Version (4 bits) & Internet Header Length / IHL (4 bits)
        Byte 8:     Time to Live (TTL)
        Byte 9:     Protocol (TCP=6, UDP=17)
        Bytes 12-15: Source IP (32-bit network byte order)
        Bytes 16-19: Destination IP (32-bit network byte order)
        """
        if length < offset + 20:
            return False, offset

        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False, offset

        ip_header_len = ihl * 4
        if ip_header_len < 20 or length < offset + ip_header_len:
            return False, offset

        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]

        # Read standard big-endian 32-bit IP integers
        src_ip_val = struct.unpack("!I", data[offset + 12 : offset + 16])[0]
        dest_ip_val = struct.unpack("!I", data[offset + 16 : offset + 20])[0]

        parsed.src_ip_int = src_ip_val
        parsed.dest_ip_int = dest_ip_val
        parsed.src_ip = ip_to_str(src_ip_val)
        parsed.dest_ip = ip_to_str(dest_ip_val)
        parsed.has_ip = True

        return True, offset + ip_header_len

    @classmethod
    def _parse_tcp(cls, data: bytes, length: int, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        """
        Parse TCP Header:
        Bytes 0-1:  Source Port
        Bytes 2-3:  Destination Port
        Bytes 4-7:  Sequence Number
        Bytes 8-11: Acknowledgment Number
        Byte 12:    Data Offset (Header Length in 32-bit words)
        Byte 13:    TCP Flags (FIN, SYN, RST, PSH, ACK, URG)
        """
        if length < offset + 20:
            return False, offset

        src_port, dest_port, seq, ack, data_offset_byte, flags = struct.unpack(
            "!HHIIBB", data[offset : offset + 14]
        )
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4

        if tcp_header_len < 20 or length < offset + tcp_header_len:
            return False, offset

        parsed.src_port = src_port
        parsed.dest_port = dest_port
        parsed.seq_number = seq
        parsed.ack_number = ack
        parsed.tcp_flags = flags
        parsed.has_tcp = True

        return True, offset + tcp_header_len

    @classmethod
    def _parse_udp(cls, data: bytes, length: int, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        """
        Parse UDP Header:
        Bytes 0-1: Source Port
        Bytes 2-3: Destination Port
        Bytes 4-5: Length (header + payload)
        Bytes 6-7: Checksum
        """
        if length < offset + 8:
            return False, offset

        src_port, dest_port = struct.unpack("!HH", data[offset : offset + 4])
        parsed.src_port = src_port
        parsed.dest_port = dest_port
        parsed.has_udp = True

        return True, offset + 8