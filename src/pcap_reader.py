"""
PCAP Binary File Parser & Packet Reader.
File: src/pcap_reader.py

PCAP (Packet Capture) is the standard file format used by Wireshark, tcpdump,
and network sniffers to record live network packets.

PCAP File Layout:
  +-------------------------------------------------------+
  | Global Header (24 bytes)                              |
  |  - Magic Number (0xa1b2c3d4 or swapped 0xd4c3b2a1)    |
  |  - Version Major & Minor (usually 2.4)                |
  |  - Timezone & Sigfigs (usually 0)                     |
  |  - Snaplen (Max packet capture length, e.g. 65535)    |
  |  - Link Type (Network Type: 1 = Ethernet)             |
  +-------------------------------------------------------+
  | Packet 1 Header (16 bytes: timestamp, incl_len, ...)  |
  | Packet 1 Data (incl_len raw bytes)                    |
  +-------------------------------------------------------+
  | Packet 2 Header (16 bytes)                            |
  | Packet 2 Data (incl_len raw bytes)                    |
  +-------------------------------------------------------+
  | ...                                                   |
  +-------------------------------------------------------+
"""

from dataclasses import dataclass
import struct
import sys
from typing import BinaryIO, Optional


# ============================================================================
# PCAP CONSTANTS
# ============================================================================

PCAP_MAGIC_NATIVE = 0xA1B2C3D4   # Standard PCAP magic number in host byte order
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1  # Byte-swapped magic number (different endianness)


# ============================================================================
# PCAP HEADER DATA STRUCTURES
# ============================================================================

@dataclass
class PcapGlobalHeader:
    """The 24-byte header at the very beginning of every PCAP file."""
    magic_number: int    # 4 bytes: identifies file format & endianness
    version_major: int   # 2 bytes: major version (2)
    version_minor: int   # 2 bytes: minor version (4)
    thiszone: int        # 4 bytes: GMT to local correction
    sigfigs: int         # 4 bytes: accuracy of timestamps
    snaplen: int         # 4 bytes: maximum length of captured packets
    network: int         # 4 bytes: data link type (1 = Ethernet)


@dataclass
class PcapPacketHeader:
    """The 16-byte header preceding every individual packet in the file."""
    ts_sec: int          # 4 bytes: timestamp seconds
    ts_usec: int         # 4 bytes: timestamp microseconds
    incl_len: int        # 4 bytes: number of octets of packet saved in file
    orig_len: int        # 4 bytes: actual length of packet on the wire


@dataclass
class RawPacket:
    """Represents a raw packet read from the PCAP file."""
    header: PcapPacketHeader
    data: bytearray


# ============================================================================
# PCAP READER
# ============================================================================

class PcapReader:
    """
    Sequentially reads packets from a standard PCAP file.
    Automatically detects and handles endianness byte-swapping.
    """
    GLOBAL_HEADER_FMT = "IHHiIII"  # 24 bytes
    PACKET_HEADER_FMT = "IIII"     # 16 bytes

    def __init__(self):
        self._file: Optional[BinaryIO] = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self._needs_byte_swap = False
        self._endian_char = "="

    def __del__(self):
        self.close()

    def open(self, filename: str) -> bool:
        """Open a PCAP file and parse the 24-byte global header."""
        self.close()
        try:
            self._file = open(filename, "rb")
        except IOError as err:
            print(f"[PcapReader] Error: Could not open '{filename}': {err}", file=sys.stderr)
            return False

        hdr_size = struct.calcsize(self.GLOBAL_HEADER_FMT)
        gh_data = self._file.read(hdr_size)
        if len(gh_data) < hdr_size:
            print("[PcapReader] Error: File is smaller than a 24-byte PCAP header", file=sys.stderr)
            self.close()
            return False

        # Read magic number using native endianness to determine byte ordering
        magic = struct.unpack("=I", gh_data[:4])[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
            self._endian_char = "="
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            self._endian_char = "<" if sys.byteorder == "big" else ">"
        else:
            print(f"[PcapReader] Error: Invalid PCAP magic number: 0x{magic:08x}", file=sys.stderr)
            self.close()
            return False

        fields = struct.unpack(self._endian_char + self.GLOBAL_HEADER_FMT, gh_data)
        self.global_header = PcapGlobalHeader(*fields)

        link_type_desc = " (Ethernet)" if self.global_header.network == 1 else ""
        print(f"[PcapReader] Opened: {filename}")
        print(f"  PCAP Version: {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snapshot Max: {self.global_header.snaplen} bytes")
        print(f"  Link Type:    {self.global_header.network}{link_type_desc}")
        return True

    def close(self) -> None:
        """Close open file handle."""
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None
        self._needs_byte_swap = False

    def is_open(self) -> bool:
        """Check if file handle is open and ready."""
        return self._file is not None and not self._file.closed

    def read_next_packet(self, packet: Optional[RawPacket] = None) -> Optional[RawPacket]:
        """
        Read the next packet from the PCAP file.
        Returns RawPacket or None at End-Of-File (EOF).
        """
        if not self.is_open():
            return None

        hdr_size = struct.calcsize(self.PACKET_HEADER_FMT)
        hdr_data = self._file.read(hdr_size)
        if len(hdr_data) < hdr_size:
            return None  # Reached EOF cleanly

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self._endian_char + self.PACKET_HEADER_FMT, hdr_data
        )
        pkt_hdr = PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len)

        # Sanity check against corrupted packet lengths
        if (self.global_header and incl_len > self.global_header.snaplen) or incl_len > 65535:
            print(f"[PcapReader] Warning: Abnormal packet length {incl_len} bytes", file=sys.stderr)
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("[PcapReader] Warning: Unexpected EOF while reading packet payload", file=sys.stderr)
            return None

        if packet is not None:
            packet.header = pkt_hdr
            packet.data = bytearray(data)
            return packet

        return RawPacket(header=pkt_hdr, data=bytearray(data))