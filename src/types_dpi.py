"""
Core Data Types, Enums, and Helper Utilities for the DPI Engine.
File: src/types_dpi.py

This module is the single source of truth for:
- Application types (YouTube, Netflix, DNS, etc.)
- Connection states (NEW, ESTABLISHED, CLASSIFIED, BLOCKED, CLOSED)
- Filtering actions (FORWARD vs DROP)
- Five-Tuple connection identifier (Source IP/Port, Dest IP/Port, Protocol)
- PacketJob container used across thread queues
- IP address conversion helpers (Big-Endian integer <-> IPv4 string)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
import ipaddress
import socket
import struct
import time
from typing import Optional


# ============================================================================
# 1. APPLICATION CLASSIFICATION TYPES
# ============================================================================

class AppType(Enum):
    """
    Identified Layer-7 application or network protocol.
    Each connection is tagged with one of these types once inspected.
    """
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


# Human-friendly display strings for each application
_APP_TYPE_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    """Convert an AppType enum value to its readable name."""
    return _APP_TYPE_NAMES.get(app, "Unknown")


def string_to_app_type(name: str) -> AppType:
    """Lookup an AppType by case-insensitive name."""
    clean = name.strip().lower()
    for app, label in _APP_TYPE_NAMES.items():
        if label.lower() == clean or app.name.lower() == clean:
            return app
    return AppType.UNKNOWN


def sni_to_app_type(sni: str) -> AppType:
    """
    Map an extracted domain / SNI string to a high-level application.
    Example: 'r3---sn-vgqsrn7e.googlevideo.com' -> AppType.YOUTUBE
    """
    if not sni:
        return AppType.UNKNOWN

    s = sni.lower()

    # Streaming & Video
    if any(k in s for k in ("youtube", "googlevideo", "ytimg", "youtu.be")):
        return AppType.YOUTUBE
    if any(k in s for k in ("netflix", "nflxvideo", "nflximg", "nflxext")):
        return AppType.NETFLIX
    if any(k in s for k in ("spotify", "scdn.co", "audio-ak")):
        return AppType.SPOTIFY

    # Social Media
    if any(k in s for k in ("facebook", "fbcdn", "fb.com", "meta.com", "fbsbx")):
        return AppType.FACEBOOK
    if any(k in s for k in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM
    if any(k in s for k in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER
    if any(k in s for k in ("tiktok", "byteoversea", "tiktokcdn", "musical.ly")):
        return AppType.TIKTOK
    if any(k in s for k in ("discord", "discordapp", "discord.gg")):
        return AppType.DISCORD
    if any(k in s for k in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP
    if any(k in s for k in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # Cloud & Tech Services
    if any(k in s for k in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE
    if any(k in s for k in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON
    if any(k in s for k in ("microsoft", "azure", "live.com", "office", "bing", "msn")):
        return AppType.MICROSOFT
    if any(k in s for k in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE
    if any(k in s for k in ("github", "githubusercontent", "github.io")):
        return AppType.GITHUB
    if any(k in s for k in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE
    if "zoom" in s:
        return AppType.ZOOM

    return AppType.HTTPS


# ============================================================================
# 2. CONNECTION STATE & POLICY ENUMS
# ============================================================================

class ConnectionState(Enum):
    """Lifecycle state of a tracked network flow."""
    NEW = auto()          # Just created (TCP SYN seen or initial packet)
    ESTABLISHED = auto()  # Handshake complete, active communication
    CLASSIFIED = auto()   # Layer-7 application identified (via SNI/Host/DNS)
    BLOCKED = auto()      # Matched a policy rule; all subsequent packets dropped
    CLOSED = auto()       # TCP FIN/RST seen or connection timed out


class PacketAction(Enum):
    """Decision made for an individual packet."""
    FORWARD = auto()      # Permit packet to internet / destination
    DROP = auto()         # Block packet (drop silently)


# ============================================================================
# 3. IP ADDRESS & FIVE-TUPLE HELPERS
# ============================================================================

def ip_to_str(ip_int: int) -> str:
    """
    Convert a 32-bit big-endian integer to standard IPv4 dotted-decimal string.
    Example: 0xc0a80164 (3232235876) -> "192.168.1.100"
    """
    try:
        return str(ipaddress.IPv4Address(ip_int & 0xFFFFFFFF))
    except Exception:
        # Fallback using bit shifts in network byte order
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def str_to_ip(ip_str: str) -> int:
    """
    Convert standard IPv4 dotted-decimal string to 32-bit big-endian integer.
    Example: "192.168.1.100" -> 0xc0a80164 (3232235876)
    """
    try:
        return int(ipaddress.IPv4Address(ip_str.strip()))
    except Exception:
        octets = [int(x) for x in ip_str.strip().split(".")]
        return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


@dataclass(frozen=True)
class FiveTuple:
    """
    Unique identifier for a bidirectional network connection (flow).
    Consists of: (Source IP, Destination IP, Source Port, Destination Port, Protocol)
    All IPs are stored as 32-bit unsigned integers in standard big-endian order.
    """
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def reverse(self) -> "FiveTuple":
        """Return the inverted tuple (opposite direction of the flow)."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def canonical(self) -> "FiveTuple":
        """
        Normalize direction so that client->server and server->client packets
        hash to the exact same key.
        Endpoint 1 is defined as (min(IP), min(Port)).
        """
        ep1 = (self.src_ip, self.src_port)
        ep2 = (self.dst_ip, self.dst_port)
        return self if ep1 <= ep2 else self.reverse()

    @property
    def src_ip_str(self) -> str:
        """Formatted source IPv4 string."""
        return ip_to_str(self.src_ip)

    @property
    def dst_ip_str(self) -> str:
        """Formatted destination IPv4 string."""
        return ip_to_str(self.dst_ip)

    @property
    def protocol_name(self) -> str:
        """Name of the transport protocol."""
        if self.protocol == 6:
            return "TCP"
        if self.protocol == 17:
            return "UDP"
        if self.protocol == 1:
            return "ICMP"
        return str(self.protocol)

    def __str__(self) -> str:
        return f"{self.src_ip_str}:{self.src_port} -> {self.dst_ip_str}:{self.dst_port} ({self.protocol_name})"


# ============================================================================
# 4. PACKET JOB (DATA PASSED THROUGH CONCURRENCY PIPELINE)
# ============================================================================

@dataclass
class PacketJob:
    """
    Container passed from PCAP Reader -> Load Balancer -> Fast Path -> Output Writer.
    Carries the raw packet bytes, extracted 5-tuple, timestamps, and payload.
    """
    packet_id: int
    ts_sec: int
    ts_usec: int
    raw_bytes: bytes
    tuple: FiveTuple
    payload: bytes
    tcp_flags: int = 0
    orig_len: int = 0
    action: PacketAction = PacketAction.FORWARD