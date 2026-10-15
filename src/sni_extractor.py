"""
Deep Payload Inspection (DPI) Extractors for Layer-7 Protocols.
File: src/sni_extractor.py

This module inspects raw application payloads to classify connections:
  1. SNIExtractor: Extracts Server Name Indication (SNI) from TLS 1.2/1.3 ClientHello.
  2. HTTPHostExtractor: Extracts the 'Host:' header from unencrypted HTTP/1.1 requests.
  3. DNSExtractor: Extracts queried domain names (QNAME) from DNS requests.
  4. QUICSNIExtractor: Extracts SNI from QUIC / HTTP3 initial handshake packets.
"""

from typing import Optional


# ============================================================================
# 1. TLS CLIENT HELLO & SNI EXTRACTOR
# ============================================================================

class SNIExtractor:
    """
    Extracts the server hostname from a TLS Client Hello message.
    
    Why this works:
      Even though TLS encrypts application traffic (HTTPS), the initial handshake
      must specify which website the client is connecting to before the server
      can present its SSL certificate. This hostname is sent in plaintext inside
      the TLS Server Name Indication (SNI) extension.
    
    TLS Record Format:
      Byte 0:      Content Type (0x16 = Handshake)
      Bytes 1-2:   TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
      Bytes 3-4:   Record Length
      Byte 5:      Handshake Type (0x01 = Client Hello)
      Bytes 6-8:   Handshake Length (24-bit integer)
      Bytes 9-10:  Client Version
      Bytes 11-42: Random bytes (32 bytes)
      Followed by: Session ID, Cipher Suites, Compression, and Extensions.
      Extension 0x0000 = Server Name Indication (SNI).
    """
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def read_uint16_be(data: bytes) -> int:
        """Read 2-byte big-endian unsigned integer."""
        return (data[0] << 8) | data[1]

    @staticmethod
    def read_uint24_be(data: bytes) -> int:
        """Read 3-byte big-endian unsigned integer."""
        return (data[0] << 16) | (data[1] << 8) | data[2]

    @classmethod
    def is_tls_client_hello(cls, payload: bytes, length: int) -> bool:
        """Verify whether payload starts with a valid TLS Client Hello header."""
        if length < 9:
            return False
        # Content Type must be Handshake (22 / 0x16)
        if payload[0] != cls.CONTENT_TYPE_HANDSHAKE:
            return False

        version = cls.read_uint16_be(payload[1:3])
        if version < 0x0300 or version > 0x0304:
            return False

        record_length = cls.read_uint16_be(payload[3:5])
        if record_length > length - 5:
            return False

        # Handshake message type must be Client Hello (1)
        if payload[5] != cls.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Parse TLS handshake records and extract the SNI hostname string.
        Returns the hostname (e.g. 'www.youtube.com') or None if not present.
        """
        if length is None:
            length = len(payload)

        if not cls.is_tls_client_hello(payload, length):
            return None

        # Step 1: Skip fixed-size TLS record & handshake headers
        offset = 5   # Skip 5-byte TLS record header
        offset += 4  # Skip 1-byte handshake type & 3-byte length
        offset += 2  # Skip 2-byte client version
        offset += 32 # Skip 32-byte client random

        # Step 2: Skip Session ID
        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        # Step 3: Skip Cipher Suites
        if offset + 2 > length:
            return None
        cipher_suites_length = cls.read_uint16_be(payload[offset : offset + 2])
        offset += 2 + cipher_suites_length

        # Step 4: Skip Compression Methods
        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        # Step 5: Parse Extensions Block
        if offset + 2 > length:
            return None
        extensions_length = cls.read_uint16_be(payload[offset : offset + 2])
        offset += 2

        extensions_end = min(offset + extensions_length, length)

        # Iterate through TLS extensions to find SNI (0x0000)
        while offset + 4 <= extensions_end:
            ext_type = cls.read_uint16_be(payload[offset : offset + 2])
            ext_len = cls.read_uint16_be(payload[offset + 2 : offset + 4])
            offset += 4

            if offset + ext_len > extensions_end:
                break

            if ext_type == cls.EXTENSION_SNI:
                if ext_len < 5:
                    break
                sni_list_len = cls.read_uint16_be(payload[offset : offset + 2])
                if sni_list_len < 3:
                    break

                sni_type = payload[offset + 2]
                sni_len = cls.read_uint16_be(payload[offset + 3 : offset + 5])

                if sni_type != cls.SNI_TYPE_HOSTNAME:
                    break
                if sni_len > ext_len - 5:
                    break

                hostname_bytes = payload[offset + 5 : offset + 5 + sni_len]
                return hostname_bytes.decode("utf-8", errors="ignore")

            offset += ext_len

        return None


# ============================================================================
# 2. HTTP/1.1 HOST EXTRACTOR
# ============================================================================

class HTTPHostExtractor:
    """
    Extracts the destination hostname from unencrypted HTTP requests by locating
    the 'Host: example.com' header.
    """

    @staticmethod
    def is_http_request(payload: bytes, length: int) -> bool:
        """Check if payload begins with a standard HTTP verb."""
        if length < 4:
            return False
        methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
        return any(payload[:4] == m for m in methods)

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """
        Scan HTTP request headers for 'Host:' and extract the domain name.
        """
        if length is None:
            length = len(payload)

        if not cls.is_http_request(payload, length):
            return None

        host_header = b"host:"
        host_len = len(host_header)

        for i in range(min(length - host_len, 2048)):
            if payload[i : i + host_len].lower() == host_header:
                start = i + host_len
                # Skip leading spaces or tabs
                while start < length and payload[start] in (32, 9):
                    start += 1

                end = start
                # Read until carriage return or newline
                while end < length and payload[end] not in (13, 10):
                    end += 1

                if end > start:
                    host = payload[start:end].decode("utf-8", errors="ignore").strip()
                    # Strip port if present (e.g. 'example.com:8080' -> 'example.com')
                    colon_pos = host.find(":")
                    if colon_pos != -1:
                        host = host[:colon_pos]
                    return host
        return None


# ============================================================================
# 3. DNS QUERY DOMAIN EXTRACTOR
# ============================================================================

class DNSExtractor:
    """
    Decodes standard DNS queries to extract the requested domain name (QNAME).
    
    DNS Header Format (12 bytes):
      Bytes 0-1:  Transaction ID
      Bytes 2-3:  Flags (QR bit = 0 indicates a Query)
      Bytes 4-5:  Question count (QDCOUNT > 0)
    
    Question section encodes domains as length-prefixed labels:
      e.g. 3 'w' 'w' 'w' 6 'g' 'o' 'o' 'g' 'l' 'e' 3 'c' 'o' 'm' 0
    """

    @staticmethod
    def is_dns_query(payload: bytes, length: int) -> bool:
        """Validate DNS query header."""
        if length < 12:
            return False
        flags = payload[2]
        # QR bit (0x80) must be 0 for a query
        if (flags & 0x80) != 0:
            return False
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0

    @classmethod
    def extract_query(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """Parse DNS question section and return dotted domain name (e.g. 'google.com')."""
        if length is None:
            length = len(payload)

        if not cls.is_dns_query(payload, length):
            return None

        offset = 12
        domain_parts = []

        while offset < length:
            label_len = payload[offset]
            if label_len == 0:
                break
            if label_len > 63:  # Compression pointer or invalid label
                break

            offset += 1
            if offset + label_len > length:
                break

            part = payload[offset : offset + label_len].decode("utf-8", errors="ignore")
            domain_parts.append(part)
            offset += label_len

        return ".".join(domain_parts) if domain_parts else None


# ============================================================================
# 4. QUIC SNI EXTRACTOR (HTTP/3)
# ============================================================================

class QUICSNIExtractor:
    """
    Extracts TLS ClientHello SNI encapsulated within QUIC Initial packets (UDP port 443).
    """

    @staticmethod
    def is_quic_initial(payload: bytes, length: int) -> bool:
        """Check if UDP packet has QUIC Long Header form."""
        if length < 5:
            return False
        return (payload[0] & 0x80) != 0

    @classmethod
    def extract(cls, payload: bytes, length: Optional[int] = None) -> Optional[str]:
        """Search for TLS ClientHello structure inside initial frames."""
        if length is None:
            length = len(payload)

        if not cls.is_quic_initial(payload, length):
            return None

        for i in range(min(length - 50, 1200)):
            if payload[i] == 0x01:  # ClientHello handshake indicator
                if i >= 5:
                    result = SNIExtractor.extract(payload[i - 5 :], length - (i - 5))
                    if result:
                        return result
        return None