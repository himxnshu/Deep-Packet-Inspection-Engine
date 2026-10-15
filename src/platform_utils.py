"""
Platform-specific byte-order conversions and endianness helpers.
Corresponds to platform.h / platform_2.h.
"""
import sys

def swap_bytes_16(value: int) -> int:
    """16-bit integer byte reversal."""
    value &= 0xFFFF
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8)

def swap_bytes_32(value: int) -> int:
    """32-bit integer byte reversal."""
    value &= 0xFFFFFFFF
    return (
        ((value & 0xFF000000) >> 24)
        | ((value & 0x00FF0000) >> 8)
        | ((value & 0x0000FF00) << 8)
        | ((value & 0x000000FF) << 24)
    )

def is_little_endian() -> bool:
    """Check system endianness at runtime."""
    return sys.byteorder == "little"

def net_to_host_16(net_value: int) -> int:
    """Convert 16-bit value from network byte order (big-endian) to host byte order."""
    return swap_bytes_16(net_value) if is_little_endian() else (net_value & 0xFFFF)

def net_to_host_32(net_value: int) -> int:
    """Convert 32-bit value from network byte order (big-endian) to host byte order."""
    return swap_bytes_32(net_value) if is_little_endian() else (net_value & 0xFFFFFFFF)

def host_to_net_16(host_value: int) -> int:
    """Convert 16-bit value from host byte order to network byte order."""
    return net_to_host_16(host_value)

def host_to_net_32(host_value: int) -> int:
    """Convert 32-bit value from host byte order to network byte order."""
    return net_to_host_32(host_value)