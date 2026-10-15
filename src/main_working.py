"""
Simplified, Self-Contained Single-Threaded DPI Filter.
File: src/main_working.py

This is a lightweight reference implementation of the Deep Packet Inspection
pipeline without multi-threading, ideal for studying and debugging.
"""

from dataclasses import dataclass
import socket
import struct
import sys
from typing import Dict, List, Set

from packet_parser import PacketParser
from pcap_reader import PcapReader
from sni_extractor import HTTPHostExtractor, SNIExtractor
from types_dpi import (
    AppType,
    FiveTuple,
    app_type_to_string,
    ip_to_str,
    sni_to_app_type,
    str_to_ip,
    string_to_app_type,
)


@dataclass
class Flow:
    """Connection flow state tracked during single-threaded inspection."""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class BlockingRules:
    """Simple policy rule engine for the standalone runner."""
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def block_ip(self, ip_str: str) -> None:
        addr = str_to_ip(ip_str)
        self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip_str}")

    def block_app(self, app_str: str) -> None:
        app = string_to_app_type(app_str)
        if app != AppType.UNKNOWN:
            self.blocked_apps.add(app)
            print(f"[Rules] Blocked app: {app_type_to_string(app)}")
        else:
            print(f"[Rules] Unknown app: {app_str}", file=sys.stderr)

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain.strip().lower())
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        if sni:
            s = sni.lower()
            for dom in self.blocked_domains:
                clean_dom = dom.replace("*.", "")
                if clean_dom in s:
                    return True
        return False


def main():
    if len(sys.argv) < 3:
        print("Usage: python main_working.py <input.pcap> <output.pcap> [options]")
        print("Options: --block-ip <ip>, --block-app <app>, --block-domain <dom>")
        return

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    rules = BlockingRules()

    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            rules.block_ip(sys.argv[i + 1])
            i += 2
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            rules.block_app(sys.argv[i + 1])
            i += 2
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            rules.block_domain(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    reader = PcapReader()
    if not reader.open(input_file):
        print(f"Error opening {input_file}", file=sys.stderr)
        return

    try:
        output = open(output_file, "wb")
    except IOError as err:
        print(f"Error opening output {output_file}: {err}", file=sys.stderr)
        reader.close()
        return

    if reader.global_header:
        gh = reader.global_header
        output.write(
            struct.pack(
                "=IHHiIII",
                gh.magic_number, gh.version_major, gh.version_minor,
                gh.thiszone, gh.sigfigs, gh.snaplen, gh.network,
            )
        )

    flows: Dict[FiveTuple, Flow] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = {}

    print("[DPI] Processing packets...")
    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        total_packets += 1
        parsed = PacketParser.parse(raw)
        if not parsed or not parsed.has_ip:
            continue
        if not parsed.has_tcp and not parsed.has_udp:
            continue

        tuple_key = FiveTuple(
            parsed.src_ip_int, parsed.dest_ip_int, parsed.src_port, parsed.dest_port, parsed.protocol
        )

        canon = tuple_key.canonical()
        if canon not in flows:
            flows[canon] = Flow(tuple=tuple_key)
        flow = flows[canon]
        flow.packets += 1
        flow.bytes += len(raw.data)

        # Offsets
        ip_ihl = (raw.data[14] & 0x0F) * 4
        trans_offset = 14 + ip_ihl

        # TLS SNI
        if (
            (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS))
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 443
        ):
            tcp_offset = ((raw.data[trans_offset + 12] >> 4) & 0x0F) * 4
            pay_offset = trans_offset + tcp_offset
            if pay_offset < len(raw.data):
                payload = raw.data[pay_offset:]
                sni = SNIExtractor.extract(payload)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

        # HTTP Host
        if (
            (flow.app_type in (AppType.UNKNOWN, AppType.HTTP))
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 80
        ):
            tcp_offset = ((raw.data[trans_offset + 12] >> 4) & 0x0F) * 4
            pay_offset = trans_offset + tcp_offset
            if pay_offset < len(raw.data):
                payload = raw.data[pay_offset:]
                host = HTTPHostExtractor.extract(payload)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 53 or parsed.src_port == 53:
                flow.app_type = AppType.DNS
            elif parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_key.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                info = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}{info})")

        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            hdr = struct.pack("=IIII", raw.header.ts_sec, raw.header.ts_usec, len(raw.data), raw.header.orig_len)
            output.write(hdr + raw.data)

    reader.close()
    output.close()

    print("\n+--------------------------------------------------------------+")
    print("|                      PROCESSING REPORT                       |")
    print("+--------------------------------------------------------------+")
    print(f"| Total Packets:      {total_packets:>10}                               |")
    print(f"| Forwarded:          {forwarded:>10}                               |")
    print(f"| Dropped:            {dropped:>10}                               |")
    print(f"| Active Flows:       {len(flows):>10}                               |")
    print("+--------------------------------------------------------------+")
    print("|                    APPLICATION BREAKDOWN                     |")
    print("+--------------------------------------------------------------+")

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0
        bar = "#" * int(pct / 5)
        print(f"| {app_type_to_string(app):<15} {count:>8} {pct:>5.1f}% {bar:<20}    |")
    print("+--------------------------------------------------------------+")

    print("\nSanitized output written to: " + output_file)


if __name__ == "__main__":
    main()