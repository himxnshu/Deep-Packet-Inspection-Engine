"""
Main DPI Engine Orchestrator.
File: src/dpi_engine.py

Orchestrates the multi-threaded DPI pipeline:
  [PCAP Reader] 
        ↓  (PacketJob)
  [LBManager: Load Balancer Pool]
        ↓  (Consistent 5-Tuple Canonical Hash Dispatch)
  [FPManager: Fast Path Inspection Cores]
        ↓  (Connection Tracking, SNI Extraction, Rule Policy Check)
  [OutputWriter Thread]
        ↓  (Sanitized Output PCAP)
"""

from dataclasses import dataclass
import socket
import struct
import threading
import time
from typing import BinaryIO, Optional, Union

from connection_tracker import ConnectionTracker, GlobalConnectionTable
from fast_path import FPManager
from load_balancer import LBManager
from packet_parser import PacketParser
from pcap_reader import PcapGlobalHeader, PcapReader
from rule_manager import RuleManager
from thread_safe_queue import ThreadSafeQueue
from types_dpi import (
    AppType,
    FiveTuple,
    PacketAction,
    PacketJob,
    app_type_to_string,
    ip_to_str,
    str_to_ip,
    string_to_app_type,
)


# ============================================================================
# CONFIGURATION & GLOBAL ENGINE METRICS
# ============================================================================

@dataclass
class EngineConfig:
    """Configuration options for the DPI Engine."""
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    queue_size: int = 10000
    rules_file: str = ""
    verbose: bool = False


class DPIStats:
    """Cumulative packet and byte counters across the pipeline."""
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0


# ============================================================================
# DPI ENGINE
# ============================================================================

class DPIEngine:
    """
    Central coordinator of the Deep Packet Inspection system.
    Manages worker threads, policy rules, and streaming PCAP processing.
    """

    def __init__(self, config: EngineConfig):
        self.config = config
        self.stats = DPIStats()
        self.rule_manager = RuleManager()
        self.output_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(config.queue_size)
        self.output_file: Optional[BinaryIO] = None
        self.output_mutex = threading.Lock()

        # Initialize thread pools
        total_fps = config.num_load_balancers * config.fps_per_lb
        self.fp_manager = FPManager(total_fps, self.rule_manager, self.handle_output)
        self.lb_manager = LBManager(
            config.num_load_balancers, config.fps_per_lb, self.fp_manager.get_queue_ptrs()
        )
        self.global_conn_table = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self.global_conn_table.register_tracker(i, self.fp_manager.get_fp(i).conn_tracker)

        self.running = False
        self.reader_thread: Optional[threading.Thread] = None
        self.output_thread: Optional[threading.Thread] = None

        print("\n+--------------------------------------------------------------+")
        print("|                    DPI ENGINE v1.0                           |")
        print("|             Deep Packet Inspection System                    |")
        print("+--------------------------------------------------------------+")
        print(f"| Configuration:                                               |")
        print(f"|   Load Balancers:    {config.num_load_balancers:>3}                                     |")
        print(f"|   FPs per LB:        {config.fps_per_lb:>3}                                     |")
        print(f"|   Total FP Cores:    {total_fps:>3}                                     |")
        print("+--------------------------------------------------------------+\n")

    def initialize(self) -> bool:
        """Load external rules file if configured."""
        if self.config.rules_file:
            self.rule_manager.load_rules(self.config.rules_file)
        print("[DPIEngine] Initialized successfully")
        return True

    def start(self) -> None:
        """Start output writer, Fast Path workers, and Load Balancer threads."""
        if self.running:
            return
        self.running = True

        # 1. Start output writer thread
        self.output_thread = threading.Thread(
            target=self._output_thread_func, name="OutputWriter", daemon=True
        )
        self.output_thread.start()

        # 2. Start workers
        self.fp_manager.start_all()
        self.lb_manager.start_all()
        print("[DPIEngine] All pipeline worker threads started")

    def stop(self) -> None:
        """Gracefully stop all worker threads and close output file."""
        if not self.running:
            return
        self.running = False

        if self.lb_manager:
            self.lb_manager.stop_all()
        if self.fp_manager:
            self.fp_manager.stop_all()

        self.output_queue.shutdown()
        if self.output_thread and self.output_thread.is_alive():
            self.output_thread.join()

        with self.output_mutex:
            if self.output_file and not self.output_file.closed:
                self.output_file.close()

        print("[DPIEngine] All pipeline threads stopped")

    def wait_for_completion(self) -> None:
        """Wait for the reader thread and all pending queue items to drain."""
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join()

        # Poll until all intermediate queues are completely empty
        deadline = time.time() + 15.0
        while time.time() < deadline:
            lb_pending = sum(lb.input_queue.size() for lb in self.lb_manager.lbs)
            fp_pending = sum(fp.input_queue.size() for fp in self.fp_manager.fps)
            out_pending = self.output_queue.size()
            if lb_pending == 0 and fp_pending == 0 and out_pending == 0:
                break
            time.sleep(0.02)

        # Allow output writer to flush final packets to disk
        time.sleep(0.05)

    def process_file(self, input_file: str, output_file: str) -> bool:
        """
        Execute full inspection on a PCAP file:
        Reads input, filters blocked packets, and writes permitted packets to output.
        """
        print(f"\n[DPIEngine] Processing Input:  {input_file}")
        print(f"[DPIEngine] Writing Output to: {output_file}\n")

        try:
            self.output_file = open(output_file, "wb")
        except IOError as err:
            print(f"[DPIEngine] Error opening output file: {err}")
            return False

        self.start()
        self.reader_thread = threading.Thread(
            target=self._reader_thread_func, args=(input_file,), daemon=True
        )
        self.reader_thread.start()

        self.wait_for_completion()
        self.stop()

        print(self.generate_report())
        print(self.fp_manager.generate_classification_report())
        return True

    def _reader_thread_func(self, input_file: str) -> None:
        """Reads PCAP file packet-by-packet and dispatches to Load Balancers."""
        reader = PcapReader()
        if not reader.open(input_file):
            print("[Reader] Error: Cannot open input PCAP file")
            return

        # Write sanitized PCAP global header to output file
        if reader.global_header:
            self._write_output_header(reader.global_header)

        print("[Reader] Reading and dispatching packets...")
        packet_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = PacketParser.parse(raw)
            if not parsed or not parsed.has_ip:
                continue
            if not parsed.has_tcp and not parsed.has_udp:
                continue

            packet_id += 1

            # Construct PacketJob container
            job = PacketJob(
                packet_id=packet_id,
                ts_sec=parsed.timestamp_sec,
                ts_usec=parsed.timestamp_usec,
                raw_bytes=bytes(raw.data),
                tuple=FiveTuple(
                    src_ip=parsed.src_ip_int,
                    dst_ip=parsed.dest_ip_int,
                    src_port=parsed.src_port,
                    dst_port=parsed.dest_port,
                    protocol=parsed.protocol,
                ),
                payload=parsed.payload,
                tcp_flags=parsed.tcp_flags,
                orig_len=raw.header.orig_len,
            )

            # Update engine counters
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            # Route to Load Balancer via 5-tuple hash
            lb = self.lb_manager.get_lb_for_packet(job.tuple)
            lb.input_queue.push(job)

        print(f"[Reader] Finished dispatching {packet_id} packets")
        reader.close()

    def _output_thread_func(self) -> None:
        """Pulls permitted packets from output queue and writes them to sanitized PCAP."""
        while self.running or not self.output_queue.empty():
            job = self.output_queue.pop_with_timeout(0.05)
            if job:
                self._write_output_packet(job)

    def handle_output(self, job: PacketJob, action: PacketAction) -> None:
        """
        Callback invoked by Fast Path worker when an inspection decision is made.
        - DROP: Increment dropped counter, discard packet.
        - FORWARD: Increment forwarded counter, push packet to output writer.
        """
        if action == PacketAction.DROP:
            self.stats.dropped_packets += 1
        else:
            self.stats.forwarded_packets += 1
            self.output_queue.push(job)

    def _write_output_header(self, gh: PcapGlobalHeader) -> bool:
        """Write standard 24-byte PCAP global header."""
        with self.output_mutex:
            if not self.output_file:
                return False
            data = struct.pack(
                "=IHHiIII",
                gh.magic_number, gh.version_major, gh.version_minor,
                gh.thiszone, gh.sigfigs, gh.snaplen, gh.network,
            )
            self.output_file.write(data)
            return True

    def _write_output_packet(self, job: PacketJob) -> None:
        """Write PCAP 16-byte packet header followed by raw packet bytes."""
        with self.output_mutex:
            if not self.output_file:
                return
            hdr = struct.pack("=IIII", job.ts_sec, job.ts_usec, len(job.raw_bytes), job.orig_len)
            self.output_file.write(hdr + job.raw_bytes)

    # ------------------------------------------------------------------------
    # Public Rule Configuration API
    # ------------------------------------------------------------------------
    def block_ip(self, ip: Union[int, str]) -> None:
        self.rule_manager.block_ip(ip)

    def unblock_ip(self, ip: Union[int, str]) -> None:
        self.rule_manager.unblock_ip(ip)

    def block_app(self, app_name: Union[AppType, str]) -> None:
        self.rule_manager.block_app(app_name)

    def unblock_app(self, app: Union[AppType, str]) -> None:
        self.rule_manager.unblock_app(app)

    def block_domain(self, dom: str) -> None:
        self.rule_manager.block_domain(dom)

    def unblock_domain(self, dom: str) -> None:
        self.rule_manager.unblock_domain(dom)

    def block_port(self, port: int) -> None:
        self.rule_manager.block_port(port)

    def unblock_port(self, port: int) -> None:
        self.rule_manager.unblock_port(port)

    def load_rules(self, fname: str) -> bool:
        return self.rule_manager.load_rules(fname)

    def save_rules(self, fname: str) -> bool:
        return self.rule_manager.save_rules(fname)

    # ------------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------------
    def generate_report(self) -> str:
        """Generate formatted ASCII execution summary."""
        lines = [
            "",
            "+--------------------------------------------------------------+",
            "|                    DPI ENGINE STATISTICS                     |",
            "+--------------------------------------------------------------+",
            "| PACKET STATISTICS                                            |",
            f"|   Total Packets:      {self.stats.total_packets:>12}                       |",
            f"|   Total Bytes:        {self.stats.total_bytes:>12}                       |",
            f"|   TCP Packets:        {self.stats.tcp_packets:>12}                       |",
            f"|   UDP Packets:        {self.stats.udp_packets:>12}                       |",
            "+--------------------------------------------------------------+",
            "| FILTERING STATISTICS                                         |",
            f"|   Forwarded:          {self.stats.forwarded_packets:>12}                       |",
            f"|   Dropped/Blocked:    {self.stats.dropped_packets:>12}                       |",
        ]
        if self.stats.total_packets > 0:
            drop_rate = 100.0 * self.stats.dropped_packets / self.stats.total_packets
            lines.append(f"|   Drop Rate:          {drop_rate:>11.2f}%                      |")

        lb_stats = self.lb_manager.get_aggregated_stats()
        lines.extend([
            "+--------------------------------------------------------------+",
            "| LOAD BALANCER STATISTICS                                     |",
            f"|   LB Received:        {lb_stats['total_received']:>12}                       |",
            f"|   LB Dispatched:      {lb_stats['total_dispatched']:>12}                       |",
        ])

        fp_stats = self.fp_manager.get_aggregated_stats()
        lines.extend([
            "+--------------------------------------------------------------+",
            "| FAST PATH STATISTICS                                         |",
            f"|   FP Processed:       {fp_stats['total_processed']:>12}                       |",
            f"|   FP Forwarded:       {fp_stats['total_forwarded']:>12}                       |",
            f"|   FP Dropped:         {fp_stats['total_dropped']:>12}                       |",
            f"|   Active Connections: {fp_stats['total_connections']:>12}                       |",
        ])

        rule_stats = self.rule_manager.get_stats()
        lines.extend([
            "+--------------------------------------------------------------+",
            "| BLOCKING RULES                                               |",
            f"|   Blocked IPs:        {rule_stats.blocked_ips:>12}                       |",
            f"|   Blocked Apps:       {rule_stats.blocked_apps:>12}                       |",
            f"|   Blocked Domains:    {rule_stats.blocked_domains:>12}                       |",
            f"|   Blocked Ports:      {rule_stats.blocked_ports:>12}                       |",
            "+--------------------------------------------------------------+\n",
        ])
        return "\n".join(lines)