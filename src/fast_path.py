"""
Fast Path (FP) Inspection Core.
File: src/fast_path.py

The Fast Path is the analytical heart of the DPI Engine. Each worker thread runs an
independent FastPathProcessor that performs:
  1. Connection tracking & TCP state machine updates
  2. Deep payload inspection (TLS ClientHello SNI, HTTP Host, DNS query)
  3. Layer-7 Application Classification
  4. Policy enforcement against RuleManager (IP, App, Domain, Port blocking)
  5. Action dispatch (FORWARD vs DROP) to output pipeline
"""

from dataclasses import dataclass
import threading
import time
from typing import Callable, List, Optional

from connection_tracker import Connection, ConnectionTracker
from rule_manager import RuleManager
from sni_extractor import DNSExtractor, HTTPHostExtractor, SNIExtractor
from thread_safe_queue import ThreadSafeQueue
from types_dpi import (
    AppType,
    ConnectionState,
    PacketAction,
    PacketJob,
    app_type_to_string,
    sni_to_app_type,
)

PacketOutputCallback = Callable[[PacketJob, PacketAction], None]


# ============================================================================
# FAST PATH WORKER STATISTICS
# ============================================================================

@dataclass
class FPStats:
    """Performance & analytical metrics for an individual Fast Path core."""
    packets_processed: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0
    connections_tracked: int = 0
    sni_extractions: int = 0
    classification_hits: int = 0


# ============================================================================
# FAST PATH PROCESSOR (SINGLE WORKER CORE)
# ============================================================================

class FastPathProcessor:
    """
    Dedicated worker core running on its own OS thread.
    Pulls packets from its private input queue and runs Layer 2-7 inspection.
    """

    def __init__(
        self,
        fp_id: int,
        rule_manager: Optional[RuleManager],
        output_callback: PacketOutputCallback,
    ):
        self.fp_id = fp_id
        self.rule_manager = rule_manager
        self.output_callback = output_callback
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self.conn_tracker = ConnectionTracker(fp_id)

        # Counters
        self.packets_processed = 0
        self.packets_forwarded = 0
        self.packets_dropped = 0
        self.sni_extractions = 0
        self.classification_hits = 0

        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Launch worker thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, name=f"FP-{self.fp_id}", daemon=True)
        self._thread.start()
        print(f"[FP{self.fp_id}] Core started")

    def stop(self) -> None:
        """Signal worker to stop, gracefully drain queue, and join thread."""
        if not self.running:
            return
        self.running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join()
        print(f"[FP{self.fp_id}] Stopped (processed {self.packets_processed} packets)")

    def _run(self) -> None:
        """Main processing loop. Continues until stopped and queue is fully drained."""
        while self.running or not self.input_queue.empty():
            job = self.input_queue.pop_with_timeout(0.05)
            if job is None:
                if self.running:
                    self.conn_tracker.cleanup_stale(300.0)
                continue

            self.packets_processed += 1
            action = self.process_packet(job)
            job.action = action

            if self.output_callback:
                self.output_callback(job, action)

            if action == PacketAction.DROP:
                self.packets_dropped += 1
            else:
                self.packets_forwarded += 1

    def process_packet(self, job: PacketJob) -> PacketAction:
        """
        Full inspection workflow for an individual packet:
        Step 1: Retrieve or create connection record
        Step 2: Track packet direction & TCP state flags
        Step 3: If already blocked, immediately DROP
        Step 4: Deep inspection if connection is unclassified
        Step 5: Check policy rules & make decision
        """
        # Step 1: Flow record
        conn = self.conn_tracker.get_or_create_connection(job.tuple)

        # Step 2: Directional accounting (outbound vs inbound)
        is_outbound = (
            job.tuple.src_ip == conn.tuple.src_ip and job.tuple.src_port == conn.tuple.src_port
        )
        self.conn_tracker.update_connection(conn, len(job.raw_bytes), is_outbound=is_outbound)

        # TCP state machine updates
        if job.tuple.protocol == 6:
            self.update_tcp_state(conn, job.tcp_flags)

        # Step 3: Fast drop if flow is already blocked
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        # Step 4: Layer 7 Deep Packet Inspection
        if conn.state != ConnectionState.CLASSIFIED and len(job.payload) > 0:
            self.inspect_payload(job, conn)

        # Step 5: Rule evaluation
        return self.check_rules(job, conn)

    def inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        """
        Deep packet payload inspection:
        - TLS Client Hello: extract Server Name Indication (SNI)
        - HTTP/1.1 Request: extract 'Host:' header
        - DNS Query: extract queried domain name
        - Port heuristic fallback
        """
        if not job.payload:
            return

        # 1. TLS SNI Inspection (Port 443 or general TLS payload)
        if self.try_extract_sni(job, conn):
            return

        # 2. HTTP Host Inspection (Port 80 or cleartext HTTP methods)
        if self.try_extract_http_host(job, conn):
            return

        # 3. DNS Query Inspection (Port 53)
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(job.payload)
            if domain:
                self.conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # 4. Port fallback classification
        if job.tuple.dst_port == 80 or job.tuple.src_port == 80:
            self.conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443 or job.tuple.src_port == 443:
            self.conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def try_extract_sni(self, job: PacketJob, conn: Connection) -> bool:
        """Extract TLS Server Name Indication (SNI) from TLS ClientHello."""
        if job.tuple.dst_port != 443 and len(job.payload) < 40:
            return False

        sni = SNIExtractor.extract(job.payload)
        if sni:
            self.sni_extractions += 1
            app = sni_to_app_type(sni)
            self.conn_tracker.classify_connection(conn, app, sni)
            if app not in (AppType.UNKNOWN, AppType.HTTPS):
                self.classification_hits += 1
            return True
        return False

    def try_extract_http_host(self, job: PacketJob, conn: Connection) -> bool:
        """Extract HTTP Host header from HTTP request."""
        if job.tuple.dst_port != 80 and not HTTPHostExtractor.is_http_request(job.payload, len(job.payload)):
            return False

        host = HTTPHostExtractor.extract(job.payload)
        if host:
            app = sni_to_app_type(host)
            self.conn_tracker.classify_connection(conn, app, host)
            if app not in (AppType.UNKNOWN, AppType.HTTP):
                self.classification_hits += 1
            return True
        return False

    def check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        """Query RuleManager to determine if packet should be permitted or dropped."""
        if not self.rule_manager:
            return PacketAction.FORWARD

        block_reason = self.rule_manager.should_block(
            job.tuple.src_ip, job.tuple.dst_port, conn.app_type, conn.sni
        )
        if block_reason:
            print(f"[FP{self.fp_id}] BLOCKED packet: {block_reason}")
            self.conn_tracker.block_connection(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    @staticmethod
    def update_tcp_state(conn: Connection, tcp_flags: int) -> None:
        """Track standard TCP state transitions based on control flags."""
        SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04

        if tcp_flags & SYN:
            if tcp_flags & ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & FIN:
            conn.fin_seen = True
        if tcp_flags & RST:
            conn.state = ConnectionState.CLOSED
        if conn.fin_seen and (tcp_flags & ACK):
            conn.state = ConnectionState.CLOSED

    def get_stats(self) -> FPStats:
        """Return snapshot of worker performance metrics."""
        return FPStats(
            packets_processed=self.packets_processed,
            packets_forwarded=self.packets_forwarded,
            packets_dropped=self.packets_dropped,
            connections_tracked=self.conn_tracker.get_active_count(),
            sni_extractions=self.sni_extractions,
            classification_hits=self.classification_hits,
        )


# ============================================================================
# FAST PATH MANAGER (ORCHESTRATOR FOR ALL FP WORKER CORES)
# ============================================================================

class FPManager:
    """Manages the lifecycle and metrics of all FastPathProcessor worker threads."""

    def __init__(
        self,
        num_fps: int,
        rule_manager: Optional[RuleManager],
        output_callback: PacketOutputCallback,
    ):
        self.fps = [
            FastPathProcessor(i, rule_manager, output_callback) for i in range(num_fps)
        ]
        print(f"[FPManager] Initialized {num_fps} Fast Path worker cores")

    def start_all(self) -> None:
        """Start all worker threads."""
        for fp in self.fps:
            fp.start()

    def stop_all(self) -> None:
        """Stop all worker threads and drain queues."""
        for fp in self.fps:
            fp.stop()

    def get_fp(self, idx: int) -> FastPathProcessor:
        """Get worker processor by ID."""
        return self.fps[idx]

    def get_queue_ptrs(self) -> List[ThreadSafeQueue[PacketJob]]:
        """Return references to all worker input queues."""
        return [fp.input_queue for fp in self.fps]

    def get_num_fps(self) -> int:
        """Total number of worker cores."""
        return len(self.fps)

    def get_aggregated_stats(self) -> dict:
        """Aggregate totals across all worker cores."""
        return {
            "total_processed": sum(fp.packets_processed for fp in self.fps),
            "total_forwarded": sum(fp.packets_forwarded for fp in self.fps),
            "total_dropped": sum(fp.packets_dropped for fp in self.fps),
            "total_connections": sum(fp.conn_tracker.get_active_count() for fp in self.fps),
            "total_sni_extracted": sum(fp.sni_extractions for fp in self.fps),
        }

    def generate_classification_report(self) -> str:
        """ASCII formatted summary of classified applications."""
        app_counts: dict = {}
        total_classified = 0
        total_unknown = 0

        for fp in self.fps:
            def aggregate(conn: Connection) -> None:
                nonlocal total_classified, total_unknown
                app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + 1
                if conn.app_type == AppType.UNKNOWN:
                    total_unknown += 1
                else:
                    total_classified += 1

            fp.conn_tracker.for_each(aggregate)

        total = total_classified + total_unknown
        c_pct = (100.0 * total_classified / total) if total > 0 else 0.0
        u_pct = (100.0 * total_unknown / total) if total > 0 else 0.0

        lines = [
            "",
            "+--------------------------------------------------------------+",
            "|               APPLICATION CLASSIFICATION REPORT              |",
            "+--------------------------------------------------------------+",
            f"| Total Connections:    {total:>10}                             |",
            f"| Classified:           {total_classified:>10} ({c_pct:>5.1f}%)                    |",
            f"| Unidentified:         {total_unknown:>10} ({u_pct:>5.1f}%)                    |",
            "+--------------------------------------------------------------+",
            "|                    APPLICATION BREAKDOWN                     |",
            "+--------------------------------------------------------------+",
        ]

        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            bar = "#" * int(pct / 5)
            lines.append(
                f"| {app_type_to_string(app):<16} {count:>8} {pct:>5.1f}% {bar:<22} |"
            )

        lines.append("+--------------------------------------------------------------+\n")
        return "\n".join(lines)