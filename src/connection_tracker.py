"""
Connection Tracking and Flow Table Maintenance.
File: src/connection_tracker.py

A network "flow" is a bidirectional sequence of packets between two endpoints,
identified by its 5-tuple: (Source IP, Destination IP, Source Port, Dest Port, Protocol).

This module manages:
  - Per-worker flow tables (FastPath worker threads track their assigned connections)
  - Connection lifecycle states (NEW -> ESTABLISHED -> CLASSIFIED -> BLOCKED / CLOSED)
  - Accurate bidirectional packet & byte counters (inbound vs outbound)
  - Global flow aggregator for generating system-wide DPI statistics
"""

from dataclasses import dataclass, field
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from types_dpi import (
    AppType,
    ConnectionState,
    FiveTuple,
    PacketAction,
    app_type_to_string,
    ip_to_str,
    sni_to_app_type,
    str_to_ip,
)


# ============================================================================
# CONNECTION (FLOW RECORD)
# ============================================================================

@dataclass
class Connection:
    """
    State record for an active bidirectional network session.
    Created when the first packet of a conversation is observed.
    """
    tuple: FiveTuple                              # Initial 5-tuple (client -> server)
    state: ConnectionState = ConnectionState.NEW
    action: PacketAction = PacketAction.FORWARD
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""                                 # Extracted domain or hostname
    packets_in: int = 0                           # Inbound packets (server -> client)
    packets_out: int = 0                          # Outbound packets (client -> server)
    bytes_in: int = 0                             # Inbound bytes
    bytes_out: int = 0                            # Outbound bytes
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    @property
    def total_packets(self) -> int:
        """Total packet count across both directions."""
        return self.packets_in + self.packets_out

    @property
    def total_bytes(self) -> int:
        """Total byte volume across both directions."""
        return self.bytes_in + self.bytes_out

    @property
    def duration_sec(self) -> float:
        """Active connection duration in seconds."""
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class TrackerStats:
    """Statistics for an individual Fast Path worker's connection tracker."""
    active_connections: int = 0
    total_connections_seen: int = 0
    classified_connections: int = 0
    blocked_connections: int = 0


# ============================================================================
# PER-WORKER CONNECTION TRACKER
# ============================================================================

class ConnectionTracker:
    """
    Flow table dedicated to a single Fast Path core.
    Because each 5-tuple flow is deterministically routed by the Load Balancer
    to the exact same FastPath core, this table operates thread-locally without
    needing expensive cross-thread locks during packet processing.
    """

    def __init__(self, fp_id: int, max_connections: int = 100000):
        self.fp_id = fp_id
        self.max_connections = max_connections
        # Keyed by canonical FiveTuple so forward and reverse packets match the same record
        self._connections: Dict[FiveTuple, Connection] = {}
        self._total_seen = 0
        self._classified_count = 0
        self._blocked_count = 0

    def get_or_create_connection(self, tuple_key: FiveTuple) -> Connection:
        """
        Find existing connection or create a new one.
        Uses canonical tuple to ensure bidirectional matching.
        """
        canon = tuple_key.canonical()
        if canon in self._connections:
            return self._connections[canon]

        # Enforce memory safety cap
        if len(self._connections) >= self.max_connections:
            self.evict_oldest()

        conn = Connection(tuple=tuple_key)
        self._connections[canon] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_key: FiveTuple) -> Optional[Connection]:
        """Lookup active connection by 5-tuple."""
        return self._connections.get(tuple_key.canonical())

    def update_connection(
        self, conn: Optional[Connection], packet_size: int, is_outbound: bool
    ) -> None:
        """
        Update flow statistics upon receiving a packet.
        - is_outbound = True: Client -> Server
        - is_outbound = False: Server -> Client
        """
        if conn is None:
            return

        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(
        self, conn: Optional[Connection], app: AppType, sni: str = ""
    ) -> None:
        """Tag connection with its identified Layer-7 application."""
        if conn is None:
            return

        conn.app_type = app
        if sni:
            conn.sni = sni
        conn.state = ConnectionState.CLASSIFIED
        self._classified_count += 1

    def block_connection(self, conn: Optional[Connection]) -> None:
        """Mark flow as blocked so subsequent packets are dropped immediately."""
        if conn is None:
            return
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_key: FiveTuple) -> None:
        """Mark connection as closed (TCP FIN or RST observed)."""
        conn = self.get_connection(tuple_key)
        if conn:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        """Remove idle or closed connections to free memory."""
        now = time.monotonic()
        stale_keys = [
            k for k, c in self._connections.items()
            if (now - c.last_seen > timeout_seconds) or c.state == ConnectionState.CLOSED
        ]
        for k in stale_keys:
            del self._connections[k]
        return len(stale_keys)

    def get_all_connections(self) -> List[Connection]:
        """Return snapshot of all currently tracked connections."""
        return list(self._connections.values())

    def get_active_count(self) -> int:
        """Number of currently tracked connections."""
        return len(self._connections)

    def get_stats(self) -> TrackerStats:
        """Return summary stats."""
        return TrackerStats(
            active_connections=len(self._connections),
            total_connections_seen=self._total_seen,
            classified_connections=self._classified_count,
            blocked_connections=self._blocked_count,
        )

    def clear(self) -> None:
        """Wipe all active connections."""
        self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        """Execute a callback for every connection."""
        for c in list(self._connections.values()):
            callback(c)

    def evict_oldest(self) -> None:
        """Evict the least-recently seen connection when table is full."""
        if not self._connections:
            return
        oldest_key = min(self._connections.keys(), key=lambda k: self._connections[k].last_seen)
        del self._connections[oldest_key]


# ============================================================================
# GLOBAL CONNECTION TABLE (CROSS-WORKER AGGREGATOR)
# ============================================================================

@dataclass
class GlobalStats:
    """Aggregated statistics across all worker threads."""
    total_active_connections: int = 0
    total_connections_seen: int = 0
    app_distribution: Dict[AppType, int] = field(default_factory=dict)
    top_domains: List[Tuple[str, int]] = field(default_factory=list)


class GlobalConnectionTable:
    """
    Coordinates and aggregates connection metrics from all FastPath workers.
    Used by CLI reports and Streamlit dashboard to display system-wide views.
    """

    def __init__(self, num_fps: int):
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.Lock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        """Register a worker's connection tracker."""
        with self._lock:
            if fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    def get_global_stats(self) -> GlobalStats:
        """Aggregate stats across all registered workers."""
        with self._lock:
            stats = GlobalStats()
            domain_counts: Dict[str, int] = {}

            for tracker in self._trackers:
                if not tracker:
                    continue
                t_stats = tracker.get_stats()
                stats.total_active_connections += t_stats.active_connections
                stats.total_connections_seen += t_stats.total_connections_seen

                def aggregate(conn: Connection) -> None:
                    stats.app_distribution[conn.app_type] = (
                        stats.app_distribution.get(conn.app_type, 0) + 1
                    )
                    if conn.sni:
                        domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

                tracker.for_each(aggregate)

            # Sort top domains by hits descending
            sorted_domains = sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)
            stats.top_domains = sorted_domains[:25]
            return stats

    def generate_report(self) -> str:
        """ASCII formatted summary of connection statistics."""
        stats = self.get_global_stats()
        lines = [
            "",
            "+--------------------------------------------------------------+",
            "|               CONNECTION STATISTICS REPORT                   |",
            "+--------------------------------------------------------------+",
            f"| Active Connections:     {stats.total_active_connections:>10}                          |",
            f"| Total Connections Seen: {stats.total_connections_seen:>10}                          |",
            "+--------------------------------------------------------------+",
            "|                    APPLICATION BREAKDOWN                     |",
            "+--------------------------------------------------------------+",
        ]

        total = sum(stats.app_distribution.values())
        sorted_apps = sorted(stats.app_distribution.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            app_str = app_type_to_string(app)
            bar = "#" * int(pct / 5)
            lines.append(f"| {app_str:<18} {count:>8} ({pct:>5.1f}%) {bar:<18} |")

        if stats.top_domains:
            lines.extend([
                "+--------------------------------------------------------------+",
                "|                      TOP DOMAINS / SNIS                      |",
                "+--------------------------------------------------------------+",
            ])
            for domain, count in stats.top_domains:
                display_dom = domain if len(domain) <= 35 else domain[:32] + "..."
                lines.append(f"| {display_dom:<40} {count:>10}       |")

        lines.append("+--------------------------------------------------------------+\n")
        return "\n".join(lines)