"""
Thread-Based Flow Hash Load Balancer.
File: src/load_balancer.py

In high-speed DPI systems, packets arrive in arbitrary order. To analyze multi-packet
protocols (like TCP handshakes or TLS SNI exchanges) without thread concurrency issues
or lock contention, all packets belonging to the same flow must be processed by the
EXACT same worker core.

The Load Balancer guarantees this using Consistent 5-Tuple Canonical Hashing:
  hash(tuple.canonical()) % num_fps

Both client->server and server->client packets yield the identical canonical hash,
ensuring zero race conditions and lock-free connection tracking.
"""

from dataclasses import dataclass
import threading
from typing import List, Optional

from thread_safe_queue import ThreadSafeQueue
from types_dpi import FiveTuple, PacketJob


# ============================================================================
# LOAD BALANCER METRICS
# ============================================================================

@dataclass
class LBStats:
    """Traffic distribution metrics for a Load Balancer instance."""
    packets_received: int
    packets_dispatched: int
    per_fp_packets: List[int]


# ============================================================================
# LOAD BALANCER WORKER
# ============================================================================

class LoadBalancer:
    """
    Distributes incoming packets from the reader to a pool of Fast Path workers.
    Operates on its own background thread.
    """

    def __init__(
        self,
        lb_id: int,
        fp_queues: List[ThreadSafeQueue[PacketJob]],
        fp_start_id: int,
    ):
        self.lb_id = lb_id
        self.fp_start_id = fp_start_id
        self.num_fps = len(fp_queues)
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(10000)
        self.fp_queues = fp_queues
        self.per_fp_counts = [0] * self.num_fps

        self.packets_received = 0
        self.packets_dispatched = 0
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def __del__(self):
        self.stop()

    def start(self) -> None:
        """Launch Load Balancer thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, name=f"LB-{self.lb_id}", daemon=True)
        self._thread.start()
        print(
            f"[LB{self.lb_id}] Started (routing to FP{self.fp_start_id}..FP{self.fp_start_id + self.num_fps - 1})"
        )

    def stop(self) -> None:
        """Signal stop, shutdown input queue, and join thread."""
        if not self.running:
            return
        self.running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join()
        print(f"[LB{self.lb_id}] Stopped (dispatched {self.packets_dispatched} packets)")

    def _run(self) -> None:
        """Main dispatch loop: pops from input queue and pushes to selected FP queue."""
        while self.running or not self.input_queue.empty():
            job = self.input_queue.pop_with_timeout(0.05)
            if job is None:
                continue

            self.packets_received += 1
            fp_index = self.select_fp(job.tuple)
            self.fp_queues[fp_index].push(job)
            self.packets_dispatched += 1
            self.per_fp_counts[fp_index] += 1

    def select_fp(self, tuple_key: FiveTuple) -> int:
        """
        Hash the canonical 5-tuple to select destination Fast Path queue.
        Guarantees bidirectional flow affinity.
        """
        return abs(hash(tuple_key.canonical())) % self.num_fps

    def get_stats(self) -> LBStats:
        """Return load balancing distribution snapshot."""
        return LBStats(
            packets_received=self.packets_received,
            packets_dispatched=self.packets_dispatched,
            per_fp_packets=list(self.per_fp_counts),
        )

    def is_running(self) -> bool:
        """Check if worker is currently active."""
        return self.running


# ============================================================================
# LOAD BALANCER MANAGER
# ============================================================================

class LBManager:
    """Orchestrates multiple Load Balancers partitioning a large Fast Path thread pool."""

    def __init__(
        self,
        num_lbs: int,
        fps_per_lb: int,
        fp_queues: List[ThreadSafeQueue[PacketJob]],
    ):
        self.fps_per_lb = fps_per_lb
        self.lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            start = lb_id * fps_per_lb
            assigned_queues = fp_queues[start : start + fps_per_lb]
            self.lbs.append(LoadBalancer(lb_id, assigned_queues, start))

        print(f"[LBManager] Created {num_lbs} Load Balancers ({fps_per_lb} FP cores each)")

    def __del__(self):
        self.stop_all()

    def start_all(self) -> None:
        """Start all Load Balancer threads."""
        for lb in self.lbs:
            lb.start()

    def stop_all(self) -> None:
        """Stop all Load Balancer threads and drain queues."""
        for lb in self.lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_key: FiveTuple) -> LoadBalancer:
        """Route packet to appropriate Load Balancer using canonical flow hash."""
        lb_index = abs(hash(tuple_key.canonical())) % len(self.lbs)
        return self.lbs[lb_index]

    def get_lb(self, lb_id: int) -> LoadBalancer:
        """Retrieve Load Balancer by index."""
        return self.lbs[lb_id]

    def get_num_lbs(self) -> int:
        """Number of active Load Balancers."""
        return len(self.lbs)

    def get_aggregated_stats(self) -> dict:
        """Aggregate packet dispatch metrics across all Load Balancers."""
        return {
            "total_received": sum(lb.packets_received for lb in self.lbs),
            "total_dispatched": sum(lb.packets_dispatched for lb in self.lbs),
        }