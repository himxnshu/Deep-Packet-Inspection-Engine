"""
Thread-Safe Rule Configuration & Traffic Policy Manager.
File: src/rule_manager.py

This module manages the filtering policies enforced by the Fast Path inspection cores:
  - Blocked Source IP Addresses (exact match)
  - Blocked Applications (YouTube, Facebook, Netflix, etc.)
  - Blocked Domains (exact matches and wildcard patterns like '*.google.com')
  - Blocked Destination Ports
  - Rule loading/saving to text configuration files
"""

from dataclasses import dataclass
from enum import Enum, auto
import threading
from typing import List, Optional, Set, Union

from types_dpi import AppType, app_type_to_string, ip_to_str, str_to_ip, string_to_app_type


# ============================================================================
# BLOCK REASON & RULE STATISTICS
# ============================================================================

@dataclass
class BlockReason:
    """Explains why a packet was marked for dropping."""
    class Type(Enum):
        IP = auto()
        APP = auto()
        DOMAIN = auto()
        PORT = auto()

    type: Type
    detail: str

    def __str__(self) -> str:
        return f"{self.type.name}: {self.detail}"


@dataclass
class RuleStats:
    """Summary counts of currently configured rules."""
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


# ============================================================================
# RULE MANAGER ENGINE
# ============================================================================

class RuleManager:
    """
    Central thread-safe repository of all traffic filtering rules.
    Queried concurrently by FastPath worker threads during packet inspection.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._blocked_ips: Set[int] = set()               # Big-endian 32-bit IPv4 integers
        self._blocked_apps: Set[AppType] = set()           # Canonical AppType enums
        self._blocked_domains: Set[str] = set()            # Exact domain strings
        self._domain_patterns: List[str] = []              # Wildcard patterns (e.g. '*.google.com')
        self._blocked_ports: Set[int] = set()              # Destination port numbers

    @staticmethod
    def parse_ip(ip_str: str) -> int:
        """Parse IPv4 string into 32-bit big-endian integer."""
        return str_to_ip(ip_str)

    @staticmethod
    def ip_to_string(ip: int) -> str:
        """Format 32-bit integer into standard IPv4 dotted-decimal string."""
        return ip_to_str(ip)

    # ------------------------------------------------------------------------
    # IP Address Filtering
    # ------------------------------------------------------------------------
    def block_ip(self, ip: Union[int, str]) -> None:
        """Add an IP address to the blocklist."""
        ip_val = str_to_ip(ip) if isinstance(ip, str) else ip
        with self._lock:
            self._blocked_ips.add(ip_val)
        print(f"[RuleManager] Blocked IP: {ip_to_str(ip_val)}")

    def unblock_ip(self, ip: Union[int, str]) -> None:
        """Remove an IP address from the blocklist."""
        ip_val = str_to_ip(ip) if isinstance(ip, str) else ip
        with self._lock:
            self._blocked_ips.discard(ip_val)
        print(f"[RuleManager] Unblocked IP: {ip_to_str(ip_val)}")

    def is_ip_blocked(self, ip: int) -> bool:
        """Check if source IP is in the blocklist."""
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        """Return list of all blocked IPv4 strings."""
        with self._lock:
            return sorted(ip_to_str(ip) for ip in self._blocked_ips)

    # ------------------------------------------------------------------------
    # Application Filtering
    # ------------------------------------------------------------------------
    def block_app(self, app: Union[AppType, str]) -> None:
        """Add an application to the blocklist."""
        if isinstance(app, str):
            app = string_to_app_type(app)
            if app == AppType.UNKNOWN:
                print(f"[RuleManager] Unknown application name: {app}")
                return

        with self._lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked application: {app_type_to_string(app)}")

    def unblock_app(self, app: Union[AppType, str]) -> None:
        """Remove an application from the blocklist."""
        if isinstance(app, str):
            app = string_to_app_type(app)
        with self._lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked application: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        """Check if an application is blocked."""
        with self._lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        """Return list of all blocked AppType enums."""
        with self._lock:
            return list(self._blocked_apps)

    # ------------------------------------------------------------------------
    # Domain / SNI Filtering
    # ------------------------------------------------------------------------
    def block_domain(self, domain: str) -> None:
        """
        Block a domain name. Supports wildcards (e.g. '*.facebook.com').
        """
        clean = domain.strip().lower()
        if not clean:
            return
        with self._lock:
            if "*" in clean:
                if clean not in self._domain_patterns:
                    self._domain_patterns.append(clean)
            else:
                self._blocked_domains.add(clean)
        print(f"[RuleManager] Blocked domain: {clean}")

    def unblock_domain(self, domain: str) -> None:
        """Remove a domain or pattern from the blocklist."""
        clean = domain.strip().lower()
        with self._lock:
            if "*" in clean:
                if clean in self._domain_patterns:
                    self._domain_patterns.remove(clean)
            else:
                self._blocked_domains.discard(clean)
        print(f"[RuleManager] Unblocked domain: {clean}")

    @staticmethod
    def domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Check if a domain matches a wildcard pattern.
        Example: 'www.facebook.com' matches '*.facebook.com' and 'facebook.com' matches '*.facebook.com'
        """
        d = domain.lower()
        p = pattern.lower()

        if p.startswith("*."):
            suffix = p[1:]  # '.facebook.com'
            root = p[2:]    # 'facebook.com'
            if d.endswith(suffix) or d == root:
                return True
        elif p.endswith(".*"):
            prefix = p[:-1] # 'facebook.'
            if d.startswith(prefix):
                return True
        elif p in d:
            return True

        return False

    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain or SNI matches any configured domain rule."""
        if not domain:
            return False

        clean = domain.lower().strip()
        with self._lock:
            # Direct exact match
            if clean in self._blocked_domains:
                return True

            # Wildcard pattern matches
            for pattern in self._domain_patterns:
                if self.domain_matches_pattern(clean, pattern):
                    return True

        return False

    def get_blocked_domains(self) -> List[str]:
        """Return list of all configured domain patterns and exact domains."""
        with self._lock:
            return sorted(list(self._blocked_domains) + list(self._domain_patterns))

    # ------------------------------------------------------------------------
    # Port Filtering
    # ------------------------------------------------------------------------
    def block_port(self, port: int) -> None:
        """Block all traffic destined for a specific port number."""
        with self._lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        """Unblock a port number."""
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        """Check if destination port is blocked."""
        with self._lock:
            return port in self._blocked_ports

    def get_blocked_ports(self) -> List[int]:
        """Return list of blocked ports."""
        with self._lock:
            return sorted(list(self._blocked_ports))

    # ------------------------------------------------------------------------
    # Combined Policy Evaluation (Fast Path Inspection Hook)
    # ------------------------------------------------------------------------
    def should_block(
        self, src_ip: int, dst_port: int, app: AppType, domain: str
    ) -> Optional[BlockReason]:
        """
        Evaluate all policy rules against packet attributes.
        Returns a BlockReason if matched, or None if packet is permitted.
        """
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockReason.Type.IP, ip_to_str(src_ip))

        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReason.Type.PORT, str(dst_port))

        if self.is_app_blocked(app):
            return BlockReason(BlockReason.Type.APP, app_type_to_string(app))

        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReason.Type.DOMAIN, domain)

        return None

    # ------------------------------------------------------------------------
    # Persistence & Maintenance
    # ------------------------------------------------------------------------
    def save_rules(self, filename: str) -> bool:
        """Save active rules to a config file."""
        with self._lock:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("# DPI Engine Policy Rules Configuration\n\n")

                    f.write("[BLOCKED_IPS]\n")
                    for ip_str in self.get_blocked_ips():
                        f.write(f"{ip_str}\n")

                    f.write("\n[BLOCKED_APPS]\n")
                    for app in self.get_blocked_apps():
                        f.write(f"{app_type_to_string(app)}\n")

                    f.write("\n[BLOCKED_DOMAINS]\n")
                    for dom in self.get_blocked_domains():
                        f.write(f"{dom}\n")

                    f.write("\n[BLOCKED_PORTS]\n")
                    for port in self.get_blocked_ports():
                        f.write(f"{port}\n")

                print(f"[RuleManager] Rules saved to: {filename}")
                return True
            except IOError as err:
                print(f"[RuleManager] Error saving rules: {err}")
                return False

    def load_rules(self, filename: str) -> bool:
        """Load rules from a config file."""
        with self._lock:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    current_section = ""
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            current_section = line.upper()
                            continue

                        if current_section == "[BLOCKED_IPS]":
                            self.block_ip(line)
                        elif current_section == "[BLOCKED_APPS]":
                            self.block_app(line)
                        elif current_section == "[BLOCKED_DOMAINS]":
                            self.block_domain(line)
                        elif current_section == "[BLOCKED_PORTS]":
                            try:
                                self.block_port(int(line))
                            except ValueError:
                                pass

                print(f"[RuleManager] Rules successfully loaded from: {filename}")
                return True
            except IOError as err:
                print(f"[RuleManager] Error loading rules file {filename}: {err}")
                return False

    def clear_all(self) -> None:
        """Reset all rules."""
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    def get_stats(self) -> RuleStats:
        """Return current rule counts."""
        with self._lock:
            return RuleStats(
                blocked_ips=len(self._blocked_ips),
                blocked_apps=len(self._blocked_apps),
                blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
                blocked_ports=len(self._blocked_ports),
            )