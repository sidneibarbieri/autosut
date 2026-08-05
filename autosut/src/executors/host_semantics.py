"""
HostContextualCapability - Semantic state management for multi-host campaigns

Replaces global state markers with host-contextual capabilities.
Examples:
  - access:initial@host1  (not global "access:initial")
  - session:shell@host1->host2  (lateral movement path)
  - credential:admin@host2

This enables honest multi-host emulation where capabilities on one host
do not incorrectly satisfy prerequisites for another host.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class HostCapability:
    """A capability tied to a specific host or host relationship"""
    capability_type: str  # e.g., "access", "session", "credential", "network"
    host: str  # target host
    via_host: Optional[str] = None  # origin host (for lateral movement)
    privilege: str = "user"  # user, admin, system

    def to_capability_string(self) -> str:
        """Convert to capability string format"""
        if self.via_host:
            return f"{self.capability_type}:{self.privilege}@{self.via_host}->{self.host}"
        return f"{self.capability_type}:{self.privilege}@{self.host}"

    @classmethod
    def from_capability_string(cls, cap_str: str) -> "HostCapability":
        """Parse capability string"""
        # Handle lateral movement: type:priv@origin->target
        if "->" in cap_str:
            left, host = cap_str.split("->")
            type_priv, via_host = left.rsplit("@", 1)
            cap_type, privilege = type_priv.split(":", 1) if ":" in type_priv else (type_priv, "user")
            return cls(cap_type, host, via_host, privilege)

        # Standard: type:priv@host
        if "@" in cap_str:
            type_priv, host = cap_str.rsplit("@", 1)
            cap_type, privilege = type_priv.split(":", 1) if ":" in type_priv else (type_priv, "user")
            return cls(cap_type, host, None, privilege)

        # Fallback: treat as global capability (for backwards compatibility)
        return cls(cap_str, "any", None, "user")


class HostCapabilityManager:
    """Manages capabilities across multiple hosts with proper isolation"""

    def __init__(self, default_host: str = "target-1"):
        self.default_host = default_host
        self._capabilities: set = set()
        self._host_capabilities: dict = {}  # host -> set of capabilities

    def add_capability(self, capability: str, host: Optional[str] = None):
        """Add a capability for a specific host"""
        target_host = host or self.default_host

        # Parse if already host-contextual
        if "@" in capability:
            hc = HostCapability.from_capability_string(capability)
            self._capabilities.add(capability)
            if hc.host not in self._host_capabilities:
                self._host_capabilities[hc.host] = set()
            self._host_capabilities[hc.host].add(hc.capability_type)
        else:
            # Add host context
            contextual = f"{capability}@{target_host}"
            self._capabilities.add(contextual)
            if target_host not in self._host_capabilities:
                self._host_capabilities[target_host] = set()
            self._host_capabilities[target_host].add(capability)

    def has_capability(self, capability: str, host: Optional[str] = None) -> bool:
        """Check if capability exists for specific host"""
        target_host = host or self.default_host

        # Check contextual version
        contextual = f"{capability}@{target_host}"
        if contextual in self._capabilities:
            return True

        # Check if host has this capability type
        if target_host in self._host_capabilities:
            return capability in self._host_capabilities[target_host]

        # Fallback: check global (for backwards compatibility during transition)
        return capability in self._capabilities

    def get_host_capabilities(self, host: str) -> List[str]:
        """Get all capabilities for a specific host"""
        caps = []
        for cap in self._capabilities:
            if f"@{host}" in cap:
                caps.append(cap)
        return caps

    def list_hosts(self) -> List[str]:
        """List all hosts with capabilities"""
        hosts = set()
        for cap in self._capabilities:
            if "@" in cap:
                _, host_part = cap.rsplit("@", 1)
                if "->" in host_part:
                    _, target = host_part.split("->")
                    hosts.add(target)
                else:
                    hosts.add(host_part)
        return sorted(hosts)

    def to_capability_list(self) -> List[str]:
        """Export all capabilities as list"""
        return sorted(self._capabilities)


def create_host_contextual_prerequisite(prerequisite: str, host: str) -> str:
    """Convert a prerequisite to host-contextual form"""
    if "@" in prerequisite:
        return prerequisite  # Already contextual
    return f"{prerequisite}@{host}"


def get_state_bridge_for_host_prerequisite(prerequisite: str, host: str) -> Optional[str]:
    """Get state bridge executor for a host-specific prerequisite"""
    # Map of prerequisite types to bridge executors
    bridge_map = {
        "access:initial": "state_bridge_initial_access",
        "network:egress_allowed": "state_bridge_egress_allowed",
        "session:shell": "state_bridge_session_shell",
        "credential:local_admin": "state_bridge_local_admin",
    }

    # Extract base prerequisite (without host)
    if "@" in prerequisite:
        base = prerequisite.split("@")[0]
    else:
        base = prerequisite

    return bridge_map.get(base)
