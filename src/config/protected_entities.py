"""
Protected entities that the SOC agent can NEVER block or modify.

SECURITY: This file uses frozenset (immutable) and is hardcoded — not loaded
from .env, not configurable at runtime, not modifiable by Claude output.
Every write tool checks this list at the tool layer (not the agent layer)
so it cannot be bypassed by prompt injection or agent manipulation.

If you need to add protected entities, edit this file and restart the service.
"""

import ipaddress
from typing import Union


# ---------------------------------------------------------------------------
# Protected IPs — never block these addresses
# ---------------------------------------------------------------------------

PROTECTED_IPS: frozenset[str] = frozenset({
    # Gateway / router — replace with your router's IP
    "192.168.1.1",
    # This Pi (the agent itself) — replace with the IP of the device running this agent
    "192.168.1.2",
    # Loopback
    "127.0.0.1",
    "::1",
    # Upstream DNS resolvers (if blocked, all DNS fails)
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    # Quad9
    "9.9.9.9",
    "149.112.112.112",
})


# ---------------------------------------------------------------------------
# Protected domains — never block these domains
# ---------------------------------------------------------------------------

PROTECTED_DOMAINS: frozenset[str] = frozenset({
    # Agent infrastructure (blocking these disables the agent)
    "api.anthropic.com",
    "imap.gmail.com",
    "smtp.gmail.com",
    # PiHole admin interface
    "pi.hole",
    # Local
    "localhost",
})

# Domain suffixes that are always protected (e.g., *.tailscale.com)
PROTECTED_DOMAIN_SUFFIXES: frozenset[str] = frozenset({
    ".tailscale.com",
    ".ts.net",
    # If using Tailscale, add your tailnet-specific domain here:
    # ".your-tailnet-name.ts.net",
})


# ---------------------------------------------------------------------------
# Protected subnets — never block traffic within these ranges
# ---------------------------------------------------------------------------

PROTECTED_SUBNETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("192.168.1.0/24"),    # Entire local LAN — adjust to match your subnet
    ipaddress.IPv4Network("100.64.0.0/10"),      # Tailscale CGNAT range
    ipaddress.IPv4Network("224.0.0.0/4"),        # Multicast
    ipaddress.IPv4Network("127.0.0.0/8"),        # Loopback
)


# ---------------------------------------------------------------------------
# Protected rules — hard limits on what the agent can do
# ---------------------------------------------------------------------------

# The agent can NEVER:
# - Disable PiHole entirely (pihole disable)
# - Modify iptables/nftables INPUT chain for SSH (port 22)
# - Modify its own systemd service
# - Delete the audit log
# - Modify this file

BLOCKED_COMMANDS: frozenset[str] = frozenset({
    "pihole disable",
    "systemctl stop pihole-FTL",
    "systemctl disable pihole-FTL",
    "systemctl stop pihole-mcp",
    "systemctl stop soc-agent",
})


# ---------------------------------------------------------------------------
# Validation functions
# ---------------------------------------------------------------------------

def is_protected_ip(ip: str) -> bool:
    """Check if an IP address is protected from blocking."""
    if ip in PROTECTED_IPS:
        return True
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in subnet for subnet in PROTECTED_SUBNETS)
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_protected_domain(domain: str) -> bool:
    """Check if a domain is protected from blocking."""
    domain_lower = domain.lower()
    if domain_lower in PROTECTED_DOMAINS:
        return True
    return any(domain_lower.endswith(suffix) for suffix in PROTECTED_DOMAIN_SUFFIXES)


def is_blocked_command(command: str) -> bool:
    """Check if a command is explicitly blocked."""
    command_lower = command.lower().strip()
    return any(blocked in command_lower for blocked in BLOCKED_COMMANDS)
