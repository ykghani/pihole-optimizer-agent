"""
Known-safe IPs and domains that the agent can auto-classify as benign.

Unlike protected_entities.py (which prevents blocking), this file is used
during the CLASSIFY step to skip Claude API calls for IPs/domains that are
well-known and safe. These can be updated more freely.
"""

# ---------------------------------------------------------------------------
# Known-safe IP ranges (skip enrichment + auto-classify as FP)
# ---------------------------------------------------------------------------

KNOWN_SAFE_IPS: frozenset[str] = frozenset({
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
    # Google DNS
    "8.8.8.8",
    "8.8.4.4",
    # Quad9
    "9.9.9.9",
    "149.112.112.112",
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
})

# Tailscale DERP server IP ranges used for STUN/NAT traversal.
# Traffic to/from these IPs is Tailscale VPN infrastructure — always benign.
# Source: https://login.tailscale.com/derpmap/default (Hetzner-hosted DERP nodes
# also appear; those are operated by Tailscale).
TAILSCALE_DERP_IPS: frozenset[str] = frozenset({
    # Well-known Tailscale DERP/STUN relay IPs (expand as needed)
    "204.80.128.1",
    "204.80.129.1",
    "204.80.130.1",
})

# ASN prefixes commonly associated with CDN/cloud infrastructure.
# Alerts involving these ASNs are not auto-dismissed but get lower weight.
CDN_ASN_PREFIXES: frozenset[str] = frozenset({
    "AS13335",   # Cloudflare
    "AS16509",   # Amazon/AWS
    "AS15169",   # Google
    "AS8075",    # Microsoft
    "AS20940",   # Akamai
    "AS54113",   # Fastly
})


# ---------------------------------------------------------------------------
# Known-safe domains (auto-classify DNS queries to these as benign)
# ---------------------------------------------------------------------------

KNOWN_SAFE_DOMAINS: frozenset[str] = frozenset({
    # OS updates
    "updates.ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "raspbian.raspberrypi.org",
    # NTP
    "pool.ntp.org",
    "time.google.com",
    "time.apple.com",
    # Agent infrastructure
    "api.anthropic.com",
    "pypi.org",
    "files.pythonhosted.org",
    # DNS over HTTPS resolvers (trigger ET INFO sigs, always benign)
    "dns.google",
    "cloudflare-dns.com",
    # VS Code Dev Tunnels (developer tooling)
    "tunnels.api.visualstudio.com",
    "rel.tunnels.api.visualstudio.com",
    "vscode.download.prss.microsoft.com",
    # Spotify P2P (normal Spotify client behaviour)
    "spotify.com",
})

# Domain suffixes that are generally safe (reduce severity but don't auto-dismiss)
KNOWN_SAFE_SUFFIXES: frozenset[str] = frozenset({
    ".googleapis.com",
    ".gstatic.com",
    ".cloudflare.com",
    ".akamaized.net",
    ".cloudfront.net",
    ".apple.com",
    ".microsoft.com",
    ".ubuntu.com",
    # Tailscale infrastructure
    ".tailscale.com",
    ".tailscale.io",
    # Spotify (P2P client traffic is normal)
    ".spotify.com",
    ".scdn.co",
    # VS Code / Microsoft dev tooling
    ".visualstudio.com",
    ".vscode-cdn.net",
})


# ---------------------------------------------------------------------------
# MAC address pinning for critical infrastructure
# ---------------------------------------------------------------------------
# Set these to your actual MAC addresses. If an IP's MAC changes unexpectedly,
# the agent treats it as a potential ARP spoofing alert.
# Format: { "192.168.1.1": "AA:BB:CC:DD:EE:FF" }

PINNED_MACS: dict[str, str] = {
    # Uncomment and fill in your actual values:
    # "192.168.1.1": "XX:XX:XX:XX:XX:XX",    # Gateway/router
    # "192.168.1.2": "XX:XX:XX:XX:XX:XX",       # This Pi (replace with your Pi's IP and MAC)
}


def is_known_safe_ip(ip: str) -> bool:
    """Check if an IP is in the known-safe list."""
    return ip in KNOWN_SAFE_IPS


def is_known_safe_domain(domain: str) -> bool:
    """Check if a domain is known-safe (exact match or suffix)."""
    domain_lower = domain.lower()
    if domain_lower in KNOWN_SAFE_DOMAINS:
        return True
    return any(domain_lower.endswith(suffix) for suffix in KNOWN_SAFE_SUFFIXES)
