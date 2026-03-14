"""
SOC agent heuristic rules for local classification.

These rules run BEFORE the Claude API call, handling obvious cases
(known FPs, known-safe IPs, alert floods) without spending API credits.
Only events that heuristics can't classify are sent to Claude.

Heuristics are deterministic and auditable — no LLM involved.
"""

import ipaddress
import logging
from datetime import datetime, time
from typing import Optional

from config.known_safe import (
    is_known_safe_ip,
    is_known_safe_domain,
    CDN_ASN_PREFIXES,
    TAILSCALE_DERP_IPS,
)
from config.protected_entities import PROTECTED_SUBNETS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# FP suppression thresholds
# ---------------------------------------------------------------------------

FP_THRESHOLD_COUNT = 5       # Number of FP classifications before auto-suppression
FP_THRESHOLD_DAYS = 7        # Window for counting FPs
FP_SUPPRESSION_DAYS = 7      # How long to suppress a signature


# ---------------------------------------------------------------------------
# Volume spike detection
# ---------------------------------------------------------------------------

VOLUME_SPIKE_MULTIPLIER = 3  # Alert if current rate > Nx rolling average


# ---------------------------------------------------------------------------
# Night-time anomaly window
# ---------------------------------------------------------------------------

NIGHT_START = time(1, 0)     # 1:00 AM
NIGHT_END = time(5, 0)       # 5:00 AM


# ---------------------------------------------------------------------------
# Alert flood detection
# ---------------------------------------------------------------------------

FLOOD_THRESHOLD = 50          # Alerts per SID in 5 minutes = flood
FLOOD_SUPPRESSION_MINUTES = 60

# ---------------------------------------------------------------------------
# STUN / NAT traversal signatures that are always benign
# ---------------------------------------------------------------------------

# Suricata signature substrings that indicate STUN traffic.
# STUN (RFC 5389) is used by Tailscale and other VPN/WebRTC software for
# NAT traversal — these alerts fire constantly and are never actionable.
STUN_SIGNATURE_SUBSTRINGS: tuple[str, ...] = (
    "STUN",
    "stun",
    "NAT traversal",
    "nat-traversal",
)


def is_tailscale_stun(signature: str, dest_ip: str, dest_port: int | None) -> bool:
    """
    Return True if the event is Tailscale / generic STUN NAT-traversal traffic.

    Matches on:
    - Signature contains a known STUN keyword, OR
    - Destination is UDP 3478 (the IANA STUN port) to a Tailscale DERP IP or
      a Tailscale domain suffix (checked via dest_ip presence in TAILSCALE_DERP_IPS).

    These are false positives with ~100% confidence on a home network running
    Tailscale — they should never reach the LLM queue.
    """
    if any(kw in signature for kw in STUN_SIGNATURE_SUBSTRINGS):
        return True
    if dest_ip in TAILSCALE_DERP_IPS:
        return True
    # UDP 3478 = STUN; combined with a non-RFC1918 dest it is almost always VPN NAT traversal
    if dest_port == 3478 and not is_rfc1918(dest_ip):
        return True
    return False


def is_rfc1918(ip: str) -> bool:
    """Check if an IP is in RFC1918 private address space."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.is_private
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_internal_ip(ip: str) -> bool:
    """Check if an IP is on the local network."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in subnet for subnet in PROTECTED_SUBNETS)
    except (ipaddress.AddressValueError, ValueError):
        return False


def classify_by_known_safe_ip(dest_ip: str) -> Optional[str]:
    """
    If the destination IP is known-safe, classify as false_positive.

    Returns classification string or None if no match.
    """
    if is_known_safe_ip(dest_ip):
        return "false_positive"
    return None


def classify_by_known_safe_domain(domain: str) -> Optional[str]:
    """
    If the domain is known-safe, classify as false_positive.
    """
    if domain and is_known_safe_domain(domain):
        return "false_positive"
    return None


def check_fp_suppression(
    signature: str,
    fp_count_fn,
) -> Optional[str]:
    """
    Check if a signature should be auto-suppressed based on FP history.

    Args:
        signature: The Suricata signature string
        fp_count_fn: Callable that returns FP count for a signature
                     (injected to decouple from Neo4j dependency)

    Returns "false_positive" if the signature should be suppressed, else None.
    """
    count = fp_count_fn(signature)
    if count >= FP_THRESHOLD_COUNT:
        logger.info(
            f"FP suppression: signature '{signature}' has {count} FPs "
            f"in {FP_THRESHOLD_DAYS} days (threshold: {FP_THRESHOLD_COUNT})"
        )
        return "false_positive"
    return None


def check_night_time_escalation(timestamp: str) -> bool:
    """
    Check if an event occurred during the night-time anomaly window.

    Events between 1am-5am local time are escalated by one severity level
    because legitimate network activity is minimal during these hours.

    Returns True if the event should be escalated.
    """
    try:
        event_time = datetime.fromisoformat(timestamp[:19]).time()
        return NIGHT_START <= event_time <= NIGHT_END
    except (ValueError, TypeError):
        return False


def check_outbound_to_unknown(
    src_ip: str,
    dest_ip: str,
    severity: Optional[int],
) -> Optional[str]:
    """
    Check for outbound traffic from internal device to unknown external IP.

    Priority 1-2 alerts with internal source → unknown external destination
    are always escalated to HIGH, regardless of other factors.
    """
    if severity is not None and severity <= 2:
        if is_internal_ip(src_ip) and not is_rfc1918(dest_ip):
            if not is_known_safe_ip(dest_ip):
                return "high"
    return None


def detect_alert_flood(
    alerts: list[dict],
    window_minutes: int = 5,
) -> list[str]:
    """
    Detect alert floods (same SID firing excessively).

    Returns list of SIDs that are flooding. These should be suppressed
    for the current cycle — the agent should NOT take automated action
    based on flooded alerts (could be attacker manipulation).
    """
    from collections import Counter

    sid_counts = Counter()
    for alert in alerts:
        sid = alert.get("signature_id")
        if sid:
            sid_counts[str(sid)] += 1

    flooded = [
        sid for sid, count in sid_counts.items()
        if count >= FLOOD_THRESHOLD
    ]

    if flooded:
        logger.warning(
            f"Alert flood detected: SIDs {flooded} "
            f"(>{FLOOD_THRESHOLD} alerts in {window_minutes}min window)"
        )

    return flooded


def check_volume_spike(
    current_count: int,
    rolling_average: float,
) -> bool:
    """
    Check if the current alert volume is a spike above the rolling average.

    Returns True if current_count > VOLUME_SPIKE_MULTIPLIER * rolling_average.
    """
    if rolling_average <= 0:
        return False
    return current_count > (VOLUME_SPIKE_MULTIPLIER * rolling_average)


def classify_event_heuristic(
    event: dict,
    fp_count_fn=None,
) -> Optional[dict]:
    """
    Attempt to classify a single event using heuristic rules.

    Returns a classification dict if heuristics can handle it,
    or None if the event should be sent to Claude.

    Classification dict: {
        "classification": "false_positive" | "low" | "medium" | "high" | "critical",
        "reason": str,
        "heuristic": str,  # Which rule matched
        "confidence": int,
    }
    """
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")
    dest_port = event.get("dest_port")
    signature = event.get("signature", "")
    severity = event.get("severity")
    domain = event.get("dns_rrname", "") or event.get("tls_sni", "")

    # 0. Tailscale / STUN NAT-traversal (highest-volume FP on home networks)
    if is_tailscale_stun(signature, dest_ip, dest_port):
        return {
            "classification": "false_positive",
            "reason": f"Tailscale/STUN NAT traversal traffic (sig='{signature}', dest={dest_ip}:{dest_port})",
            "heuristic": "tailscale_stun",
            "confidence": 98,
        }

    # 1. Known-safe destination IP
    result = classify_by_known_safe_ip(dest_ip)
    if result:
        return {
            "classification": result,
            "reason": f"Destination IP {dest_ip} is in known-safe list",
            "heuristic": "known_safe_ip",
            "confidence": 95,
        }

    # 2. Known-safe domain
    result = classify_by_known_safe_domain(domain)
    if result:
        return {
            "classification": result,
            "reason": f"Domain {domain} is in known-safe list",
            "heuristic": "known_safe_domain",
            "confidence": 90,
        }

    # 3. FP suppression (repeated false positives)
    if fp_count_fn and signature:
        result = check_fp_suppression(signature, fp_count_fn)
        if result:
            return {
                "classification": result,
                "reason": f"Signature '{signature}' auto-suppressed (>{FP_THRESHOLD_COUNT} FPs in {FP_THRESHOLD_DAYS}d)",
                "heuristic": "fp_suppression",
                "confidence": 90,
            }

    # 4. Outbound to unknown (escalation, not auto-classify as FP)
    result = check_outbound_to_unknown(src_ip, dest_ip, severity)
    if result:
        reason = f"Priority {severity} alert: internal {src_ip} → unknown external {dest_ip}"
        # Night-time escalation
        timestamp = event.get("timestamp", "")
        if check_night_time_escalation(timestamp):
            result = "critical"
            reason += " (night-time anomaly: 1am-5am)"

        return {
            "classification": result,
            "reason": reason,
            "heuristic": "outbound_to_unknown",
            "confidence": 85,
        }

    # 5. Informational alerts (severity 4) — auto-classify as low
    if severity == 4:
        return {
            "classification": "low",
            "reason": f"Informational alert (severity 4): {signature}",
            "heuristic": "info_severity",
            "confidence": 85,
        }

    # Heuristics can't classify this — send to Claude
    return None
