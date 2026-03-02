"""
PiHole & SOC MCP Server - HTTP Transport

This server exposes PiHole and SOC operations as MCP tools that can be called
by any MCP client (Claude Desktop, LangGraph agent, curl, etc.)

Key design decisions:
- Uses HTTP transport (not stdio) so it can run as a persistent service
- Stateless mode for reliability (no session state to lose on restart)
- JSON responses for easier debugging
- All tools are async for better performance under load
- Global write rate limiter applied to all write operations
"""

import sys
import os
import hmac
import hashlib
import json
import time
import logging
from typing import Any
from collections import defaultdict
from urllib.parse import parse_qs

# Add parent directory to path so we can import tools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP
from starlette.responses import JSONResponse, HTMLResponse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging to stderr (CRITICAL: stdout is reserved for MCP protocol in stdio mode)
# Even though we're using HTTP, it's good practice to keep stdout clean
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

# Import our PiHole tool functions
from tools.pihole_tools import (
    get_recent_queries,
    get_top_blocked_domains,
    get_top_permitted_domains,
    whitelist_domain,
    blacklist_domain,
    test_domain_resolution,
    get_client_activity,
    get_pihole_status,
    get_gravity_info,
)

# Import SOC tool functions
from tools.suricata_tools import get_new_alerts, get_alert_count_by_severity
from tools.ntopng_tools import (
    get_active_hosts,
    get_active_flows,
    get_alerts as ntopng_get_alerts,
    get_host_data,
    get_top_talkers,
    parse_hosts_response,
    parse_flows_response,
)
from tools.enrichment_tools import enrich_ip, enrich_batch
from tools.firewall_tools import (
    block_external_ip,
    unblock_external_ip,
    rollback_all,
    get_active_blocks,
    confirm_block,
    process_auto_rollbacks,
)
from config.protected_entities import is_protected_ip, is_protected_domain

# Create the MCP server instance
#
# FastMCP is a high-level wrapper that simplifies MCP server creation.
# It automatically generates JSON schemas from Python type hints.
#
# Note: Configuration is now passed to mcp.run() instead of constructor
# to avoid deprecation warnings in FastMCP 2.14+
mcp = FastMCP("PiHole & SOC Agent")


# ============================================================================
# GLOBAL WRITE RATE LIMITER
# ============================================================================
# Applies to ALL write operations regardless of which agent calls them.
# This is the tool-layer safety net that cannot be bypassed by agent logic.

_write_timestamps: dict[str, list[float]] = defaultdict(list)
WRITE_RATE_LIMIT = 10   # Max writes per minute across all tools
WRITE_WINDOW = 60       # Seconds


def _check_write_rate_limit(tool_name: str) -> bool:
    """Check if a write operation is within the rate limit. Returns True if allowed."""
    now = time.time()
    _write_timestamps[tool_name] = [
        t for t in _write_timestamps[tool_name] if now - t < WRITE_WINDOW
    ]
    total_writes = sum(len(ts) for ts in _write_timestamps.values())
    if total_writes >= WRITE_RATE_LIMIT:
        logger.warning(f"Write rate limit hit ({total_writes}/{WRITE_RATE_LIMIT} per {WRITE_WINDOW}s)")
        return False
    _write_timestamps[tool_name].append(now)
    return True


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================
# Each @mcp.tool() decorator registers a function as an MCP tool.
# The function's docstring becomes the tool description.
# Type hints become the parameter schema.

@mcp.tool()
async def pihole_get_recent_queries(minutes: int = 60) -> dict:
    """
    Get recent DNS queries from PiHole logs.
    
    Use this to understand current network activity, identify patterns,
    and find domains that might need to be whitelisted or blacklisted.
    
    Args:
        minutes: How far back to look (default: 60 minutes, max recommended: 1440 = 24 hours)
    
    Returns:
        Dictionary containing:
        - total_queries: Number of DNS queries in the time period
        - total_blocked: Number of blocked queries
        - total_permitted: Number of allowed queries
        - queries: List of recent query objects (domain, client, timestamp)
        - blocked: List of unique blocked domains
        - permitted: List of unique permitted domains
    """
    logger.info(f"Getting queries from last {minutes} minutes")
    return get_recent_queries(minutes)


@mcp.tool()
async def pihole_get_top_blocked(count: int = 20) -> list[dict]:
    """
    Get the most frequently blocked domains in the last 24 hours.
    
    Use this to identify:
    - Common tracking domains being blocked
    - Potential false positives (legitimate domains blocked too often)
    - Patterns in blocked traffic
    
    Args:
        count: Number of top domains to return (default: 20)
    
    Returns:
        List of {domain, count} objects sorted by frequency
    """
    logger.info(f"Getting top {count} blocked domains")
    return get_top_blocked_domains(count)


@mcp.tool()
async def pihole_get_top_permitted(count: int = 20) -> list[dict]:
    """
    Get the most frequently permitted (allowed) domains in the last 24 hours.
    
    Use this to identify:
    - Normal network traffic patterns
    - Domains that might be tracking but not in blocklists
    - Baseline for understanding expected behavior
    
    Args:
        count: Number of top domains to return (default: 20)
    
    Returns:
        List of {domain, count} objects sorted by frequency
    """
    logger.info(f"Getting top {count} permitted domains")
    return get_top_permitted_domains(count)


@mcp.tool()
async def pihole_whitelist(domain: str, reason: str) -> dict:
    """
    Add a domain to PiHole's whitelist (allow list).

    ⚠️ IMPORTANT: This modifies PiHole configuration. Use with caution.

    Args:
        domain: The domain to whitelist (e.g., "cdn.example.com")
        reason: Why this domain is being whitelisted (REQUIRED for audit)

    Returns:
        {success: bool, message: str, reason: str}
    """
    if not reason:
        return {'success': False, 'message': 'Reason is required for audit purposes'}
    if not _check_write_rate_limit("pihole_whitelist"):
        return {'success': False, 'message': 'Write rate limit exceeded. Try again in 60 seconds.'}

    logger.info(f"Whitelisting domain: {domain} (reason: {reason})")
    return whitelist_domain(domain, reason)


@mcp.tool()
async def pihole_blacklist(domain: str, reason: str) -> dict:
    """
    Add a domain to PiHole's blacklist (block list).

    ⚠️ IMPORTANT: This modifies PiHole configuration. Use with caution.

    Args:
        domain: The domain to blacklist (e.g., "tracking.badsite.com")
        reason: Why this domain is being blacklisted (REQUIRED for audit)

    Returns:
        {success: bool, message: str, reason: str}
    """
    if not reason:
        return {'success': False, 'message': 'Reason is required for audit purposes'}
    if is_protected_domain(domain):
        return {'success': False, 'message': f'Cannot blacklist {domain} — protected entity'}
    if not _check_write_rate_limit("pihole_blacklist"):
        return {'success': False, 'message': 'Write rate limit exceeded. Try again in 60 seconds.'}

    logger.info(f"Blacklisting domain: {domain} (reason: {reason})")
    return blacklist_domain(domain, reason)


@mcp.tool()
async def pihole_test_domain(domain: str) -> dict:
    """
    Test if a domain is currently blocked or permitted by PiHole.
    
    Use this to verify:
    - Whether a domain is in the blocklist
    - If a whitelist change took effect
    - What IP a domain resolves to
    
    Args:
        domain: Domain to test (e.g., "google.com")
    
    Returns:
        {domain, status: 'blocked'|'permitted', resolved_ips: [...], message}
    """
    logger.info(f"Testing domain resolution: {domain}")
    return test_domain_resolution(domain)


@mcp.tool()
async def pihole_get_clients(hours: int = 24) -> list[dict]:
    """
    Get DNS query activity per client device.
    
    Use this to identify:
    - Which devices are most active
    - Unusual activity from specific devices
    - IoT devices that might be phoning home excessively
    
    Args:
        hours: Time window to analyze (default: 24 hours)
    
    Returns:
        List of {client: IP, query_count: int} sorted by activity
    """
    logger.info(f"Getting client activity for last {hours} hours")
    return get_client_activity(hours)


@mcp.tool()
async def pihole_status() -> dict:
    """
    Get PiHole system status and statistics.
    
    Returns:
        - is_enabled: Whether blocking is active
        - ftl_running: Whether the DNS service is running
        - domains_blocked: Total domains in blocklist
        - queries_today: DNS queries processed today
        - blocked_today: Queries blocked today
        - percent_blocked: Percentage of queries blocked
    """
    logger.info("Getting PiHole status")
    return get_pihole_status()


@mcp.tool()
async def pihole_gravity_info() -> dict:
    """
    Get information about PiHole's blocklists (gravity database).
    
    Returns:
        - last_update: When blocklists were last updated
        - raw_output: Detailed gravity information
    """
    logger.info("Getting gravity info")
    return get_gravity_info()


# ============================================================================
# SOC TOOLS — Suricata, ntopng, enrichment, firewall
# ============================================================================

@mcp.tool()
async def soc_get_suricata_alerts() -> dict:
    """
    Get new Suricata IDS alerts since the last check.

    Reads eve.json incrementally using a file-offset bookmark.
    Only new events since the last cycle are returned.

    Returns:
        Dictionary with 'alerts', 'dns_events', 'tls_events', 'total_new_lines'
    """
    logger.info("Getting new Suricata alerts")
    return get_new_alerts()


@mcp.tool()
async def soc_get_suricata_summary(hours: int = 24) -> dict:
    """
    Get Suricata alert counts by severity for the last N hours.

    Returns:
        {critical, major, medium, info, total}
    """
    logger.info(f"Getting Suricata summary for last {hours} hours")
    return get_alert_count_by_severity(hours=hours)


@mcp.tool()
async def soc_get_network_hosts() -> dict:
    """
    Get all currently active hosts from ntopng.

    Returns host list with IP, MAC, hostname, bytes sent/received.
    Useful for new-device detection and traffic baseline analysis.
    """
    logger.info("Getting active network hosts from ntopng")
    raw = await get_active_hosts()
    if "error" in raw:
        return raw
    return {"hosts": parse_hosts_response(raw)}


@mcp.tool()
async def soc_get_network_flows() -> dict:
    """
    Get currently active network flows from ntopng.

    Each flow shows: client IP, server IP, protocol, ports, bytes transferred.
    Useful for detecting unusual connections.
    """
    logger.info("Getting active network flows from ntopng")
    raw = await get_active_flows()
    if "error" in raw:
        return raw
    return {"flows": parse_flows_response(raw)}


@mcp.tool()
async def soc_get_ntopng_alerts() -> dict:
    """Get ntopng alerts."""
    logger.info("Getting ntopng alerts")
    return await ntopng_get_alerts()


@mcp.tool()
async def soc_enrich_ip(ip: str) -> dict:
    """
    Enrich an external IP with reverse DNS, whois/ASN, and country data.

    Results are cached for 24 hours to avoid redundant lookups.

    Args:
        ip: The external IP address to enrich

    Returns:
        {ip, reverse_dns, asn, org, country, enriched_at}
    """
    if is_protected_ip(ip):
        return {"ip": ip, "note": "Protected entity — enrichment skipped"}
    logger.info(f"Enriching IP: {ip}")
    return enrich_ip(ip)


@mcp.tool()
async def soc_block_ip(ip: str, reason: str) -> dict:
    """
    Block an external IP address (Phase 1: dry-run only).

    ⚠️ Checks protected entities and rate limits before acting.
    In Phase 1, logs the action but does not execute firewall commands.

    Args:
        ip: The external IP to block
        reason: Why this IP is being blocked (REQUIRED for audit)

    Returns:
        {success, message, action_id, auto_rollback_at, dry_run}
    """
    if not reason:
        return {'success': False, 'message': 'Reason is required for audit purposes'}
    if is_protected_ip(ip):
        return {'success': False, 'message': f'Cannot block {ip} — protected entity'}
    if not _check_write_rate_limit("soc_block_ip"):
        return {'success': False, 'message': 'Write rate limit exceeded'}

    import uuid
    action_id = f"block-{uuid.uuid4().hex[:12]}"
    logger.info(f"Blocking IP: {ip} (reason: {reason})")
    return block_external_ip(ip=ip, reason=reason, action_id=action_id)


@mcp.tool()
async def soc_unblock_ip(ip: str) -> dict:
    """
    Remove a block on an external IP (Phase 1: dry-run only).

    Args:
        ip: The IP to unblock
    """
    logger.info(f"Unblocking IP: {ip}")
    return unblock_external_ip(ip=ip, action_id="manual")


@mcp.tool()
async def soc_rollback_all(hours: int = 24) -> dict:
    """
    Emergency stop: rollback ALL SOC actions from the last N hours.

    Args:
        hours: How far back to rollback (default: 24 hours)
    """
    logger.warning(f"Emergency rollback requested for last {hours} hours")
    return rollback_all(hours=hours)


@mcp.tool()
async def soc_get_active_blocks() -> list[dict]:
    """Get all currently active (non-rolled-back) IP blocks."""
    return get_active_blocks()


# ============================================================================
# APPROVAL ENDPOINT - Actionable links from email reports
# ============================================================================

# Secret key for signing approval tokens (set in .env)
APPROVAL_SECRET = os.getenv('APPROVAL_SECRET', '')

if not APPROVAL_SECRET:
    logger.warning("APPROVAL_SECRET not set in .env — approval links will be disabled. "
                   "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\"")


def generate_approval_token(action: str, domain: str) -> str:
    """Generate an HMAC token to sign an approval action."""
    message = f"{action}:{domain}"
    return hmac.new(
        APPROVAL_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_approval_token(action: str, domain: str, token: str) -> bool:
    """Verify that an approval token is valid."""
    expected = generate_approval_token(action, domain)
    return hmac.compare_digest(token, expected)


@mcp.custom_route("/approve", methods=["GET"])
async def approve_action(request):
    """
    HTTP endpoint for approving recommendations via email links.

    Expected query params: action, domain, token, reason
    Example: /approve?action=block&domain=tracker.com&token=abc123&reason=Tracking+domain
    """
    if not APPROVAL_SECRET:
        return HTMLResponse(
            "<h2>Approval links are disabled</h2>"
            "<p>Set APPROVAL_SECRET in your .env file to enable this feature.</p>",
            status_code=503
        )

    params = parse_qs(request.url.query)
    action = params.get("action", [None])[0]
    domain = params.get("domain", [None])[0]
    token = params.get("token", [None])[0]
    reason = params.get("reason", ["Approved via email link"])[0]

    if not all([action, domain, token]):
        return HTMLResponse(
            "<h2>Bad Request</h2><p>Missing required parameters (action, domain, token).</p>",
            status_code=400
        )

    if action not in ("block", "blacklist", "whitelist", "allow"):
        return HTMLResponse(
            f"<h2>Bad Request</h2><p>Invalid action: {action}. Use block or allow.</p>",
            status_code=400
        )

    # Normalize action names
    normalized_action = "blacklist" if action in ("block", "blacklist") else "whitelist"

    if not verify_approval_token(normalized_action, domain, token):
        logger.warning(f"Invalid approval token for {normalized_action} {domain}")
        return HTMLResponse(
            "<h2>Unauthorized</h2><p>Invalid or expired approval token.</p>",
            status_code=403
        )

    # Execute the action
    if normalized_action == "whitelist":
        result = whitelist_domain(domain, f"[APPROVED] {reason}")
    else:
        result = blacklist_domain(domain, f"[APPROVED] {reason}")

    logger.info(f"Approval executed: {normalized_action} {domain} — success={result.get('success')}")

    success = result.get("success", False)
    if success:
        return HTMLResponse(
            f"<h2>Done</h2>"
            f"<p><strong>{domain}</strong> has been {'allowed' if normalized_action == 'whitelist' else 'blocked'}.</p>"
            f"<p>Reason: {reason}</p>"
        )
    else:
        return HTMLResponse(
            f"<h2>Failed</h2>"
            f"<p>Could not {normalized_action} <strong>{domain}</strong>.</p>"
            f"<p>Error: {result.get('message', 'Unknown error')}</p>",
            status_code=500
        )


# ============================================================================
# SERVER STARTUP
# ============================================================================

def main():
    """Start the MCP server with HTTP transport."""
    port = int(os.getenv('MCP_SERVER_PORT', 8765))

    logger.info(f"Starting PiHole & SOC MCP Server on port {port}")
    logger.info("PiHole tools:")
    logger.info("  - pihole_get_recent_queries, pihole_get_top_blocked, pihole_get_top_permitted")
    logger.info("  - pihole_whitelist, pihole_blacklist, pihole_test_domain")
    logger.info("  - pihole_get_clients, pihole_status, pihole_gravity_info")
    logger.info("SOC tools:")
    logger.info("  - soc_get_suricata_alerts, soc_get_suricata_summary")
    logger.info("  - soc_get_network_hosts, soc_get_network_flows, soc_get_ntopng_alerts")
    logger.info("  - soc_enrich_ip, soc_block_ip, soc_unblock_ip")
    logger.info("  - soc_rollback_all, soc_get_active_blocks")
    
    # Run with HTTP transport
    # Configuration:
    # - host="127.0.0.1": Localhost-only for security (NEVER use "0.0.0.0" without auth!)
    # - stateless_http=True: Server doesn't track sessions, more robust for restarts
    # - json_response=True: Returns JSON instead of SSE streams, easier to debug
    # For remote access, use Tailscale/WireGuard VPN (see README)
    logger.info(f"🔒 Security: Binding to localhost only (127.0.0.1:{port})")
    logger.info("   For remote access, use SSH port forwarding or Tailscale VPN")

    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True
    )


if __name__ == "__main__":
    main()
