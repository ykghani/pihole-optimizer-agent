"""
PiHole MCP Server - HTTP Transport

This server exposes PiHole operations as MCP tools that can be called
by any MCP client (Claude Desktop, LangGraph agent, curl, etc.)

Key design decisions:
- Uses HTTP transport (not stdio) so it can run as a persistent service
- Stateless mode for reliability (no session state to lose on restart)
- JSON responses for easier debugging
- All tools are async for better performance under load
"""

import sys
import os
import logging
from typing import Any

# Add parent directory to path so we can import tools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP
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

# Create the MCP server instance
#
# FastMCP is a high-level wrapper that simplifies MCP server creation.
# It automatically generates JSON schemas from Python type hints.
#
# Note: Configuration is now passed to mcp.run() instead of constructor
# to avoid deprecation warnings in FastMCP 2.14+
mcp = FastMCP("PiHole Agent")


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
    
    When to whitelist:
    - Domain is blocked but needed for legitimate functionality
    - False positive from blocklist (e.g., CDN serving both ads and content)
    - User explicitly requested access to the domain
    
    Args:
        domain: The domain to whitelist (e.g., "cdn.example.com")
        reason: Why this domain is being whitelisted (REQUIRED for audit)
    
    Returns:
        {success: bool, message: str, reason: str}
    """
    if not reason:
        return {'success': False, 'message': 'Reason is required for audit purposes'}
    
    logger.info(f"Whitelisting domain: {domain} (reason: {reason})")
    return whitelist_domain(domain, reason)


@mcp.tool()
async def pihole_blacklist(domain: str, reason: str) -> dict:
    """
    Add a domain to PiHole's blacklist (block list).
    
    ⚠️ IMPORTANT: This modifies PiHole configuration. Use with caution.
    
    When to blacklist:
    - Domain is clearly tracking/advertising but not in blocklists
    - Suspicious domain making unusual requests
    - Known malware/phishing domain
    
    Args:
        domain: The domain to blacklist (e.g., "tracking.badsite.com")
        reason: Why this domain is being blacklisted (REQUIRED for audit)
    
    Returns:
        {success: bool, message: str, reason: str}
    """
    if not reason:
        return {'success': False, 'message': 'Reason is required for audit purposes'}
    
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
# SERVER STARTUP
# ============================================================================

def main():
    """Start the MCP server with HTTP transport."""
    port = int(os.getenv('MCP_SERVER_PORT', 8765))
    
    logger.info(f"Starting PiHole MCP Server on port {port}")
    logger.info("Available tools:")
    logger.info("  - pihole_get_recent_queries")
    logger.info("  - pihole_get_top_blocked")
    logger.info("  - pihole_get_top_permitted")
    logger.info("  - pihole_whitelist")
    logger.info("  - pihole_blacklist")
    logger.info("  - pihole_test_domain")
    logger.info("  - pihole_get_clients")
    logger.info("  - pihole_status")
    logger.info("  - pihole_gravity_info")
    
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
