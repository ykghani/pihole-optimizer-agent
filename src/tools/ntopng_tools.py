"""
ntopng REST API client for flow analysis and host anomaly detection.

ntopng exposes a REST API on port 3000 for querying host-level statistics,
active flows, and alert history. This module provides typed wrappers
around those endpoints.

Authentication: Token-based auth via Authorization header (.env: NTOPNG_TOKEN).
Generate a token in ntopng Settings → Preferences → Token-based Authentication.
"""

import os
import logging
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Configuration
NTOPNG_BASE_URL = os.getenv("NTOPNG_URL", "http://localhost:3000")
NTOPNG_TOKEN = os.getenv("NTOPNG_TOKEN", "")
NTOPNG_IFACE = os.getenv("NTOPNG_IFACE", "1")  # Default interface index (wlan0 = 1)

# Request timeout (seconds)
NTOPNG_TIMEOUT = 15


async def _ntopng_get(endpoint: str, params: Optional[dict] = None) -> dict:
    """
    Make an authenticated GET request to the ntopng REST API.

    Returns the JSON response body, or an error dict on failure.
    """
    if not NTOPNG_TOKEN:
        return {"error": "NTOPNG_TOKEN not configured in .env"}

    url = f"{NTOPNG_BASE_URL}{endpoint}"
    headers = {"Authorization": f"Token {NTOPNG_TOKEN}"}

    try:
        async with httpx.AsyncClient(timeout=NTOPNG_TIMEOUT) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"ntopng API error {e.response.status_code}: {endpoint}")
        return {"error": f"HTTP {e.response.status_code}: {str(e)}"}
    except httpx.ConnectError:
        logger.error(f"Cannot connect to ntopng at {NTOPNG_BASE_URL}")
        return {"error": f"Connection refused: {NTOPNG_BASE_URL}"}
    except httpx.TimeoutException:
        logger.error(f"ntopng request timed out: {endpoint}")
        return {"error": f"Timeout: {endpoint}"}
    except Exception as e:
        logger.error(f"ntopng request failed: {e}")
        return {"error": str(e)}


async def get_active_hosts() -> dict:
    """
    Get all currently active hosts on the network.

    Paginates through all pages automatically (ntopng returns 10 per page).
    Returns a synthetic dict with a flat "data" list of all hosts.
    """
    all_hosts = []
    page = 1
    while True:
        result = await _ntopng_get(
            "/lua/rest/v2/get/host/active.lua",
            params={"ifid": NTOPNG_IFACE, "currentPage": page},
        )
        if "error" in result:
            return result
        rsp = result.get("rsp", {})
        data = rsp.get("data", [])
        all_hosts.extend(data)
        per_page = rsp.get("perPage", 10)
        # Stop when we've received a partial page
        if len(data) < per_page:
            break
        page += 1
    return {"rsp": {"data": all_hosts}}


async def get_host_data(host_ip: str) -> dict:
    """
    Get detailed data for a specific host.

    Includes traffic statistics, active flows, DNS queries,
    and anomaly information for the specified IP.
    """
    result = await _ntopng_get(
        "/lua/rest/v2/get/host/data.lua",
        params={"ifid": NTOPNG_IFACE, "host": host_ip},
    )
    return result


async def get_active_flows() -> dict:
    """
    Get all currently active network flows.

    Each flow shows: client IP, server IP, protocol, ports,
    bytes transferred, and duration. Useful for detecting
    unusual connections (e.g., outbound to unknown IPs at 3am).
    Paginates through all pages automatically.
    """
    all_flows = []
    page = 1
    while True:
        result = await _ntopng_get(
            "/lua/rest/v2/get/flow/active.lua",
            params={"ifid": NTOPNG_IFACE, "currentPage": page},
        )
        if "error" in result:
            return result
        rsp = result.get("rsp", {})
        data = rsp.get("data", [])
        all_flows.extend(data)
        per_page = rsp.get("perPage", 10)
        if len(data) < per_page:
            break
        page += 1
    return {"rsp": {"data": all_flows}}


async def get_host_flows(host_ip: str) -> dict:
    """Get active flows for a specific host."""
    result = await _ntopng_get(
        "/lua/rest/v2/get/flow/active.lua",
        params={"ifid": NTOPNG_IFACE, "host": host_ip},
    )
    return result


async def get_alerts(
    alert_type: str = "all",
    epoch_begin: Optional[int] = None,
    epoch_end: Optional[int] = None,
) -> dict:
    """
    Get ntopng alerts.

    Args:
        alert_type: Filter by type ('all', 'host', 'interface', 'network', 'flow')
        epoch_begin: Start timestamp (epoch seconds)
        epoch_end: End timestamp (epoch seconds)
    """
    params = {"ifid": NTOPNG_IFACE}
    if epoch_begin:
        params["epoch_begin"] = str(epoch_begin)
    if epoch_end:
        params["epoch_end"] = str(epoch_end)

    # ntopng alert endpoint varies by version
    endpoint = "/lua/rest/v2/get/alert/list.lua"
    if alert_type != "all":
        endpoint = f"/lua/rest/v2/get/{alert_type}/alert/list.lua"

    result = await _ntopng_get(endpoint, params=params)
    return result


async def get_interface_data() -> dict:
    """
    Get network interface statistics.

    Returns packet counts, throughput, and error rates
    for the monitored interface.
    """
    result = await _ntopng_get(
        "/lua/rest/v2/get/interface/data.lua",
        params={"ifid": NTOPNG_IFACE},
    )
    return result


async def get_top_talkers() -> dict:
    """
    Get top network talkers (hosts generating the most traffic).

    Useful for detecting devices with abnormal traffic volumes.
    """
    result = await _ntopng_get(
        "/lua/rest/v2/get/interface/top_local_talkers.lua",
        params={"ifid": NTOPNG_IFACE},
    )
    return result


def parse_hosts_response(raw: dict) -> list[dict]:
    """
    Parse the ntopng hosts response into a normalized list.

    Handles the v6+ paginated format: {"rsp": {"data": [...], ...}}
    """
    if "error" in raw:
        return []

    rsp = raw.get("rsp", raw)

    # Paginated v6+ format: rsp.data is the list
    if isinstance(rsp, dict):
        hosts = rsp.get("data", [])
    elif isinstance(rsp, list):
        hosts = rsp
    else:
        return []

    parsed = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        b = host.get("bytes", {})
        flows = host.get("num_flows", {})
        parsed.append({
            "ip": host.get("ip", ""),
            "mac": host.get("mac", ""),
            "name": host.get("name", host.get("ip", "")),
            "bytes_sent": b.get("sent", 0) if isinstance(b, dict) else 0,
            "bytes_recv": b.get("recvd", 0) if isinstance(b, dict) else 0,
            "num_flows": flows.get("total", 0) if isinstance(flows, dict) else 0,
            "is_local": host.get("is_localhost", False),
        })

    return parsed


def parse_flows_response(raw: dict) -> list[dict]:
    """Parse ntopng flows response into a normalized list."""
    if "error" in raw:
        return []

    rsp = raw.get("rsp", raw)
    if isinstance(rsp, dict):
        data = rsp.get("data", [])
    elif isinstance(rsp, list):
        data = rsp
    else:
        return []

    parsed = []
    for flow in data:
        if not isinstance(flow, dict):
            continue
        parsed.append({
            "client_ip": flow.get("cli.ip", flow.get("column_client", "")),
            "server_ip": flow.get("srv.ip", flow.get("column_server", "")),
            "client_port": flow.get("cli.port"),
            "server_port": flow.get("srv.port"),
            "protocol": flow.get("proto.l4", flow.get("column_proto_l4", "")),
            "bytes_sent": flow.get("cli2srv.bytes", 0),
            "bytes_recv": flow.get("srv2cli.bytes", 0),
            "first_seen": flow.get("seen.first"),
            "last_seen": flow.get("seen.last"),
            "client_name": flow.get("cli.host", ""),
            "server_name": flow.get("srv.host", ""),
        })

    return parsed


if __name__ == "__main__":
    import asyncio

    async def test():
        print("Testing ntopng tools...")
        print(f"Base URL: {NTOPNG_BASE_URL}")

        hosts = await get_active_hosts()
        if "error" in hosts:
            print(f"Error: {hosts['error']}")
        else:
            parsed = parse_hosts_response(hosts)
            print(f"\nActive hosts: {len(parsed)}")
            for h in parsed[:5]:
                print(f"  {h['ip']} ({h['name']}) - {h['bytes_sent']}B sent")

    asyncio.run(test())
