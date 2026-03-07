"""
Suricata eve.json parser and alert extraction tools.

Reads Suricata's structured JSON event log incrementally using a file-offset
bookmark. Only new lines since the last run are processed, preventing
duplicate alerts and keeping each cycle fast.

Security: All strings extracted from eve.json are UNTRUSTED (attacker-controlled
network traffic). They must be sanitized before inclusion in any LLM prompt.
"""

import json
import os
import re
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Default paths
EVE_JSON_PATH = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
FAST_LOG_PATH = os.getenv("SURICATA_FAST_LOG", "/var/log/suricata/fast.log")
OFFSET_FILE = os.path.expanduser("~/.soc-agent/eve_offset.json")

# Safety: max events per collection cycle to prevent resource exhaustion
MAX_EVENTS_PER_CYCLE = 1000


def _load_offset() -> int:
    """Load the last-read byte offset from the bookmark file."""
    try:
        with open(OFFSET_FILE, "r") as f:
            data = json.load(f)
            return data.get("offset", 0)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return 0


def _save_offset(offset: int) -> None:
    """Save the current byte offset to the bookmark file."""
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    with open(OFFSET_FILE, "w") as f:
        json.dump({"offset": offset, "updated_at": datetime.now().isoformat()}, f)


def sanitize_for_prompt(raw_string: str, max_length: int = 253) -> str:
    """
    Sanitize an untrusted string before including it in an LLM prompt.

    Defends against prompt injection via network traffic (DNS queries,
    HTTP headers, TLS SNI fields, etc.).

    - Truncates to max_length (DNS labels max 253 chars)
    - Strips non-printable characters
    - Removes known prompt delimiter patterns
    """
    s = raw_string[:max_length]
    # Remove non-printable chars except basic whitespace
    s = re.sub(r"[^\x20-\x7E]", "", s)
    # Remove characters that look like prompt delimiters
    s = s.replace("<|", "").replace("|>", "")
    s = s.replace("```", "")
    s = s.replace("<<", "").replace(">>", "")
    # Remove XML-like tags that could confuse the model
    s = re.sub(r"</?[a-zA-Z][^>]*>", "", s)
    return s


def _parse_eve_line(line: str) -> Optional[dict]:
    """
    Parse a single line from eve.json into a structured dict.

    Returns None for malformed lines or event types we don't care about.
    """
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = event.get("event_type")
    if event_type not in ("alert", "dns", "tls", "flow", "http"):
        return None

    parsed = {
        "timestamp": event.get("timestamp", ""),
        "event_type": event_type,
        "src_ip": event.get("src_ip", ""),
        "dest_ip": event.get("dest_ip", ""),
        "src_port": event.get("src_port"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto", ""),
    }

    # Alert-specific fields
    if event_type == "alert":
        alert = event.get("alert", {})
        parsed.update({
            "signature": alert.get("signature", ""),
            "signature_id": alert.get("signature_id"),
            "severity": alert.get("severity"),
            "category": alert.get("category", ""),
        })

    # DNS-specific fields
    if event_type == "dns":
        dns = event.get("dns", {})
        parsed["dns_rrname"] = dns.get("rrname", "")
        parsed["dns_rrtype"] = dns.get("rrtype", "")

    # TLS-specific fields
    if event_type == "tls":
        tls = event.get("tls", {})
        parsed["tls_sni"] = tls.get("sni", "")

    # HTTP-specific fields
    if event_type == "http":
        http = event.get("http", {})
        parsed["http_hostname"] = http.get("hostname", "")
        parsed["http_url"] = http.get("url", "")

    return parsed


def get_new_alerts(
    eve_path: str = EVE_JSON_PATH,
    max_events: int = MAX_EVENTS_PER_CYCLE,
    alert_only: bool = False,
) -> dict:
    """
    Read new events from eve.json since the last offset.

    Uses incremental reading: starts at the last-saved byte offset, reads
    only new lines, and saves the new offset. This makes each cycle O(new events)
    not O(total log size).

    Args:
        eve_path: Path to eve.json file
        max_events: Maximum events to read per cycle (prevents resource exhaustion)
        alert_only: If True, only return alert events (skip dns/tls/flow/http)

    Returns:
        Dict with 'alerts', 'dns_events', 'tls_events', 'flow_events',
        'total_new_lines', and 'truncated' flag.
    """
    offset = _load_offset()
    alerts = []
    dns_events = []
    tls_events = []
    flow_events = []
    http_events = []
    lines_read = 0
    truncated = False

    try:
        file_size = os.path.getsize(eve_path)
    except OSError as e:
        logger.error(f"Cannot stat {eve_path}: {e}")
        return {
            "error": str(e),
            "alerts": [],
            "dns_events": [],
            "tls_events": [],
            "flow_events": [],
            "http_events": [],
            "total_new_lines": 0,
            "truncated": False,
        }

    # If file was rotated (smaller than offset), reset to beginning
    if file_size < offset:
        logger.info(f"eve.json appears rotated (size {file_size} < offset {offset}), resetting")
        offset = 0

    try:
        with open(eve_path, "r") as f:
            f.seek(offset)

            # Use readline() instead of iteration so f.tell() works correctly.
            # Python's for-loop iterator uses read-ahead buffering which disables tell().
            while True:
                line = f.readline()
                if not line:
                    break

                lines_read += 1

                if lines_read > max_events:
                    truncated = True
                    logger.warning(
                        f"Hit max_events cap ({max_events}). "
                        f"Remaining events will be read next cycle."
                    )
                    break

                parsed = _parse_eve_line(line.strip())
                if parsed is None:
                    continue

                event_type = parsed["event_type"]
                if event_type == "alert":
                    alerts.append(parsed)
                elif event_type == "dns" and not alert_only:
                    dns_events.append(parsed)
                elif event_type == "tls" and not alert_only:
                    tls_events.append(parsed)
                elif event_type == "flow" and not alert_only:
                    flow_events.append(parsed)
                elif event_type == "http" and not alert_only:
                    http_events.append(parsed)

            # Save new offset (current file position)
            new_offset = f.tell()
            _save_offset(new_offset)

    except FileNotFoundError:
        logger.error(f"eve.json not found at {eve_path}")
        return {
            "error": f"File not found: {eve_path}",
            "alerts": [],
            "dns_events": [],
            "tls_events": [],
            "flow_events": [],
            "http_events": [],
            "total_new_lines": 0,
            "truncated": False,
        }
    except PermissionError:
        logger.error(f"Permission denied reading {eve_path}")
        return {
            "error": f"Permission denied: {eve_path}",
            "alerts": [],
            "dns_events": [],
            "tls_events": [],
            "flow_events": [],
            "http_events": [],
            "total_new_lines": 0,
            "truncated": False,
        }

    logger.info(
        f"Read {lines_read} new lines from eve.json: "
        f"{len(alerts)} alerts, {len(dns_events)} DNS, "
        f"{len(tls_events)} TLS, {len(flow_events)} flows"
    )

    return {
        "alerts": alerts,
        "dns_events": dns_events,
        "tls_events": tls_events,
        "flow_events": flow_events,
        "http_events": http_events,
        "total_new_lines": lines_read,
        "truncated": truncated,
    }


def get_alert_count_by_severity(
    eve_path: str = EVE_JSON_PATH,
    hours: int = 24,
) -> dict:
    """
    Count alerts by severity level for the last N hours.

    This reads from the current position backwards (tail), useful for
    quick summary statistics without full incremental processing.
    """
    from datetime import timedelta

    cutoff = datetime.now() - timedelta(hours=hours)
    counts = {1: 0, 2: 0, 3: 0, 4: 0}

    try:
        with open(eve_path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") != "alert":
                        continue
                    ts = event.get("timestamp", "")
                    # Suricata timestamps: "2026-03-01T14:30:00.123456+0000"
                    event_time = datetime.fromisoformat(ts[:19])
                    if event_time < cutoff:
                        continue
                    severity = event.get("alert", {}).get("severity", 4)
                    if severity in counts:
                        counts[severity] += 1
                except (json.JSONDecodeError, ValueError):
                    continue
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Cannot read {eve_path}: {e}")
        return {"error": str(e), "counts": counts}

    return {
        "hours": hours,
        "critical": counts[1],
        "major": counts[2],
        "medium": counts[3],
        "info": counts[4],
        "total": sum(counts.values()),
    }


def reset_offset() -> None:
    """Reset the eve.json offset to 0. Used for testing or after log rotation."""
    _save_offset(0)
    logger.info("Eve.json offset reset to 0")


if __name__ == "__main__":
    print("Testing Suricata tools...")
    print(f"\neve.json path: {EVE_JSON_PATH}")
    print(f"Offset file: {OFFSET_FILE}")

    result = get_new_alerts()
    print(f"\nNew alerts: {len(result['alerts'])}")
    print(f"DNS events: {len(result['dns_events'])}")
    print(f"TLS events: {len(result['tls_events'])}")
    print(f"Flow events: {len(result['flow_events'])}")
    print(f"Truncated: {result['truncated']}")

    if result["alerts"]:
        print(f"\nFirst alert: {json.dumps(result['alerts'][0], indent=2)}")
