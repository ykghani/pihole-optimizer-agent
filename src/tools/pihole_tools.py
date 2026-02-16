"""
PiHole CLI wrapper functions.

Each function executes a pihole command via subprocess and returns
the output. These are the building blocks that the MCP server exposes.
"""

import subprocess
import json
import re
from datetime import datetime
from typing import Optional
import logging

# Configure logging to stderr (not stdout - critical for MCP!)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Defaults to stderr
)
logger = logging.getLogger(__name__)


def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """
    Execute a shell command and return (stdout, stderr, return_code).
    
    Args:
        cmd: Command as list of strings, e.g., ["pihole", "-q", "google.com"]
        timeout: Maximum seconds to wait for command
        
    Returns:
        Tuple of (stdout, stderr, return_code)
        
    Why subprocess.run instead of os.system:
        - Captures output (os.system only returns exit code)
        - Proper error handling
        - Timeout support
        - No shell injection vulnerabilities (list form avoids shell=True)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,  # Capture both stdout and stderr
            text=True,            # Return strings, not bytes
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        return "", f"Command timed out after {timeout} seconds", 1
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return "", str(e), 1


def get_recent_queries(minutes: int = 60) -> dict:
    """
    Parse PiHole's query log to get recent DNS queries.

    The pihole log is at /var/log/pihole/pihole.log and contains lines like:
    Feb 13 10:30:45 dnsmasq[1234]: query[A] google.com from 192.168.1.100
    Feb 13 10:30:45 dnsmasq[1234]: forwarded google.com to 1.1.1.1
    Feb 13 10:30:46 dnsmasq[1234]: /etc/pihole/gravity.db doubleclick.net is 0.0.0.0

    Returns:
        Dict with 'queries', 'blocked', 'permitted' lists
    """
    from datetime import datetime, timedelta

    # Input validation: cap at 7 days to prevent memory exhaustion
    if minutes > 10080:  # 7 days
        logger.warning(f"Requested {minutes} minutes of data, capping at 10080 (7 days)")
        minutes = 10080

    cutoff_time = datetime.now() - timedelta(minutes=minutes)
    queries = []
    blocked = []
    permitted = []
    
    try:
        # Read the log file directly (faster than pihole -t for historical data)
        with open('/var/log/pihole/pihole.log', 'r') as f:
            for line in f:
                # Parse timestamp (assumes current year)
                try:
                    # Extract timestamp part: "Feb 13 10:30:45"
                    timestamp_str = line[:15]
                    timestamp = datetime.strptime(
                        f"{datetime.now().year} {timestamp_str}",
                        "%Y %b %d %H:%M:%S"
                    )
                    
                    if timestamp < cutoff_time:
                        continue
                    
                    # Parse query lines
                    if 'query[' in line:
                        # Extract domain and client
                        match = re.search(r'query\[(\w+)\] (\S+) from (\S+)', line)
                        if match:
                            query_type, domain, client = match.groups()
                            queries.append({
                                'timestamp': timestamp.isoformat(),
                                'type': query_type,
                                'domain': domain,
                                'client': client
                            })
                    
                    # Blocked queries contain "gravity.db" or "is 0.0.0.0"
                    if 'gravity.db' in line or 'is 0.0.0.0' in line:
                        match = re.search(r'(\S+) is 0\.0\.0\.0', line)
                        if match:
                            blocked.append(match.group(1))
                    
                    # Forwarded = permitted
                    if 'forwarded' in line:
                        match = re.search(r'forwarded (\S+) to', line)
                        if match:
                            permitted.append(match.group(1))
                            
                except (ValueError, AttributeError):
                    continue  # Skip malformed lines
                    
    except FileNotFoundError:
        logger.error("PiHole log file not found at /var/log/pihole/pihole.log")
        return {'error': 'Log file not found', 'queries': [], 'blocked': [], 'permitted': []}
    except PermissionError:
        logger.error("Permission denied reading PiHole log - run with appropriate permissions")
        return {'error': 'Permission denied', 'queries': [], 'blocked': [], 'permitted': []}
    
    return {
        'time_range_minutes': minutes,
        'total_queries': len(queries),
        'total_blocked': len(blocked),
        'total_permitted': len(permitted),
        'queries': queries[-100:],  # Last 100 queries (avoid huge responses)
        'blocked': list(set(blocked))[:50],  # Unique blocked domains
        'permitted': list(set(permitted))[:50]  # Unique permitted domains
    }


def get_top_blocked_domains(count: int = 20) -> list[dict]:
    """
    Get the most frequently blocked domains.
    
    Uses: pihole -c -j (chronometer in JSON mode)
    Or parses the database directly for more detail.
    """
    stdout, stderr, code = run_command(['pihole', '-c', '-j'])
    
    if code != 0:
        logger.warning(f"pihole -c -j failed, falling back to log parsing: {stderr}")
        # Fallback: count blocked domains from log
        result = get_recent_queries(minutes=1440)  # Last 24 hours
        from collections import Counter
        blocked_counts = Counter(result.get('blocked', []))
        return [
            {'domain': domain, 'count': cnt}
            for domain, cnt in blocked_counts.most_common(count)
        ]
    
    try:
        data = json.loads(stdout)
        # The JSON output structure varies by PiHole version
        # Try to extract top blocked domains
        top_blocked = data.get('top_blocked', {})
        # Pi-hole returns a dict of {domain: count} — convert to list format
        if isinstance(top_blocked, dict):
            return [
                {'domain': domain, 'count': cnt}
                for domain, cnt in sorted(top_blocked.items(), key=lambda x: x[1], reverse=True)
            ][:count]
        return top_blocked[:count]
    except json.JSONDecodeError:
        logger.error(f"Failed to parse pihole output as JSON: {stdout[:200]}")
        return []


def get_top_permitted_domains(count: int = 20) -> list[dict]:
    """
    Get the most frequently permitted (allowed) domains.
    """
    result = get_recent_queries(minutes=1440)  # Last 24 hours
    from collections import Counter
    permitted_counts = Counter(result.get('permitted', []))
    return [
        {'domain': domain, 'count': cnt}
        for domain, cnt in permitted_counts.most_common(count)
    ]


def whitelist_domain(domain: str, reason: str = "") -> dict:
    """
    Add a domain to PiHole's whitelist.
    
    Command: pihole -w <domain>
    
    Args:
        domain: The domain to whitelist (e.g., "example.com")
        reason: Why we're whitelisting (for audit log)
        
    Returns:
        Dict with 'success' bool and 'message' string
    """
    # Validate domain format (basic check)
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', domain):
        return {'success': False, 'message': f'Invalid domain format: {domain}'}
    
    stdout, stderr, code = run_command(['pihole', '-w', domain])
    
    # Log the action for audit trail
    audit_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': 'whitelist',
        'domain': domain,
        'reason': reason,
        'success': code == 0,
        'output': stdout or stderr
    }
    _write_audit_log(audit_entry)
    
    if code == 0:
        return {'success': True, 'message': f'Successfully whitelisted {domain}', 'reason': reason}
    else:
        return {'success': False, 'message': f'Failed to whitelist {domain}: {stderr}'}


def blacklist_domain(domain: str, reason: str = "") -> dict:
    """
    Add a domain to PiHole's blacklist.
    
    Command: pihole -b <domain>
    """
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', domain):
        return {'success': False, 'message': f'Invalid domain format: {domain}'}
    
    stdout, stderr, code = run_command(['pihole', '-b', domain])
    
    audit_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': 'blacklist',
        'domain': domain,
        'reason': reason,
        'success': code == 0,
        'output': stdout or stderr
    }
    _write_audit_log(audit_entry)
    
    if code == 0:
        return {'success': True, 'message': f'Successfully blacklisted {domain}', 'reason': reason}
    else:
        return {'success': False, 'message': f'Failed to blacklist {domain}: {stderr}'}


def test_domain_resolution(domain: str) -> dict:
    """
    Test if a domain is currently blocked by PiHole.
    
    Uses: dig <domain> @localhost
    
    If PiHole blocks it, dig returns 0.0.0.0
    If permitted, dig returns the actual IP(s)
    """
    stdout, stderr, code = run_command(['dig', '+short', domain, '@localhost'])
    
    if code != 0:
        return {'domain': domain, 'status': 'error', 'message': stderr}
    
    ips = stdout.strip().split('\n') if stdout.strip() else []
    
    # 0.0.0.0 or empty means blocked
    is_blocked = not ips or ips == ['0.0.0.0'] or ips == ['']
    
    return {
        'domain': domain,
        'status': 'blocked' if is_blocked else 'permitted',
        'resolved_ips': ips if not is_blocked else [],
        'message': 'Domain is blocked by PiHole' if is_blocked else f'Domain resolves to {", ".join(ips)}'
    }


def get_client_activity(hours: int = 24) -> list[dict]:
    """
    Get DNS query counts per client device.
    
    Useful for identifying:
    - Which devices are most active
    - Devices generating unusual traffic
    - IoT devices that might be compromised
    """
    result = get_recent_queries(minutes=hours * 60)
    
    from collections import Counter
    client_counts = Counter(q['client'] for q in result.get('queries', []))
    
    return [
        {'client': client, 'query_count': count}
        for client, count in client_counts.most_common()
    ]


def get_pihole_status() -> dict:
    """
    Get overall PiHole status and statistics.
    
    Uses: pihole status
    """
    stdout, stderr, code = run_command(['pihole', 'status'])
    
    # Parse the text output
    status = {
        'raw_output': stdout,
        'is_enabled': 'Pi-hole blocking is enabled' in stdout or '[✓] DNS' in stdout,
        'ftl_running': 'FTL is running' in stdout or '[✓] FTL' in stdout
    }
    
    # Try to get numeric stats via the API/JSON
    json_out, _, json_code = run_command(['pihole', '-c', '-j'])
    if json_code == 0:
        try:
            stats = json.loads(json_out)
            status.update({
                'domains_blocked': stats.get('domains_being_blocked', 0),
                'queries_today': stats.get('dns_queries_today', 0),
                'blocked_today': stats.get('ads_blocked_today', 0),
                'percent_blocked': stats.get('ads_percentage_today', 0)
            })
        except json.JSONDecodeError:
            pass
    
    return status


def get_gravity_info() -> dict:
    """
    Get information about PiHole's blocklists (gravity).
    
    Useful for understanding current blocking coverage.
    """
    stdout, stderr, code = run_command(['pihole', '-g', '-l'])  # List gravity sources
    
    return {
        'raw_output': stdout,
        'last_update': _get_gravity_last_update()
    }


def _get_gravity_last_update() -> Optional[str]:
    """Get timestamp of last gravity update."""
    try:
        import os
        stat = os.stat('/etc/pihole/gravity.db')
        return datetime.fromtimestamp(stat.st_mtime).isoformat()
    except:
        return None


def _write_audit_log(entry: dict) -> None:
    """Append an entry to the audit log."""
    import os
    log_dir = os.path.expanduser('~/pihole-agent/logs')
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'audit.jsonl')
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + '\n')


# Quick test when run directly
if __name__ == '__main__':
    print("Testing PiHole tools...")
    print("\n1. PiHole Status:")
    print(json.dumps(get_pihole_status(), indent=2))
    
    print("\n2. Testing domain resolution (google.com):")
    print(json.dumps(test_domain_resolution('google.com'), indent=2))
    
    print("\n3. Testing domain resolution (doubleclick.net - should be blocked):")
    print(json.dumps(test_domain_resolution('doubleclick.net'), indent=2))
    
    print("\n4. Recent queries (last 5 minutes):")
    result = get_recent_queries(minutes=5)
    print(f"Total queries: {result['total_queries']}")
    print(f"Blocked: {result['total_blocked']}")
    print(f"Permitted: {result['total_permitted']}")
