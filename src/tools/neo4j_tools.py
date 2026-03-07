"""
Neo4j graph database tools for the SOC agent's long-term memory.

The knowledge graph stores devices, domains, IPs, alerts, and findings
with relationships that enable cross-tool correlation queries.

Uses the official neo4j Python driver with Bolt protocol (port 7687).
All writes use MERGE (upsert) semantics to prevent duplicates.
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# Lazy driver initialization (avoid import errors if neo4j not installed)
_driver = None


def _get_driver():
    """Lazy-initialize the Neo4j driver."""
    global _driver
    if _driver is None:
        try:
            from neo4j import GraphDatabase
            if not NEO4J_PASSWORD:
                logger.error("NEO4J_PASSWORD not set in .env")
                return None
            _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            logger.info(f"Connected to Neo4j at {NEO4J_URI}")
        except ImportError:
            logger.error("neo4j package not installed. Run: uv add neo4j")
            return None
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            return None
    return _driver


def _run_query(query: str, parameters: Optional[dict] = None) -> list[dict]:
    """Execute a Cypher query and return results as list of dicts."""
    driver = _get_driver()
    if driver is None:
        return []

    try:
        with driver.session() as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]
    except Exception as e:
        logger.error(f"Neo4j query failed: {e}\nQuery: {query}")
        return []


def _run_write(query: str, parameters: Optional[dict] = None) -> bool:
    """Execute a write query. Returns True on success."""
    driver = _get_driver()
    if driver is None:
        return False

    try:
        with driver.session() as session:
            session.run(query, parameters or {})
            return True
    except Exception as e:
        logger.error(f"Neo4j write failed: {e}\nQuery: {query}")
        return False


# ---------------------------------------------------------------------------
# Device operations
# ---------------------------------------------------------------------------

def upsert_device(ip: str, mac: str = "", hostname: str = "", is_known: bool = False) -> bool:
    """Create or update a Device node."""
    return _run_write(
        """
        MERGE (d:Device {ip: $ip})
        ON CREATE SET d.mac = $mac, d.hostname = $hostname,
                      d.first_seen = datetime(), d.last_seen = datetime(),
                      d.is_known = $is_known
        ON MATCH SET  d.last_seen = datetime(),
                      d.mac = CASE WHEN $mac <> '' THEN $mac ELSE d.mac END,
                      d.hostname = CASE WHEN $hostname <> '' THEN $hostname ELSE d.hostname END
        """,
        {"ip": ip, "mac": mac, "hostname": hostname, "is_known": is_known},
    )


def get_device(ip: str) -> Optional[dict]:
    """Get a Device node by IP."""
    results = _run_query("MATCH (d:Device {ip: $ip}) RETURN d", {"ip": ip})
    return results[0]["d"] if results else None


def get_all_known_devices() -> list[dict]:
    """Get all known devices (for new-device detection)."""
    return _run_query(
        "MATCH (d:Device) RETURN d.ip AS ip, d.mac AS mac, d.hostname AS hostname, "
        "d.last_seen AS last_seen, d.is_known AS is_known"
    )


# ---------------------------------------------------------------------------
# Domain operations
# ---------------------------------------------------------------------------

def upsert_domain(name: str, category: str = "") -> bool:
    """Create or update a Domain node."""
    return _run_write(
        """
        MERGE (d:Domain {name: $name})
        ON CREATE SET d.first_seen = datetime(), d.last_seen = datetime(),
                      d.category = $category
        ON MATCH SET  d.last_seen = datetime()
        """,
        {"name": name, "category": category},
    )


# ---------------------------------------------------------------------------
# IP operations (external IPs)
# ---------------------------------------------------------------------------

def upsert_external_ip(
    address: str,
    asn: str = "",
    org: str = "",
    country: str = "",
    rdns: str = "",
) -> bool:
    """Create or update an external IP node with enrichment data."""
    return _run_write(
        """
        MERGE (i:IP {address: $address})
        ON CREATE SET i.asn = $asn, i.org = $org, i.country = $country,
                      i.rdns = $rdns, i.first_seen = datetime(),
                      i.last_seen = datetime(), i.enriched_at = datetime()
        ON MATCH SET  i.last_seen = datetime(),
                      i.asn = CASE WHEN $asn <> '' THEN $asn ELSE i.asn END,
                      i.org = CASE WHEN $org <> '' THEN $org ELSE i.org END,
                      i.country = CASE WHEN $country <> '' THEN $country ELSE i.country END,
                      i.rdns = CASE WHEN $rdns <> '' THEN $rdns ELSE i.rdns END,
                      i.enriched_at = datetime()
        """,
        {"address": address, "asn": asn, "org": org, "country": country, "rdns": rdns},
    )


# ---------------------------------------------------------------------------
# Alert operations
# ---------------------------------------------------------------------------

def upsert_alert(
    alert_id: str,
    signature: str,
    severity: str,
    source: str,
    timestamp: str,
    classification: str = "",
    description: str = "",
    recommended_action: str = "",
) -> bool:
    """Create or update an Alert node."""
    return _run_write(
        """
        MERGE (a:Alert {alert_id: $alert_id})
        ON CREATE SET a.signature = $signature, a.severity = $severity,
                      a.source = $source, a.timestamp = datetime($timestamp),
                      a.classification = $classification,
                      a.description = $description,
                      a.recommended_action = $recommended_action,
                      a.created_at = datetime()
        ON MATCH SET  a.classification = CASE WHEN $classification <> '' THEN $classification ELSE a.classification END,
                      a.description = CASE WHEN $description <> '' THEN $description ELSE a.description END,
                      a.recommended_action = CASE WHEN $recommended_action <> '' THEN $recommended_action ELSE a.recommended_action END
        """,
        {
            "alert_id": alert_id,
            "signature": signature,
            "severity": severity,
            "source": source,
            "timestamp": timestamp,
            "classification": classification,
            "description": description,
            "recommended_action": recommended_action,
        },
    )


# ---------------------------------------------------------------------------
# Finding operations
# ---------------------------------------------------------------------------

def upsert_finding(
    finding_id: str,
    classification: str,
    description: str,
    correlated_sources: list[str],
    timestamp: str = "",
) -> bool:
    """Create or update a Finding node."""
    if not timestamp:
        timestamp = datetime.now().isoformat()

    return _run_write(
        """
        MERGE (f:Finding {finding_id: $finding_id})
        ON CREATE SET f.classification = $classification,
                      f.description = $description,
                      f.correlated_sources = $sources,
                      f.timestamp = datetime($timestamp),
                      f.created_at = datetime()
        ON MATCH SET  f.classification = $classification,
                      f.description = $description
        """,
        {
            "finding_id": finding_id,
            "classification": classification,
            "description": description,
            "sources": correlated_sources,
            "timestamp": timestamp,
        },
    )


# ---------------------------------------------------------------------------
# Relationship operations
# ---------------------------------------------------------------------------

def link_device_queried_domain(device_ip: str, domain_name: str, blocked: bool = False) -> bool:
    """Create a QUERIED relationship between a Device and Domain."""
    return _run_write(
        """
        MATCH (d:Device {ip: $device_ip})
        MATCH (dom:Domain {name: $domain_name})
        MERGE (d)-[r:QUERIED]->(dom)
        ON CREATE SET r.count = 1, r.first_seen = datetime(),
                      r.last_seen = datetime(), r.blocked = $blocked
        ON MATCH SET  r.count = r.count + 1, r.last_seen = datetime()
        """,
        {"device_ip": device_ip, "domain_name": domain_name, "blocked": blocked},
    )


def link_domain_resolved_to_ip(domain_name: str, ip_address: str) -> bool:
    """Create a RESOLVED_TO relationship between a Domain and IP."""
    return _run_write(
        """
        MATCH (dom:Domain {name: $domain_name})
        MATCH (ip:IP {address: $ip_address})
        MERGE (dom)-[r:RESOLVED_TO]->(ip)
        ON CREATE SET r.first_seen = datetime(), r.last_seen = datetime()
        ON MATCH SET  r.last_seen = datetime()
        """,
        {"domain_name": domain_name, "ip_address": ip_address},
    )


def link_alert_targeted_device(alert_id: str, device_ip: str) -> bool:
    """Create a TARGETED relationship between an Alert and Device."""
    return _run_write(
        """
        MATCH (a:Alert {alert_id: $alert_id})
        MATCH (d:Device {ip: $device_ip})
        MERGE (a)-[:TARGETED]->(d)
        """,
        {"alert_id": alert_id, "device_ip": device_ip},
    )


def link_alert_involved_ip(alert_id: str, ip_address: str) -> bool:
    """Create an INVOLVED relationship between an Alert and external IP."""
    return _run_write(
        """
        MATCH (a:Alert {alert_id: $alert_id})
        MATCH (ip:IP {address: $ip_address})
        MERGE (a)-[:INVOLVED]->(ip)
        """,
        {"alert_id": alert_id, "ip_address": ip_address},
    )


def link_finding_derived_from_alert(finding_id: str, alert_id: str) -> bool:
    """Create a DERIVED_FROM relationship between a Finding and Alert."""
    return _run_write(
        """
        MATCH (f:Finding {finding_id: $finding_id})
        MATCH (a:Alert {alert_id: $alert_id})
        MERGE (f)-[:DERIVED_FROM]->(a)
        """,
        {"finding_id": finding_id, "alert_id": alert_id},
    )


# ---------------------------------------------------------------------------
# Query operations (for agent CLASSIFY and CORRELATE nodes)
# ---------------------------------------------------------------------------

def count_fp_for_signature(signature: str, days: int = 7) -> int:
    """
    Count how many times a signature has been classified as false_positive.

    Used by the FP suppression heuristic: if >5 in 7 days, auto-suppress.
    """
    results = _run_query(
        """
        MATCH (a:Alert {signature: $sig, classification: 'false_positive'})
        WHERE a.created_at > datetime() - duration({days: $days})
        RETURN count(a) AS fp_count
        """,
        {"sig": signature, "days": days},
    )
    return results[0]["fp_count"] if results else 0


def get_device_alert_history(device_ip: str, days: int = 7) -> list[dict]:
    """Get alert history for a device over the last N days."""
    return _run_query(
        """
        MATCH (d:Device {ip: $ip})<-[:TARGETED]-(a:Alert)
        WHERE a.created_at > datetime() - duration({days: $days})
        RETURN a.alert_id AS alert_id, a.signature AS signature,
               a.severity AS severity, a.classification AS classification,
               a.timestamp AS timestamp
        ORDER BY a.timestamp DESC
        LIMIT 50
        """,
        {"ip": device_ip, "days": days},
    )


def get_cross_tool_correlated_devices() -> list[dict]:
    """
    Find devices that appear in both PiHole blocks and Suricata alerts.

    This is the core cross-tool correlation query.
    """
    return _run_query(
        """
        MATCH (d:Device)-[:QUERIED {blocked: true}]->(dom:Domain)
        MATCH (d)-[:TARGETED]-(a:Alert)
        RETURN DISTINCT d.ip AS ip, d.hostname AS hostname,
               count(DISTINCT dom) AS blocked_domains,
               count(DISTINCT a) AS alert_count
        ORDER BY alert_count DESC
        """
    )


def get_stale_devices(hours: int = 24) -> list[dict]:
    """Find devices not seen in the last N hours (possible offline/compromised)."""
    return _run_query(
        """
        MATCH (d:Device)
        WHERE d.last_seen < datetime() - duration({hours: $hours})
        RETURN d.ip AS ip, d.hostname AS hostname, d.last_seen AS last_seen
        ORDER BY d.last_seen ASC
        """,
        {"hours": hours},
    )


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

def enforce_retention(days: int = 7) -> int:
    """
    Delete nodes older than the retention period.

    Returns the number of deleted nodes.
    """
    results = _run_query(
        """
        MATCH (n)
        WHERE n.created_at < datetime() - duration({days: $days})
           OR n.last_seen < datetime() - duration({days: $days})
        WITH n LIMIT 1000
        DETACH DELETE n
        RETURN count(n) AS deleted
        """,
        {"days": days},
    )
    count = results[0]["deleted"] if results else 0
    if count > 0:
        logger.info(f"Retention: deleted {count} nodes older than {days} days")
    return count


def get_neo4j_stats() -> dict:
    """
    Return basic graph stats (node/relationship counts by label).

    Used for smoke-testing connectivity and for the performance baseline.
    Returns an error dict if Neo4j is unreachable.
    """
    driver = _get_driver()
    if driver is None:
        return {"error": "Cannot connect to Neo4j — check NEO4J_PASSWORD and that Docker is running"}

    try:
        driver.verify_connectivity()
    except Exception as e:
        return {"error": f"Neo4j connectivity check failed: {e}"}

    counts = {}
    for label in ("Device", "Domain", "IP", "Alert", "Finding"):
        results = _run_query(f"MATCH (n:{label}) RETURN count(n) AS c")
        counts[label.lower() + "_count"] = results[0]["c"] if results else 0

    rel_results = _run_query("MATCH ()-[r]->() RETURN count(r) AS c")
    counts["relationship_count"] = rel_results[0]["c"] if rel_results else 0
    counts["neo4j_uri"] = NEO4J_URI
    counts["status"] = "ok"
    return counts


def close() -> None:
    """Close the Neo4j driver connection."""
    global _driver
    if _driver:
        _driver.close()
        _driver = None
        logger.info("Neo4j connection closed")
