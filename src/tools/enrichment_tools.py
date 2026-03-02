"""
IP enrichment tools: reverse DNS, whois/ASN lookup, and abuse scoring.

These tools add context to external IPs seen in Suricata alerts and
ntopng flows. Enrichment results are cached to avoid redundant lookups
and limit external API calls.

Security: Enrichment uses hardcoded external resolvers (1.1.1.1), not
local DNS, preventing a local DNS poisoner from influencing results.
"""

import json
import os
import re
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Cache file for enrichment results (avoid redundant lookups)
ENRICHMENT_CACHE_FILE = os.path.expanduser("~/.soc-agent/enrichment_cache.json")
CACHE_TTL_HOURS = 24

# Rate limiting: max lookups per run
MAX_ENRICHMENT_PER_RUN = int(os.getenv("MAX_ENRICHMENT_PER_RUN", "20"))

# External resolver for rDNS (not local, to prevent poisoning)
RDNS_RESOLVER = "1.1.1.1"

# Enrichment mode: "external" (default) or "local" (no outbound queries)
ENRICHMENT_MODE = os.getenv("ENRICHMENT_MODE", "external")


def _load_cache() -> dict:
    """Load enrichment cache from disk."""
    try:
        with open(ENRICHMENT_CACHE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    """Save enrichment cache to disk."""
    os.makedirs(os.path.dirname(ENRICHMENT_CACHE_FILE), exist_ok=True)
    with open(ENRICHMENT_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def _is_cache_fresh(entry: dict) -> bool:
    """Check if a cache entry is still within the TTL."""
    try:
        enriched_at = datetime.fromisoformat(entry.get("enriched_at", ""))
        return datetime.now() - enriched_at < timedelta(hours=CACHE_TTL_HOURS)
    except (ValueError, TypeError):
        return False


def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup for an IP address.

    Uses an external resolver (1.1.1.1) to prevent local DNS poisoning
    from influencing enrichment results.
    """
    try:
        result = subprocess.run(
            ["dig", "+short", "-x", ip, f"@{RDNS_RESOLVER}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        rdns = result.stdout.strip()
        # dig returns trailing dot for FQDNs
        if rdns and rdns != ip:
            return rdns.rstrip(".")
        return None
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.warning(f"rDNS lookup failed for {ip}: {e}")
        return None


def whois_lookup(ip: str) -> dict:
    """
    Perform a whois lookup for an IP address.

    Extracts: ASN, organization name, country, and abuse contact.
    """
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout

        # Parse key fields from whois output
        asn = None
        org = None
        country = None

        for line in output.split("\n"):
            line_lower = line.lower().strip()
            if line_lower.startswith("originas") or line_lower.startswith("origin:"):
                match = re.search(r"(AS\d+)", line, re.IGNORECASE)
                if match:
                    asn = match.group(1).upper()
            elif line_lower.startswith("orgname:") or line_lower.startswith("org-name:"):
                org = line.split(":", 1)[1].strip()
            elif line_lower.startswith("netname:") and not org:
                org = line.split(":", 1)[1].strip()
            elif line_lower.startswith("country:"):
                country = line.split(":", 1)[1].strip().upper()

        return {"asn": asn, "org": org, "country": country}

    except subprocess.TimeoutExpired:
        logger.warning(f"Whois lookup timed out for {ip}")
        return {"asn": None, "org": None, "country": None}
    except Exception as e:
        logger.warning(f"Whois lookup failed for {ip}: {e}")
        return {"asn": None, "org": None, "country": None}


def enrich_ip(ip: str, use_cache: bool = True) -> dict:
    """
    Fully enrich an external IP address with rDNS, whois, and ASN data.

    Uses cache to avoid redundant lookups. Respects ENRICHMENT_MODE:
    - "external": Full whois + rDNS via external resolvers
    - "local": No outbound queries (returns cached data or empty)

    Returns:
        Dict with ip, reverse_dns, asn, org, country, enriched_at
    """
    # Check cache first
    if use_cache:
        cache = _load_cache()
        if ip in cache and _is_cache_fresh(cache[ip]):
            logger.debug(f"Cache hit for {ip}")
            return cache[ip]

    if ENRICHMENT_MODE == "local":
        logger.debug(f"Local-only mode: skipping external enrichment for {ip}")
        return {
            "ip": ip,
            "reverse_dns": None,
            "asn": None,
            "org": None,
            "country": None,
            "enriched_at": datetime.now().isoformat(),
            "mode": "local",
        }

    # Perform lookups
    rdns = reverse_dns(ip)
    whois_data = whois_lookup(ip)

    enrichment = {
        "ip": ip,
        "reverse_dns": rdns,
        "asn": whois_data.get("asn"),
        "org": whois_data.get("org"),
        "country": whois_data.get("country"),
        "enriched_at": datetime.now().isoformat(),
        "mode": "external",
    }

    # Update cache
    if use_cache:
        cache = _load_cache()
        cache[ip] = enrichment
        _save_cache(cache)

    return enrichment


def enrich_batch(ips: list[str], max_lookups: int = MAX_ENRICHMENT_PER_RUN) -> dict[str, dict]:
    """
    Enrich a batch of IPs, respecting rate limits.

    Args:
        ips: List of IP addresses to enrich
        max_lookups: Maximum new lookups (cached results don't count)

    Returns:
        Dict mapping IP -> enrichment data
    """
    results = {}
    new_lookups = 0

    cache = _load_cache()

    for ip in ips:
        # Check cache first (doesn't count toward rate limit)
        if ip in cache and _is_cache_fresh(cache[ip]):
            results[ip] = cache[ip]
            continue

        # Rate limit new lookups
        if new_lookups >= max_lookups:
            logger.warning(
                f"Enrichment rate limit reached ({max_lookups}). "
                f"Remaining IPs will be enriched next cycle."
            )
            break

        results[ip] = enrich_ip(ip, use_cache=True)
        new_lookups += 1

    logger.info(f"Enriched {len(results)} IPs ({new_lookups} new lookups, "
                f"{len(results) - new_lookups} cached)")
    return results


def clear_cache() -> None:
    """Clear the enrichment cache. Used for testing."""
    try:
        os.remove(ENRICHMENT_CACHE_FILE)
        logger.info("Enrichment cache cleared")
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    print("Testing enrichment tools...")
    print(f"Mode: {ENRICHMENT_MODE}")

    test_ip = "1.1.1.1"
    print(f"\nEnriching {test_ip}:")
    result = enrich_ip(test_ip)
    print(json.dumps(result, indent=2))
