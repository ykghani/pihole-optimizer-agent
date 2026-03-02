"""
LangGraph state definition for the SOC agent workflow.

This TypedDict defines all data that flows through the SOC agent's
LangGraph nodes. Each node reads from and writes to this state.
"""

from typing import TypedDict, Optional


class SOCState(TypedDict):
    """
    State that flows through the SOC LangGraph workflow.

    Organized by pipeline stage:
    1. Collection — raw data from sources
    2. Processing — deduplicated, enriched, correlated
    3. Classification — severity labels and recommended actions
    4. Actions — what was proposed, approved, and executed
    5. Routing — what to email, what to log
    6. Meta — run metadata, errors, safety budget
    """

    # --- Collection ---
    suricata_alerts: list        # List of SuricataAlert dicts
    dns_events: list             # List of PiholeDNSEvent dicts
    ntopng_flows: list           # List of NtopngFlow dicts
    ntopng_anomalies: list       # List of NtopngHostAnomaly dicts
    collection_errors: list      # Which sources failed

    # --- Processing ---
    deduplicated_events: list    # After dedup (hashed clusters with count)
    enriched_events: list        # After whois/rDNS enrichment
    correlated_findings: list    # Cross-source CorrelatedFinding dicts

    # --- Classification ---
    classifications: list        # AlertClassification dicts from Claude/heuristics
    false_positives: list        # Auto-suppressed FP signature IDs

    # --- Actions ---
    proposed_actions: list       # ProposedAction dicts (before safety check)
    approved_actions: list       # Actions that passed safety checks
    executed_actions: list       # ExecutedAction dicts (after execution)
    held_for_human: list         # Actions requiring human approval

    # --- Routing ---
    immediate_alerts: list       # HIGH/CRITICAL findings to email immediately
    digest_alerts: list          # MEDIUM findings for hourly digest
    log_only: list               # LOW/FP findings to log only

    # --- Neo4j ---
    neo4j_writes: list           # Graph operations to persist

    # --- Meta ---
    run_id: str
    run_timestamp: str
    soc_mode: str                # shadow | recommend | auto_suppress | active
    safety_budget: dict          # Remaining action budget for this run
    sources_available: list      # Which sources returned data
    errors: list                 # Errors accumulated during run


def create_initial_state(run_id: str, run_timestamp: str, soc_mode: str) -> SOCState:
    """Create an empty initial state for a new SOC agent run."""
    return SOCState(
        # Collection
        suricata_alerts=[],
        dns_events=[],
        ntopng_flows=[],
        ntopng_anomalies=[],
        collection_errors=[],
        # Processing
        deduplicated_events=[],
        enriched_events=[],
        correlated_findings=[],
        # Classification
        classifications=[],
        false_positives=[],
        # Actions
        proposed_actions=[],
        approved_actions=[],
        executed_actions=[],
        held_for_human=[],
        # Routing
        immediate_alerts=[],
        digest_alerts=[],
        log_only=[],
        # Neo4j
        neo4j_writes=[],
        # Meta
        run_id=run_id,
        run_timestamp=run_timestamp,
        soc_mode=soc_mode,
        safety_budget={
            "actions_remaining": 3,
            "blocks_remaining": 2,
            "api_calls_remaining": 30,
            "enrichment_remaining": 20,
        },
        sources_available=[],
        errors=[],
    )
