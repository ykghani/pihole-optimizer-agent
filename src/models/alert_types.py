"""
Pydantic models for SOC agent alert processing.

These models enforce strict typing on all data flowing through the pipeline,
especially Claude's classification output — preventing prompt injection
from producing actions outside the allowed schema.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    SURICATA = "suricata"
    PIHOLE = "pihole"
    NTOPNG = "ntopng"


class SuricataSeverity(int, Enum):
    """Suricata alert priorities (1=critical, 4=info)."""
    CRITICAL = 1
    MAJOR = 2
    MEDIUM = 3
    INFO = 4


class Classification(str, Enum):
    """Agent classification levels for findings."""
    FALSE_POSITIVE = "false_positive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendedAction(str, Enum):
    """Allowed actions the agent can propose. No other actions are possible."""
    SUPPRESS = "suppress"
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_DEVICE = "isolate_device"
    NONE = "none"


# ---------------------------------------------------------------------------
# Raw event models (from data sources)
# ---------------------------------------------------------------------------

class SuricataAlert(BaseModel):
    """A single alert parsed from Suricata's eve.json."""
    timestamp: str
    event_type: str = "alert"
    src_ip: str
    dest_ip: str
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    signature: str = ""
    signature_id: Optional[int] = None
    severity: Optional[int] = None
    category: str = ""
    # DNS metadata (present on DNS events)
    dns_rrname: Optional[str] = None
    # TLS metadata (present on TLS events)
    tls_sni: Optional[str] = None


class NtopngFlow(BaseModel):
    """A flow record from ntopng REST API."""
    client_ip: str
    server_ip: str
    client_port: Optional[int] = None
    server_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    client_name: Optional[str] = None
    server_name: Optional[str] = None


class NtopngHostAnomaly(BaseModel):
    """An anomaly detected by ntopng for a specific host."""
    ip: str
    hostname: Optional[str] = None
    anomaly_type: str
    description: str
    severity: Optional[str] = None
    timestamp: Optional[str] = None


class PiholeDNSEvent(BaseModel):
    """A DNS query event from PiHole logs."""
    timestamp: str
    query_type: str
    domain: str
    client: str
    blocked: bool = False


# ---------------------------------------------------------------------------
# Enrichment models
# ---------------------------------------------------------------------------

class IPEnrichment(BaseModel):
    """Enrichment data for an external IP address."""
    ip: str
    reverse_dns: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    abuse_score: Optional[int] = None
    enriched_at: str = Field(default_factory=lambda: datetime.now().isoformat())


# ---------------------------------------------------------------------------
# Classification models (Claude output — strictly validated)
# ---------------------------------------------------------------------------

class AlertClassification(BaseModel):
    """
    Claude's classification output for a single alert/finding.

    This model uses Literal types to prevent Claude from proposing
    actions outside the allowed set — a key defense against prompt injection.
    """
    alert_id: str
    classification: Classification
    description: str = Field(max_length=500)
    recommended_action: RecommendedAction
    confidence: int = Field(ge=0, le=100)
    correlated_sources: list[str] = Field(default_factory=list)


class ClassificationBatch(BaseModel):
    """Batch of classifications returned by Claude."""
    classifications: list[AlertClassification]


# ---------------------------------------------------------------------------
# Correlation models
# ---------------------------------------------------------------------------

class CorrelatedFinding(BaseModel):
    """A finding that correlates evidence from multiple sources."""
    finding_id: str
    sources: list[AlertSource]
    primary_alert: Optional[SuricataAlert] = None
    related_dns: list[PiholeDNSEvent] = Field(default_factory=list)
    related_flows: list[NtopngFlow] = Field(default_factory=list)
    related_anomalies: list[NtopngHostAnomaly] = Field(default_factory=list)
    device_ip: Optional[str] = None
    external_ip: Optional[str] = None
    domain: Optional[str] = None
    enrichment: Optional[IPEnrichment] = None
    # Classification (filled by CLASSIFY node)
    classification: Optional[Classification] = None
    recommended_action: Optional[RecommendedAction] = None
    confidence: Optional[int] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Action models
# ---------------------------------------------------------------------------

class ProposedAction(BaseModel):
    """An action the agent wants to take, before safety checks."""
    action_id: str
    action_type: RecommendedAction
    target: str  # IP, domain, or device identifier
    reason: str
    finding_id: str
    classification: Classification
    confidence: int = Field(ge=0, le=100)


class ExecutedAction(BaseModel):
    """An action that was actually executed, with rollback info."""
    action_id: str
    action_type: RecommendedAction
    target: str
    reason: str
    command: Optional[str] = None
    rollback_command: Optional[str] = None
    auto_rollback_at: Optional[str] = None
    executed_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    success: bool = False
    result_message: str = ""
    confirmed_by_human: bool = False
