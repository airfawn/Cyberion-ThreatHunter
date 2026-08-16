"""Data models for the threat hunting subsystem."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class HuntStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvidenceType(str, Enum):
    OBSERVED = "observed"
    CORRELATED = "correlated"
    ENRICHMENT = "enrichment"
    ANALYST = "analyst"


@dataclass
class ThreatHypothesis:
    """Analyst-defined hypothesis for ad hoc threat hunting."""

    hypothesis_id: str
    name: str
    description: str
    reason: str
    data_sources: List[str]
    query_kql: str
    indicators_to_extract: List[str]
    expected_behavior: str
    mitre_technique: str
    severity: str
    confidence: float
    status: str
    created_at: str
    updated_at: str

    @staticmethod
    def new_default() -> "ThreatHypothesis":
        now = datetime.now(timezone.utc).isoformat()
        return ThreatHypothesis(
            hypothesis_id=f"hyp-{uuid.uuid4().hex[:10]}",
            name="New Hypothesis",
            description="",
            reason="",
            data_sources=["events"],
            query_kql="events | take 100",
            indicators_to_extract=[
                "ip_address",
                "pid",
                "ppid",
                "process_name",
                "user",
                "hostname",
                "filepath",
                "command",
                "timestamp",
                "hash",
            ],
            expected_behavior="",
            mitre_technique="",
            severity="medium",
            confidence=0.5,
            status="draft",
            created_at=now,
            updated_at=now,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ThreatHypothesis":
        default = ThreatHypothesis.new_default()
        merged = default.to_dict()
        merged.update(data or {})
        return ThreatHypothesis(**merged)


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    process: str
    user: str
    host: str
    source_ip: str
    destination_ip: str
    command_line: str
    file_path: str
    severity: str
    correlation_reason: str
    evidence_type: str
    uncertain: bool
    raw_event: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    """Persistable state for a single hunt investigation."""

    investigation_id: str
    hypothesis: Dict[str, Any]
    start_time: str
    end_time: str
    status: str
    initial_event: Dict[str, Any]
    suspicious_events: List[Dict[str, Any]]
    related_events: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    extracted_indicators: Dict[str, List[str]]
    ip_enrichment: Dict[str, Dict[str, Any]]
    mitre_techniques: List[str]
    confidence: float
    analyst_conclusion: str
    error: Optional[str] = None

    @staticmethod
    def new(hypothesis: ThreatHypothesis) -> "InvestigationState":
        now = datetime.now(timezone.utc).isoformat()
        return InvestigationState(
            investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
            hypothesis=hypothesis.to_dict(),
            start_time=now,
            end_time="",
            status=HuntStatus.IDLE.value,
            initial_event={},
            suspicious_events=[],
            related_events=[],
            timeline=[],
            extracted_indicators={},
            ip_enrichment={},
            mitre_techniques=[hypothesis.mitre_technique] if hypothesis.mitre_technique else [],
            confidence=max(0.0, min(1.0, float(hypothesis.confidence))),
            analyst_conclusion="",
            error=None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "InvestigationState":
        default = InvestigationState.new(ThreatHypothesis.new_default())
        merged = default.to_dict()
        merged.update(data or {})
        return InvestigationState(**merged)
