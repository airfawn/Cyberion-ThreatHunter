"""Threat hunting controller and background workers."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt5.QtCore import QObject, pyqtSignal

from .correlation_engine import CorrelationEngine
from .hypothesis_manager import HypothesisManager
from .indicator_extractor import IndicatorExtractor
from .models import HuntStatus, InvestigationState, ThreatHypothesis
from .reputation import ReputationLookupService
from .timeline_builder import TimelineBuilder


class HuntWorker(threading.Thread):
    """Background hunt worker; reports progress via controller callbacks."""

    def __init__(
        self,
        controller: "ThreatHuntingController",
        investigation_id: str,
        hypothesis: ThreatHypothesis,
        time_window_minutes: int,
        max_seed_events: int,
        max_related_events: int,
    ):
        super().__init__(daemon=True)
        self.controller = controller
        self.investigation_id = investigation_id
        self.hypothesis = hypothesis
        self.time_window_minutes = time_window_minutes
        self.max_seed_events = max_seed_events
        self.max_related_events = max_related_events
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        self.controller._run_hunt_worker(
            investigation_id=self.investigation_id,
            hypothesis=self.hypothesis,
            cancel_event=self.cancel_event,
            time_window_minutes=self.time_window_minutes,
            max_seed_events=self.max_seed_events,
            max_related_events=self.max_related_events,
        )


class ThreatHuntingController(QObject):
    """Coordinates threat hunting hypotheses and investigations."""

    hypotheses_changed = pyqtSignal(list)
    investigation_updated = pyqtSignal(dict)
    overview_updated = pyqtSignal(dict)

    def __init__(self, db, query_engine, parent=None):
        super().__init__(parent)
        self.db = db
        self.query_engine = query_engine

        self.hypothesis_manager = HypothesisManager()
        self.extractor = IndicatorExtractor()
        self.correlation_engine = CorrelationEngine(db=self.db, extractor=self.extractor)
        self.timeline_builder = TimelineBuilder()
        self.reputation = ReputationLookupService()

        self._lock = threading.RLock()
        self._investigations: Dict[str, InvestigationState] = {}
        self._workers: Dict[str, HuntWorker] = {}

        for inv in self.hypothesis_manager.list_investigations():
            self._investigations[inv.investigation_id] = inv

    # ------------------------------------------------------------------
    # Hypothesis lifecycle
    # ------------------------------------------------------------------

    def list_hypotheses(self) -> List[ThreatHypothesis]:
        hypotheses = self.hypothesis_manager.list_hypotheses()
        if not hypotheses:
            default = ThreatHypothesis.new_default()
            default.name = "Encoded PowerShell Execution Hunt"
            default.description = "Look for encoded command usage in PowerShell process activity."
            default.reason = "Encoded command execution can indicate obfuscation or malicious staging."
            default.query_kql = (
                "events | where process_name contains \"powershell\" "
                "or command contains \"-enc\" or command contains \"EncodedCommand\" "
                "| sort by timestamp desc | take 150"
            )
            default.expected_behavior = "PowerShell with encoded command lines and follow-on process/network activity"
            default.mitre_technique = "T1059.001"
            default.status = "active"
            self.hypothesis_manager.upsert_hypothesis(default)
            hypotheses = [default]
        return hypotheses

    def save_hypothesis(self, hypothesis: ThreatHypothesis) -> ThreatHypothesis:
        saved = self.hypothesis_manager.upsert_hypothesis(hypothesis)
        self.hypotheses_changed.emit([item.to_dict() for item in self.list_hypotheses()])
        return saved

    def delete_hypothesis(self, hypothesis_id: str) -> bool:
        deleted = self.hypothesis_manager.delete_hypothesis(hypothesis_id)
        if deleted:
            self.hypotheses_changed.emit([item.to_dict() for item in self.list_hypotheses()])
        return deleted

    # ------------------------------------------------------------------
    # Hunt lifecycle
    # ------------------------------------------------------------------

    def run_hypothesis(
        self,
        hypothesis: ThreatHypothesis,
        time_window_minutes: int = 30,
        max_seed_events: int = 150,
        max_related_events: int = 400,
    ) -> InvestigationState:
        investigation = InvestigationState.new(hypothesis)
        investigation.status = HuntStatus.RUNNING.value

        with self._lock:
            self._investigations[investigation.investigation_id] = investigation
            worker = HuntWorker(
                controller=self,
                investigation_id=investigation.investigation_id,
                hypothesis=hypothesis,
                time_window_minutes=time_window_minutes,
                max_seed_events=max_seed_events,
                max_related_events=max_related_events,
            )
            self._workers[investigation.investigation_id] = worker

        self._persist_and_emit(investigation)
        worker.start()
        return investigation

    def cancel_hunt(self, investigation_id: str) -> bool:
        with self._lock:
            worker = self._workers.get(investigation_id)
            investigation = self._investigations.get(investigation_id)

        if worker is None:
            return False

        worker.cancel()
        if investigation:
            investigation.status = HuntStatus.CANCELLED.value
            investigation.end_time = datetime.now(timezone.utc).isoformat()
            investigation.error = "Cancelled by analyst"
            self._persist_and_emit(investigation)
        return True

    def list_investigations(self) -> List[InvestigationState]:
        with self._lock:
            items = list(self._investigations.values())
        return sorted(items, key=lambda item: item.start_time, reverse=True)

    def get_overview(self) -> Dict[str, int]:
        items = self.list_investigations()
        active = sum(1 for item in items if item.status == HuntStatus.RUNNING.value)
        failed = sum(1 for item in items if item.status == HuntStatus.FAILED.value)
        findings = sum(len(item.related_events) + len(item.suspicious_events) for item in items)
        high_conf = sum(1 for item in items if item.confidence >= 0.75)
        return {
            "active_hunts": active,
            "recent_hunts": min(len(items), 20),
            "findings": findings,
            "high_confidence": high_conf,
            "failed_hunts": failed,
        }

    # ------------------------------------------------------------------
    # Worker implementation
    # ------------------------------------------------------------------

    def _run_hunt_worker(
        self,
        investigation_id: str,
        hypothesis: ThreatHypothesis,
        cancel_event: threading.Event,
        time_window_minutes: int,
        max_seed_events: int,
        max_related_events: int,
    ) -> None:
        investigation = self._investigations[investigation_id]

        try:
            if cancel_event.is_set():
                self._mark_cancelled(investigation)
                return

            bounded_query = self._bounded_query(hypothesis.query_kql, max_seed_events)
            query_result = self.query_engine.execute(bounded_query)
            seed_events = [dict(item) for item in query_result.rows]
            investigation.suspicious_events = seed_events

            if cancel_event.is_set():
                self._mark_cancelled(investigation)
                return

            if not seed_events:
                investigation.status = HuntStatus.COMPLETED.value
                investigation.end_time = datetime.now(timezone.utc).isoformat()
                investigation.analyst_conclusion = (
                    "No suspicious events matched the hypothesis query. "
                    "Consider adjusting scope or indicator predicates."
                )
                self._persist_and_emit(investigation)
                return

            initial_event = seed_events[0]
            investigation.initial_event = initial_event

            related = self.correlation_engine.correlate(
                initial_event,
                window_minutes=time_window_minutes,
                limit=max_related_events,
            )
            investigation.related_events = related

            if cancel_event.is_set():
                self._mark_cancelled(investigation)
                return

            timeline = self.timeline_builder.build(initial_event, related)
            investigation.timeline = timeline

            evidence_events = [initial_event] + related
            indicators = self.extractor.merge(evidence_events)
            investigation.extracted_indicators = indicators

            enrichment: Dict[str, Dict] = {}
            for ip in self.extractor.public_ips(indicators):
                if cancel_event.is_set():
                    self._mark_cancelled(investigation)
                    return
                enrichment[ip] = self.reputation.enrich_ip(ip)
            investigation.ip_enrichment = enrichment

            investigation.confidence = self._estimate_confidence(
                hypothesis_confidence=hypothesis.confidence,
                related_events=related,
                enrichment=enrichment,
            )

            investigation.analyst_conclusion = self._build_default_conclusion(investigation)
            investigation.status = HuntStatus.COMPLETED.value
            investigation.end_time = datetime.now(timezone.utc).isoformat()
            investigation.error = None
            self._persist_and_emit(investigation)
        except Exception as exc:
            investigation.status = HuntStatus.FAILED.value
            investigation.end_time = datetime.now(timezone.utc).isoformat()
            investigation.error = str(exc)
            self._persist_and_emit(investigation)
        finally:
            with self._lock:
                self._workers.pop(investigation_id, None)

    def _mark_cancelled(self, investigation: InvestigationState) -> None:
        investigation.status = HuntStatus.CANCELLED.value
        investigation.end_time = datetime.now(timezone.utc).isoformat()
        investigation.error = "Cancelled by analyst"
        self._persist_and_emit(investigation)

    def _persist_and_emit(self, investigation: InvestigationState) -> None:
        self.hypothesis_manager.save_investigation(investigation)
        self.investigation_updated.emit(investigation.to_dict())
        self.overview_updated.emit(self.get_overview())

    def _bounded_query(self, kql: str, limit: int) -> str:
        trimmed = (kql or "").strip()
        if not trimmed:
            return f"events | take {limit}"
        lower = trimmed.lower()
        if "| take" in lower:
            return trimmed
        return f"{trimmed} | take {limit}"

    def _estimate_confidence(
        self,
        hypothesis_confidence: float,
        related_events: List[Dict],
        enrichment: Dict[str, Dict],
    ) -> float:
        base = max(0.0, min(1.0, float(hypothesis_confidence)))
        relationship_boost = min(len(related_events) / 20.0, 0.25)
        malicious_hits = 0
        for record in enrichment.values():
            status = str(record.get("status") or "").lower()
            if "malicious" in status or "suspicious" in status:
                malicious_hits += 1
        enrichment_boost = min(malicious_hits * 0.08, 0.2)
        return round(min(base + relationship_boost + enrichment_boost, 0.98), 2)

    def _build_default_conclusion(self, investigation: InvestigationState) -> str:
        related_count = len(investigation.related_events)
        suspicious_count = len(investigation.suspicious_events)
        enrichment_available = any(
            bool(item.get("available")) for item in investigation.ip_enrichment.values()
        )
        uncertainty = sum(
            1 for event in investigation.related_events if event.get("_correlation_uncertain")
        )

        return (
            "Observed evidence: "
            f"{suspicious_count} suspicious event(s) matched the hypothesis query. "
            "Correlated evidence: "
            f"{related_count} related event(s) were linked by shared identifiers"
            f" ({uncertainty} low-confidence link(s)). "
            "External enrichment: "
            f"{'available' if enrichment_available else 'not configured or unavailable'}. "
            "Analyst interpretation: results indicate behaviors worth manual validation; "
            "findings are not a definitive malicious verdict."
        )
