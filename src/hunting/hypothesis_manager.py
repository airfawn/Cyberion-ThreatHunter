"""Persistence and lifecycle management for threat hunting hypotheses."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .models import InvestigationState, ThreatHypothesis


class HypothesisManager:
    """Stores hypotheses and investigation snapshots in JSON files."""

    def __init__(
        self,
        hypotheses_path: Optional[Path] = None,
        investigations_path: Optional[Path] = None,
    ):
        root = Path(__file__).resolve().parent.parent.parent
        data_dir = root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        self.hypotheses_path = hypotheses_path or data_dir / "threat_hypotheses.json"
        self.investigations_path = investigations_path or data_dir / "threat_investigations.json"

    def list_hypotheses(self) -> List[ThreatHypothesis]:
        payload = self._read_json(self.hypotheses_path, [])
        return [ThreatHypothesis.from_dict(item) for item in payload]

    def get_hypothesis(self, hypothesis_id: str) -> Optional[ThreatHypothesis]:
        for hypothesis in self.list_hypotheses():
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis
        return None

    def upsert_hypothesis(self, hypothesis: ThreatHypothesis) -> ThreatHypothesis:
        now = datetime.now(timezone.utc).isoformat()
        hypothesis.updated_at = now
        items = self.list_hypotheses()
        found = False
        for idx, existing in enumerate(items):
            if existing.hypothesis_id == hypothesis.hypothesis_id:
                items[idx] = hypothesis
                found = True
                break
        if not found:
            if not hypothesis.created_at:
                hypothesis.created_at = now
            items.append(hypothesis)

        self._write_json(self.hypotheses_path, [item.to_dict() for item in items])
        return hypothesis

    def delete_hypothesis(self, hypothesis_id: str) -> bool:
        items = self.list_hypotheses()
        remaining = [item for item in items if item.hypothesis_id != hypothesis_id]
        if len(remaining) == len(items):
            return False
        self._write_json(self.hypotheses_path, [item.to_dict() for item in remaining])
        return True

    def save_investigation(self, investigation: InvestigationState) -> None:
        snapshots = self.list_investigations()
        replaced = False
        for idx, item in enumerate(snapshots):
            if item.investigation_id == investigation.investigation_id:
                snapshots[idx] = investigation
                replaced = True
                break
        if not replaced:
            snapshots.append(investigation)

        # Keep latest 200 investigations for responsiveness.
        snapshots = sorted(snapshots, key=lambda x: x.start_time, reverse=True)[:200]
        self._write_json(self.investigations_path, [item.to_dict() for item in snapshots])

    def list_investigations(self) -> List[InvestigationState]:
        payload = self._read_json(self.investigations_path, [])
        return [InvestigationState.from_dict(item) for item in payload]

    def _read_json(self, path: Path, default):
        if not path.exists():
            return default
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return default

    def _write_json(self, path: Path, payload) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
