"""Sigma import service integrated with AlertManager persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from ..alerts.manager import AlertManager
from .converter import SigmaRuleConverter
from .models import ConversionStatus, SigmaConversionResult


CONVERSION_VERSION = "1.0"


class SigmaRuleImporter:
    def __init__(self, alert_manager: AlertManager):
        self.alert_manager = alert_manager
        self.converter = SigmaRuleConverter()
        self._create_schema()

    def _create_schema(self) -> None:
        conn = self.alert_manager.conn
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sigma_imports (
                sigma_id TEXT PRIMARY KEY,
                local_rule_id TEXT NOT NULL,
                sigma_modified_date TEXT,
                last_imported TEXT NOT NULL,
                conversion_version TEXT NOT NULL,
                source_path TEXT,
                status TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_sigma_imports_rule ON sigma_imports(local_rule_id)"
        )
        conn.commit()

    def validate_file(self, path: str) -> list[SigmaConversionResult]:
        content = Path(path).read_text(encoding="utf-8")
        docs = self.converter.load_sigma_documents(content)
        return [self.converter.convert_sigma_dict(doc, source_path=path) for doc in docs]

    def convert_file(self, path: str) -> list[SigmaConversionResult]:
        return self.validate_file(path)

    def import_file(self, path: str, update_existing: bool = False) -> list[SigmaConversionResult]:
        results = self.validate_file(path)
        for result in results:
            if result.status not in {
                ConversionStatus.SUPPORTED,
                ConversionStatus.SUPPORTED_WITH_WARNINGS,
            }:
                continue

            sigma_id = result.sigma_id or ""
            if not sigma_id:
                result.status = ConversionStatus.INVALID
                result.errors.append("Sigma id is required for import")
                continue

            existing = self._get_import_record(sigma_id)
            if existing and not update_existing:
                result.status = ConversionStatus.SUPPORTED_WITH_WARNINGS
                result.warnings.append(
                    f"Sigma ID {sigma_id} already imported as local rule {existing['local_rule_id']}"
                )
                result.local_rule_id = existing["local_rule_id"]
                continue

            if result.local_rule is None:
                result.status = ConversionStatus.INVALID
                result.errors.append("Conversion produced no local rule")
                continue

            if existing and update_existing:
                # Update existing local rule by ID.
                rule = result.local_rule
                current = self.alert_manager.get_rule(existing["local_rule_id"])
                if current is None:
                    rule.id = None
                    created = self.alert_manager.create_rule(rule)
                else:
                    rule.id = current.id
                    rule.created_at = current.created_at
                    self.alert_manager.update_rule(rule)
                    created = rule
            else:
                created = self.alert_manager.create_rule(result.local_rule)

            result.local_rule_id = created.id
            self._upsert_import_record(
                sigma_id=sigma_id,
                local_rule_id=created.id,
                sigma_modified_date=(result.ir.metadata.modified if result.ir else ""),
                source_path=path,
                status=result.status.value,
            )

        return results

    def import_path(self, path: str, update_existing: bool = False) -> list[SigmaConversionResult]:
        p = Path(path)
        if p.is_file():
            return self.import_file(str(p), update_existing=update_existing)

        results: list[SigmaConversionResult] = []
        for file_path in sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml")):
            results.extend(self.import_file(str(file_path), update_existing=update_existing))
        return results

    def _get_import_record(self, sigma_id: str):
        cur = self.alert_manager.conn.cursor()
        cur.execute(
            "SELECT sigma_id, local_rule_id, sigma_modified_date, last_imported, conversion_version, source_path, status FROM sigma_imports WHERE sigma_id = ?",
            (sigma_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "sigma_id": row[0],
            "local_rule_id": row[1],
            "sigma_modified_date": row[2],
            "last_imported": row[3],
            "conversion_version": row[4],
            "source_path": row[5],
            "status": row[6],
        }

    def _upsert_import_record(
        self,
        *,
        sigma_id: str,
        local_rule_id: str,
        sigma_modified_date: str,
        source_path: str,
        status: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        cur = self.alert_manager.conn.cursor()
        cur.execute(
            """
            INSERT INTO sigma_imports (sigma_id, local_rule_id, sigma_modified_date, last_imported, conversion_version, source_path, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sigma_id) DO UPDATE SET
                local_rule_id = excluded.local_rule_id,
                sigma_modified_date = excluded.sigma_modified_date,
                last_imported = excluded.last_imported,
                conversion_version = excluded.conversion_version,
                source_path = excluded.source_path,
                status = excluded.status
            """,
            (
                sigma_id,
                local_rule_id,
                sigma_modified_date,
                now,
                CONVERSION_VERSION,
                source_path,
                status,
            ),
        )
        self.alert_manager.conn.commit()
