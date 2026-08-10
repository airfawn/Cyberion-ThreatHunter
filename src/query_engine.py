"""Structured query engine foundation for Cyberion events.

This module is the single point where higher layers (the GUI / repository)
turn *structured* queries into validated database calls. A future KQL parser
should produce a list of :class:`QueryCondition` objects and hand them to a
:class:`QueryEngine`; no SQL is ever built by the GUI layer.

The engine intentionally does NOT parse user-authored KQL strings yet -- it
only understands structured conditions, which keeps the boundary testable and
injection-safe.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .database import FIELD_ALIASES, SCHEMA_COLUMNS, SUPPORTED_OPERATORS, validate_field as _db_validate_field


@dataclass(frozen=True)
class QueryCondition:
    """A single validated filter term: ``field <op> value``."""

    field: str
    op: str
    value: Any

    def __post_init__(self):
        if self.op not in SUPPORTED_OPERATORS:
            raise ValueError(f"Unsupported operator: {self.op!r}")
        canonical = _db_validate_field(self.field)
        object.__setattr__(self, "field", canonical)

    def to_dict(self) -> Dict[str, Any]:
        return {"field": self.field, "op": self.op, "value": self.value}

    @staticmethod
    def eq(field: str, value: Any) -> "QueryCondition":
        return QueryCondition(field, "==", value)

    @staticmethod
    def contains(field: str, value: Any) -> "QueryCondition":
        return QueryCondition(field, "contains", value)


ConditionLike = Union[QueryCondition, Dict[str, Any]]


def normalize_conditions(conditions: Optional[List[ConditionLike]]) -> List[Dict[str, Any]]:
    """Validate a list of conditions (or None) and return plain dicts."""
    if conditions is None:
        return []
    if not isinstance(conditions, list):
        raise ValueError("conditions must be a list of QueryCondition or dict")
    normalized: List[Dict[str, Any]] = []
    for item in conditions:
        if isinstance(item, QueryCondition):
            normalized.append(item.to_dict())
        elif isinstance(item, dict):
            try:
                cond = QueryCondition(
                    field=item.get("field", ""),
                    op=item.get("op", ""),
                    value=item.get("value"),
                )
            except (TypeError, AttributeError) as exc:
                raise ValueError(f"Invalid query condition: {item!r}") from exc
            normalized.append(cond.to_dict())
        else:
            raise ValueError(f"Invalid query condition: {item!r}")
    return normalized


class QueryEngine:
    """Validates structured conditions and executes them against a database.

    Any object exposing the ``CyberionDB`` query surface (get_event,
    get_events, get_events_since, search_events, count_events,
    get_distinct_values) can be used.
    """

    def __init__(self, db):
        self._db = db

    def get_event(self, event_id: int) -> Optional[Dict[str, Any]]:
        return self._db.get_event(event_id)

    def get_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self._db.get_events(limit=limit, offset=offset)

    def get_events_since(
        self, timestamp: str, limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        return self._db.get_events_since(timestamp, limit=limit, offset=offset)

    def search(
        self,
        conditions: Optional[List[ConditionLike]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return self._db.search_events(
            normalize_conditions(conditions), limit=limit, offset=offset
        )

    def count(self, conditions: Optional[List[ConditionLike]] = None) -> int:
        return self._db.count_events(normalize_conditions(conditions))

    def distinct(self, field: str, limit: int = 50) -> List[Any]:
        return self._db.get_distinct_values(field, limit=limit)

    def field_names(self) -> List[str]:
        """First-class fields the engine can filter/sort on."""
        return list(SCHEMA_COLUMNS)
