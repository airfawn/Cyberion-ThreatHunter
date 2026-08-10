"""GUI-facing data access boundary for Cyberion events.

The PyQt layer interacts only with :class:`EventRepository` -- never with the
database or with SQL. The repository translates the GUI's simple request
patterns (load recent, filter by field/operator/value, count, distinct
values) into validated structured queries for the query engine.
"""

from typing import Any, Dict, List, Optional

from .database import SCHEMA_COLUMNS
from .query_engine import ConditionLike, QueryEngine


class EventRepository:
    """Boundary object between the GUI and the persistent event store."""

    def __init__(self, engine: Optional[QueryEngine] = None, db: Any = None):
        if engine is not None:
            self._engine = engine
        elif db is not None:
            self._engine = QueryEngine(db)
        else:
            raise ValueError("EventRepository requires either an engine or a db")

    # ------------------------------------------------------------------ #
    # Simple reads
    # ------------------------------------------------------------------ #

    def load_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Newest events first; used to restore the table on startup."""
        return self._engine.get_events(limit=limit)

    def get_by_id(self, event_id: int) -> Optional[Dict[str, Any]]:
        return self._engine.get_event(event_id)

    def event_count(self) -> int:
        return self._engine.count()

    # ------------------------------------------------------------------ #
    # Filtering
    # ------------------------------------------------------------------ #

    def search(
        self,
        field: str,
        op: str,
        value: Any,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Single-condition search, e.g. search('severity', '>=', 3)."""
        from .query_engine import QueryCondition

        return self._engine.search(
            [QueryCondition(field, op, value)], limit=limit, offset=offset
        )

    def search_conditions(
        self,
        conditions: Optional[List[ConditionLike]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return self._engine.search(conditions, limit=limit, offset=offset)

    def count(self, conditions: Optional[List[ConditionLike]] = None) -> int:
        return self._engine.count(conditions)

    def distinct_values(self, field: str, limit: int = 50) -> List[Any]:
        return self._engine.distinct(field, limit=limit)

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def known_fields(self) -> List[str]:
        """First-class columns usable for filtering/sorting."""
        return list(SCHEMA_COLUMNS)
