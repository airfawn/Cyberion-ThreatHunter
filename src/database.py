# python src/database.py
"""Cyberion event database layer.

Stores normalized event fields plus the original raw JSON in a SQLite
database and exposes a clean query API. The schema is tuned for
security/log searching: common fields are first-class indexed columns,
while unknown/dynamic fields are kept in an ``extra`` JSON column so new
collector fields never require a schema migration.
"""

import json
import queue
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Schema definition
# ---------------------------------------------------------------------------

# First-class columns (frequently queried / common security fields).
SCHEMA_COLUMNS = [
    "timestamp",
    "received_at",
    "source",
    "agent_id",
    "agent_name",
    "hostname",
    "os",
    "event_type",
    "severity",
    "success",
    "pid",
    "ppid",
    "process_name",
    "parent_process",
    "user",
    "filepath",
    "command",
    "message",
    "ip_address",
]

# Indexed columns (high-value security-search fields only; not everything).
INDEXED_COLUMNS = [
    "timestamp",
    "event_type",
    "severity",
    "agent_id",
    "hostname",
    "process_name",
    "user",
    "filepath",
]

# Map common field synonyms onto first-class columns.
FIELD_ALIASES = {
    "process": "process_name",
    "proc": "process_name",
    "os_name": "os",
    "file": "filepath",
    "cmd": "command",
    "parent_process_name": "parent_process",
}

# Reverse mapping: canonical column -> aliases that resolve to it.
_REVERSE_FIELD_ALIASES: Dict[str, list] = {}
for _alias, _canonical in FIELD_ALIASES.items():
    _REVERSE_FIELD_ALIASES.setdefault(_canonical, []).append(_alias)

# These keys are never treated as dynamic ``extra`` fields.
_RESERVED_KEYS = {"raw_event", "extra", "structured", "raw_message"}

SUPPORTED_OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "contains", "startswith", "endswith"}

_OP_TO_SQL = {
    "==": "=",
    "!=": "!=",
    ">": ">",
    "<": "<",
    ">=": ">=",
    "<=": "<=",
}

_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_field(field: str) -> str:
    """Validate a field name, resolving aliases. Returns canonical name."""
    canonical = FIELD_ALIASES.get(field, field)
    if not _FIELD_RE.match(canonical):
        raise ValueError(f"Invalid field name: {field!r}")
    return canonical


def default_db_path() -> Path:
    """Path to the persistent project database (never inside src/)."""
    return Path(__file__).resolve().parent.parent / "data" / "cyberion.db"


def _escape_like(value: Any) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _coerce_value(column: str, value: Any) -> Any:
    """Coerce a raw event value into the type expected by its column."""
    if value is None or value == "":
        return None
    if column in {"severity"}:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if column in {"success"}:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, (int, float)):
            return 1 if value else 0
        if isinstance(value, str):
            low = value.strip().lower()
            if low in {"true", "yes", "1", "success", "successful", "succeeded", "granted"}:
                return 1
            if low in {"false", "no", "0", "fail", "failed", "failure", "denied", "rejected"}:
                return 0
            return None
        return None
    if column in {"pid", "ppid"}:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, (dict, list, bool)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def event_payload_to_dict(queue_item) -> dict:
    """Convert the server's queue item into an event dict.

    Accepts a dict directly, or the server's 3-tuple
    ``(received_at, source, raw_event)`` and 5-tuple
    ``(received_at, source, raw_event, raw_message, structured)`` wire
    formats.
    """
    if isinstance(queue_item, dict):
        return queue_item
    if isinstance(queue_item, (tuple, list)):
        if len(queue_item) == 5:
            received_at, source, raw_event, raw_message, structured = queue_item
        elif len(queue_item) == 3:
            received_at, source, raw_event = queue_item
            raw_message = raw_event
            structured = None
        else:
            raise ValueError(f"Unexpected queue item length: {len(queue_item)}")
        return {
            "received_at": received_at,
            "source": source,
            "raw_event": raw_event,
            "raw_message": raw_message,
            "structured": structured,
        }
    raise ValueError(f"Unexpected queue item type: {type(queue_item)!r}")


class CyberionDB:
    """Thread-safe SQLite-backed persistent store for Cyberion events.

    A single connection is shared (``check_same_thread=False``) between the
    persistence worker thread and the GUI thread; an internal lock serializes
    access. WAL mode plus a busy timeout avoid ``database is locked`` errors.
    """

    _ROW_COLUMNS = ["id"] + SCHEMA_COLUMNS + ["raw_event", "extra", "structured"]
    _INSERT_COLUMNS = SCHEMA_COLUMNS + ["raw_event", "extra", "structured"]

    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self._lock = threading.RLock()
        self._create_schema()
        
        # Initialize alert manager and detection manager
        from .alerts.manager import AlertManager  # type: ignore
        from .detections.manager import DetectionManager  # type: ignore
        self.alerts = AlertManager(self.conn)
        self.detections = DetectionManager(self.conn)

    # ------------------------------------------------------------------ #
    # Schema
    # ------------------------------------------------------------------ #

    def _create_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp      TEXT,
                    received_at    TEXT,
                    source         TEXT,
                    agent_id       TEXT,
                    agent_name     TEXT,
                    hostname       TEXT,
                    os             TEXT,
                    event_type     TEXT,
                    severity       INTEGER,
                    success        INTEGER,
                    pid            INTEGER,
                    ppid           INTEGER,
                    process_name   TEXT,
                    parent_process TEXT,
                    user           TEXT,
                    filepath       TEXT,
                    command        TEXT,
                    message        TEXT,
                    ip_address     TEXT,
                    raw_event      TEXT NOT NULL,
                    extra          TEXT,
                    structured     TEXT
                )
                """
            )
            for col in INDEXED_COLUMNS:
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_events_{col} ON events ({col})"
                )
            self.conn.commit()

    # ------------------------------------------------------------------ #
    # Insertion
    # ------------------------------------------------------------------ #

    def _insert_sql(self) -> str:
        cols = ", ".join(self._INSERT_COLUMNS)
        placeholders = ", ".join("?" for _ in self._INSERT_COLUMNS)
        return f"INSERT INTO events ({cols}) VALUES ({placeholders})"

    def _event_to_row(self, event) -> dict:
        """Map an event dict (schema + dynamic keys) onto a DB row dict."""
        event = event_payload_to_dict(event)
        lookup = dict(event)
        structured = event.get("structured")
        if isinstance(structured, dict):
            for key, value in structured.items():
                lookup.setdefault(key, value)

        row: dict = {}
        consumed: set = set()
        for col in SCHEMA_COLUMNS:
            value = lookup.get(col)
            if value is None:
                for alias in _REVERSE_FIELD_ALIASES.get(col, []):
                    if alias in lookup and lookup[alias] is not None:
                        value = lookup[alias]
                        consumed.add(alias)
                        break
            row[col] = _coerce_value(col, value)

        raw_message = event.get("raw_message")
        if raw_message is None:
            raw = event.get("raw_event", "")
            raw_message = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
        row["raw_event"] = raw_message if isinstance(raw_message, str) else json.dumps(
            raw_message, ensure_ascii=False
        )

        extra: dict = {}
        for key, value in lookup.items():
            if key in SCHEMA_COLUMNS or key in _RESERVED_KEYS or key in consumed:
                continue
            if value is not None:
                extra[key] = value
        row["extra"] = json.dumps(extra, ensure_ascii=False) if extra else None

        row["structured"] = (
            json.dumps(structured, ensure_ascii=False) if isinstance(structured, dict) else None
        )
        return row

    def insert_event(self, event: dict) -> int:
        """Insert a single event and return its row id."""
        with self._lock:
            row = self._event_to_row(event)
            cur = self.conn.cursor()
            cur.execute(self._insert_sql(), tuple(row[c] for c in self._INSERT_COLUMNS))
            self.conn.commit()
            return cur.lastrowid

    def insert_events(self, events: list) -> int:
        """Insert many events in a single transaction. Returns row count."""
        if not events:
            return 0
        with self._lock:
            rows = [self._event_to_row(e) for e in events]
            cur = self.conn.cursor()
            cur.executemany(
                self._insert_sql(),
                [tuple(r[c] for c in self._INSERT_COLUMNS) for r in rows],
            )
            self.conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #

    def _select(self) -> str:
        return ", ".join(self._ROW_COLUMNS)

    def _row_to_dict(self, row) -> dict:
        """Convert a DB row into a flat event dict for the application."""
        d = dict(zip(self._ROW_COLUMNS, row))
        try:
            extra = json.loads(d["extra"]) if d.get("extra") else {}
        except (json.JSONDecodeError, TypeError):
            extra = {}
        d.update(extra)
        try:
            d["structured"] = json.loads(d["structured"]) if d.get("structured") else {}
        except (json.JSONDecodeError, TypeError):
            d["structured"] = {}
        d["raw_message"] = d.get("raw_event", "")
        d.pop("extra", None)
        return d

    def get_event(self, event_id: int) -> Optional[dict]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(f"SELECT {self._select()} FROM events WHERE id = ?", (event_id,))
            row = cur.fetchone()
            return self._row_to_dict(row) if row else None

    def get_events(self, limit: int = 100, offset: int = 0) -> list:
        """Newest-first events (cursor/keyset pagination via id DESC)."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT {self._select()} FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_events_since(self, timestamp: str, limit: int = 100, offset: int = 0) -> list:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT {self._select()} FROM events "
                "WHERE COALESCE(timestamp, received_at) >= ? "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (timestamp, limit, offset),
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # Query execution (controlled SQL only)
    # ------------------------------------------------------------------ #

    def _validate_field(self, field: str) -> str:
        return validate_field(field)

    def _conditions_to_where(self, conditions: Optional[list]) -> tuple[str, list]:
        """Translate controlled conditions into a parameterized WHERE clause.

        Never builds SQL from unsanitized user input: field names are
        validated against a strict pattern and the allowed column set, and all
        values are bound as ``?`` parameters.
        """
        clauses: list = []
        params: list = []
        for cond in conditions or []:
            if not isinstance(cond, dict):
                raise ValueError(f"Invalid query condition: {cond!r}")
            field = self._validate_field(cond.get("field"))
            op = cond.get("op")
            if "value" not in cond:
                raise ValueError(f"Query condition missing value: {cond!r}")
            value = cond.get("value")
            if op not in SUPPORTED_OPERATORS:
                raise ValueError(f"Unsupported operator: {op!r}")

            column = field if field in SCHEMA_COLUMNS else f"json_extract(extra, '$.{field}')"
            if op in _OP_TO_SQL:
                clauses.append(f"{column} {_OP_TO_SQL[op]} ?")
                params.append(value if isinstance(value, (int, float)) else str(value))
            elif op == "contains":
                clauses.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(f"%{_escape_like(value)}%")
            elif op == "startswith":
                clauses.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(f"{_escape_like(value)}%")
            elif op == "endswith":
                clauses.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(f"%{_escape_like(value)}")

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def search_events(
        self,
        conditions: Optional[list] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list:
        """Search events by a list of structured conditions."""
        with self._lock:
            where, params = self._conditions_to_where(conditions)
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT {self._select()} FROM events{where} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    def count_events(self, conditions: Optional[list] = None) -> int:
        with self._lock:
            where, params = self._conditions_to_where(conditions)
            cur = self.conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM events{where}", params)
            return cur.fetchone()[0]

    def execute_query(
        self,
        where_sql: str,
        params: Optional[list] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list:
        """Execute a SELECT using a pre-built WHERE fragment.

        Intended for SQL produced by the query engine only. ``where_sql`` must
        be empty or start with ``WHERE`` and contain only ``?`` placeholders.
        """
        if where_sql and not where_sql.lstrip().upper().startswith("WHERE"):
            raise ValueError("execute_query only accepts a WHERE fragment")
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT {self._select()} FROM events {where_sql} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                list(params or []) + [limit, offset],
            )
            return [self._row_to_dict(r) for r in cur.fetchall()]

    def get_distinct_values(self, field: str, limit: int = 50) -> list:
        col = self._validate_field(field)
        if col not in SCHEMA_COLUMNS:
            return []
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                f"SELECT DISTINCT {col} FROM events "
                f"WHERE {col} IS NOT NULL AND {col} != '' "
                f"ORDER BY {col} LIMIT ?",
                (limit,),
            )
            return [r[0] for r in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # Compatibility / lifecycle
    # ------------------------------------------------------------------ #

    def fetch_all(self) -> list:
        """Return raw tuples for all events, ordered by id."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, received_at, source, raw_event FROM events ORDER BY id")
            return cur.fetchall()

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass


class EventPersistenceWorker:
    """Consumes events from the server queue, persists them to the DB in
    batches, then forwards them to the GUI queue.

    Runs on its own thread so DB writes never block the PyQt GUI, and events
    are still persisted even if the GUI is closed or crashes.
    """

    def __init__(
        self,
        db: CyberionDB,
        input_queue: queue.Queue,
        output_queue: queue.Queue,
        batch_size: int = 50,
        flush_interval: float = 1.0,
    ):
        self.db = db
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """Drain remaining events, flush, and stop the worker thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        pending: list = []
        while not self._stop_event.is_set():
            try:
                item = self.input_queue.get(timeout=self.flush_interval)
            except queue.Empty:
                item = None
            if item is None:
                if pending:
                    self._flush(pending)
                    pending = []
                continue
            pending.append(item)
            if len(pending) >= self.batch_size:
                self._flush(pending)
                pending = []

        while True:
            try:
                pending.append(self.input_queue.get_nowait())
            except queue.Empty:
                break
        if pending:
            self._flush(pending)

    def _flush(self, items: list):
        try:
            self.db.insert_events(items)
            for item in items:
                try:
                    event = self.db.get_events(limit=1)[0]
                    if event and event.get("id") is not None:
                        self._evaluate_detections(event)
                except Exception:
                    pass
        except Exception as exc:
            # Never crash the pipeline because of a DB error; the GUI still
            # sees the event and the error is logged.
            print(f"[Persistence] Failed to insert {len(items)} events: {exc}")
        for item in items:
            self.output_queue.put(item)

    def _evaluate_detections(self, event: dict) -> None:
        try:
            from .detections.engine import DetectionEngine  # type: ignore

            engine = DetectionEngine(self.db)
            engine.evaluate_event(event)
        except Exception as exc:
            print(f"[Persistence] Failed to evaluate detections: {exc}")
