"""Severity classification engine for Cyberion log events.

The engine reads ``config/log_severity.yaml`` and classifies normalized
events into one of five semantic levels::

    critical > bad > warning > info > good

Classification is configuration-driven: the UI never hard-codes severity
rules. The engine validates the YAML structure, fails safely when a rule is
malformed, and never mutates the event it classifies.

Typical flow::

    Raw Event -> Event Parser -> Severity Classifier -> UI Renderer

The renderer only consumes :class:`SeverityResult` presentation metadata
(level, color, label, symbol) and the individual row/column values.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - defensive guard
    yaml = None

logger = logging.getLogger(__name__)

# Canonical severity levels, highest to lowest precedence.
SEVERITY_LEVELS = ("critical", "bad", "warning", "info", "good")

DEFAULT_LEVEL = "info"

SUPPORTED_OPS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "contains",
    "startswith",
    "endswith",
    "in",
    "not_in",
    "regex",
    "exists",
    "not_exists",
}

# Commonly observed value synonyms used when an expected value is a boolean
# but the normalized event carries a string.
_TRUE_WORDS = {"true", "yes", "1", "success", "successful", "succeeded", "granted", "allowed", "normal"}
_FALSE_WORDS = {"false", "no", "0", "fail", "failed", "failure", "denied", "rejected", "error"}

_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")

# Aliases that may appear in a normalized event for a conventional field name.
_FIELD_ALIASES = {
    "process_name": ("process", "proc"),
    "command": ("command_line", "cmd"),
    "filepath": ("file", "path"),
    "os": ("os_name",),
}


class SeverityConfigError(Exception):
    """Raised when the severity YAML configuration is structurally invalid."""


@dataclass
class SeverityResult:
    """Result of classifying a single event. Read-only presentation data."""

    level: str
    color: str
    label: str
    symbol: str
    reason: str = ""
    matched: bool = False


@dataclass
class _FieldMatcher:
    """A single ``field op value`` term within a condition."""

    field: str
    op: str
    value: Any

    def __init__(self, field: str, matcher: Any):
        self.field = field
        if isinstance(matcher, dict):
            self.op = str(matcher.get("op", "eq")).lower()
            if self.op not in SUPPORTED_OPS:
                raise SeverityConfigError(
                    f"Unsupported operator {self.op!r} for field {field!r}"
                )
            self.value = matcher.get("value")
            if self.op not in {"exists", "not_exists"} and not matcher.get("value"):
                raise SeverityConfigError(
                    f"Condition for field {field!r} with op {self.op!r} is missing a value"
                )
        else:
            self.op = "eq"
            self.value = matcher

    @property
    def description(self) -> str:
        if isinstance(self.value, list):
            shown = ", ".join(str(v) for v in self.value)
        else:
            shown = str(self.value)
        return f"{self.field} {self.op} {shown}"

    def matches(self, event: Dict[str, Any]) -> bool:
        return _match_value(_lookup(event, self.field), self.op, self.value)


class SeverityCondition:
    """A single condition: an AND of many ``field op value`` terms.

    The YAML list form ``- event_type: "authentication"
                          status: "success"`` produces one condition
    whose terms are ``event_type eq 'authentication'`` AND
    ``status eq 'success'``.
    """

    def __init__(self, spec: Dict[str, Any]):
        if not isinstance(spec, dict) or not spec:
            raise SeverityConfigError(f"Invalid condition spec: {spec!r}")
        self.terms: List[_FieldMatcher] = []
        for field, matcher in spec.items():
            self.terms.append(_FieldMatcher(field=field, matcher=matcher))

    @property
    def description(self) -> str:
        return ", ".join(term.description for term in self.terms)

    def matches(self, event: Dict[str, Any]) -> bool:
        return all(term.matches(event) for term in self.terms)


@dataclass(frozen=True)
class SeverityLevel:
    """Presentation + rule metadata for a single severity level."""

    name: str
    label: str
    symbol: str
    color: str
    conditions: tuple = field(default=())
    condition_specs: tuple = field(default=())

    def matches(self, event: Dict[str, Any]) -> bool:
        for cond in self.conditions:
            if cond.matches(event):
                return True
        return False

    def first_match(self, event: Dict[str, Any]) -> Optional[str]:
        """Return the description of the first matching condition, if any."""
        for cond in self.conditions:
            if cond.matches(event):
                return cond.description
        return None


def _normalize_bool(value: Any) -> Optional[bool]:
    """Coerce a normalized event value into a boolean (or None if ambiguous)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _TRUE_WORDS:
            return True
        if low in _FALSE_WORDS:
            return False
    return None


def _lookup(event: Dict[str, Any], field: str) -> Any:
    """Resolve a field name against a normalized event (aliases + case)."""
    if field in event:
        return event[field]
    for alias in _FIELD_ALIASES.get(field, ()):
        if alias in event:
            return event[alias]
    lowered = {str(k).lower(): v for k, v in event.items()}
    return lowered.get(field.lower())


def _match_value(actual: Any, op: str, expected: Any) -> bool:
    """Evaluate a single value against an operator/value pair."""
    if op == "exists":
        return actual is not None and str(actual) != ""
    if op == "not_exists":
        return actual is None or str(actual) == ""

    if actual is None:
        return False

    if op == "eq":
        if isinstance(expected, bool):
            return _normalize_bool(actual) is expected
        if isinstance(expected, (int, float)):
            try:
                return float(actual) == float(expected)
            except (TypeError, ValueError):
                return str(actual).casefold() == str(expected).casefold()
        return str(actual).casefold() == str(expected).casefold()

    if op == "ne":
        return not _match_value(actual, "eq", expected)

    if op in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(actual)
            right = float(expected)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right

    if op in {"contains", "startswith", "endswith"}:
        hay = str(actual).casefold()
        needle = str(expected).casefold()
        if op == "contains":
            return needle in hay
        if op == "startswith":
            return hay.startswith(needle)
        return hay.endswith(needle)

    if op == "in":
        return any(_match_value(actual, "eq", item) for item in (expected or []))
    if op == "not_in":
        return not any(_match_value(actual, "eq", item) for item in (expected or []))

    if op == "regex":
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            return False

    return False


# --------------------------------------------------------------------------- #
# Built-in fallback configuration (used when the YAML file is missing or
# malformed, so the application never crashes at startup).
# --------------------------------------------------------------------------- #

_FALLBACK_CONFIG = {
    "severity": {
        "good": {
            "label": "GOOD",
            "symbol": "\U0001F7E2",
            "color": "#22C55E",
            "conditions": [
                {"event_type": "authentication", "status": "success"},
                {"event_type": "authentication", "success": True},
                {"event_type": "process", "status": "normal"},
            ],
        },
        "info": {
            "label": "INFO",
            "symbol": "\U0001F535",
            "color": "#3B82F6",
            "conditions": [
                {"event_type": "system"},
                {"event_type": "application"},
                {"event_type": "network"},
                {"event_type": "syslog"},
                {"event_type": "journald_log"},
            ],
        },
        "warning": {
            "label": "WARNING",
            "symbol": "\U0001F7E1",
            "color": "#F59E0B",
            "conditions": [
                {"event_type": "authentication", "status": "failure"},
                {"event_type": "process", "suspicious": True},
                {"event_type": "command", "suspicious": True},
                {"severity": {"op": "gte", "value": 3}},
            ],
        },
        "bad": {
            "label": "BAD",
            "symbol": "\U0001F534",
            "color": "#EF4444",
            "conditions": [
                {"event_type": "malware"},
                {"event_type": "ransomware"},
                {"event_type": "detection", "severity": "high"},
                {"severity": {"op": "gte", "value": 4}},
            ],
        },
        "critical": {
            "label": "CRITICAL",
            "symbol": "\u26D4",
            "color": "#DC2626",
            "conditions": [
                {"event_type": "detection", "severity": "critical"},
                {"event_type": "ransomware", "confirmed": True},
            ],
        },
    }
}


class SeverityEngine:
    """Loads, validates, and evaluates severity rules against events."""

    def __init__(self, config_path: Optional[Path | str] = None):
        self.config_path = Path(config_path) if config_path else default_config_path()
        self.errors: List[str] = []
        self.levels: Dict[str, SeverityLevel] = {}
        self._rank: Dict[str, int] = {
            name: len(SEVERITY_LEVELS) - i for i, name in enumerate(SEVERITY_LEVELS)
        }
        self._load()

    # ------------------------------------------------------------------ #
    # Loading / validation
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        data = None
        if yaml is None:
            self.errors.append("PyYAML is not installed; using built-in severity mapping")
        else:
            try:
                with self.config_path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
            except FileNotFoundError:
                self.errors.append(f"Severity config not found: {self.config_path}")
            except Exception as exc:
                self.errors.append(f"Failed to parse severity config {self.config_path}: {exc}")

        if not isinstance(data, dict) or not isinstance(data.get("severity"), dict):
            if data is not None:
                self.errors.append(
                    f"Severity config must contain a 'severity' mapping: {self.config_path}"
                )
            data = _FALLBACK_CONFIG

        self._build_levels(data["severity"])

        if self.errors:
            for err in self.errors:
                logger.error("Severity configuration error: %s", err)

    def _build_levels(self, mapping: Dict[str, Any]) -> None:
        for name in SEVERITY_LEVELS:
            spec = mapping.get(name)
            if not isinstance(spec, dict):
                self.errors.append(
                    f"Severity level {name!r} missing or not a mapping; using fallback"
                )
                spec = _FALLBACK_CONFIG["severity"][name]
            self.levels[name] = self._build_level(name, spec)

        # Unknown extra levels are ignored so future configs do not crash the
        # current UI, but are surfaced as errors.
        for name in mapping:
            if name not in SEVERITY_LEVELS:
                self.errors.append(
                    f"Ignoring unknown severity level {name!r} (expected one of "
                    f"{', '.join(SEVERITY_LEVELS)})"
                )

    def _build_level(self, name: str, spec: Dict[str, Any]) -> SeverityLevel:
        label = str(spec.get("label", name.upper()))
        symbol = str(spec.get("symbol", ""))
        color = str(spec.get("color", ""))
        if not _COLOR_RE.match(color):
            self.errors.append(
                f"Severity level {name!r}: invalid color {color!r}; using fallback"
            )
            color = _FALLBACK_CONFIG["severity"][name]["color"]

        conditions: List[SeverityCondition] = []
        for idx, cond_spec in enumerate(spec.get("conditions", [])):
            try:
                conditions.append(_condition_from_spec(cond_spec))
            except (SeverityConfigError, TypeError, ValueError) as exc:
                self.errors.append(
                    f"Severity level {name!r} condition #{idx + 1} skipped: {exc}"
                )

        if not conditions:
            self.errors.append(
                f"Severity level {name!r} has no usable conditions; using fallback"
            )
            for cond_spec in _FALLBACK_CONFIG["severity"][name]["conditions"]:
                conditions.append(_condition_from_spec(cond_spec))

        return SeverityLevel(
            name=name,
            label=label,
            symbol=symbol,
            color=color,
            conditions=tuple(conditions),
            condition_specs=tuple(spec.get("conditions", [])),
        )

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #

    def classify_event(self, event: Any) -> SeverityResult:
        """Classify a normalized event into a severity level.

        The event is never mutated. Returns presentation metadata for the
        winning level and the (highest-priority) matching rule, if any.
        """
        if not isinstance(event, dict):
            return self._result_for(None, None)
        matched_reason = None
        matched_level = None
        for name in SEVERITY_LEVELS:  # highest precedence first
            level = self.levels[name]
            reason = level.first_match(event)
            if reason is not None:
                matched_reason = reason
                matched_level = level
                break
        if matched_level is None:
            return self._result_for(DEFAULT_LEVEL, None)
        return self._result_for(matched_level.name, matched_reason)

    def classify(self, event: Any) -> str:
        """Return only the severity level name for an event."""
        return self.classify_event(event).level

    def _result_for(self, level: Optional[str], reason: Optional[str]) -> SeverityResult:
        if level is None or level not in self.levels:
            level = DEFAULT_LEVEL
        lvl = self.levels[level]
        return SeverityResult(
            level=level,
            color=lvl.color,
            label=lvl.label,
            symbol=lvl.symbol,
            reason=reason or "",
            matched=reason is not None,
        )

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    def presentation(self, level: str) -> Dict[str, str]:
        """Return presentation metadata (color/label/symbol) for a level."""
        lvl = self.levels.get(level, self.levels[DEFAULT_LEVEL])
        return {"color": lvl.color, "label": lvl.label, "symbol": lvl.symbol}

    def rank(self, level: str) -> int:
        """Return the severity rank (higher = more severe). Unknown -> lowest."""
        return self._rank.get(level, len(self._rank))

    def level_names(self) -> List[str]:
        return list(SEVERITY_LEVELS)


def _condition_from_spec(spec: Any) -> SeverityCondition:
    """Build a condition from a YAML mapping of field -> matcher(s)."""
    return SeverityCondition(spec)


def default_config_path() -> Path:
    """Path to the project's severity configuration file."""
    return Path(__file__).resolve().parent.parent / "config" / "log_severity.yaml"


def load_severity_engine(config_path: Optional[Path | str] = None) -> SeverityEngine:
    """Convenience loader used by the GUI at startup."""
    return SeverityEngine(config_path)


__all__ = [
    "SEVERITY_LEVELS",
    "DEFAULT_LEVEL",
    "SUPPORTED_OPS",
    "SeverityEngine",
    "SeverityConfigError",
    "SeverityCondition",
    "SeverityLevel",
    "SeverityResult",
    "default_config_path",
    "load_severity_engine",
]