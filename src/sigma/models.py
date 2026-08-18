"""Models for Sigma import, IR, and conversion results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ConversionStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_WARNINGS = "SUPPORTED_WITH_WARNINGS"
    UNSUPPORTED = "UNSUPPORTED"
    INVALID = "INVALID"


@dataclass
class SigmaMetadata:
    title: str = ""
    sigma_id: str = ""
    status: str = ""
    description: str = ""
    author: str = ""
    date: str = ""
    modified: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    level: str = ""


@dataclass
class SigmaLogsource:
    product: str = ""
    category: str = ""
    service: str = ""


@dataclass
class DetectionAtom:
    field: str
    operator: str
    values: List[Any]


@dataclass
class DetectionExpr:
    """Boolean expression node.

    kind: atom | and | or | not
    """

    kind: str
    atom: Any = None
    children: List["DetectionExpr"] = field(default_factory=list)


@dataclass
class CyberionDetectionIR:
    metadata: SigmaMetadata
    logsource: SigmaLogsource
    platform: str
    event_type_hint: str
    root_expr: Optional[DetectionExpr]
    unsupported_features: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    source_path: str = ""
    original_sigma: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SigmaConversionResult:
    status: ConversionStatus
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sigma_id: str = ""
    sigma_title: str = ""
    local_rule_id: str = ""
    ir: Optional[CyberionDetectionIR] = None
    local_rule: Any = None


@dataclass
class SigmaImportRecord:
    sigma_id: str
    local_rule_id: str
    sigma_modified_date: str
    last_imported: str
    conversion_version: str
    source_path: str
    status: str
