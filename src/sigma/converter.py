"""Sigma YAML to Cyberion rule converter via intermediate representation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import yaml  # type: ignore

from ..alerts import ActionConfig, ActionType, AlertRule, AlertSeverity
from ..query.model_to_kql import query_definition_to_kql
from ..query.query_model import (
    ComparisonOperator,
    Condition,
    ConditionGroup,
    LogicalOperator,
    QueryDefinition,
)
from .condition_parser import ConditionSyntaxError, SigmaConditionParser
from .field_mapping import SigmaFieldMapper
from .logsource_mapping import SigmaLogsourceMapper
from .models import (
    ConversionStatus,
    CyberionDetectionIR,
    DetectionAtom,
    DetectionExpr,
    SigmaConversionResult,
    SigmaLogsource,
    SigmaMetadata,
)


INVERTIBLE_OPERATORS = {
    ComparisonOperator.EQUALS: ComparisonOperator.NOT_EQUALS,
    ComparisonOperator.NOT_EQUALS: ComparisonOperator.EQUALS,
    ComparisonOperator.CONTAINS: ComparisonOperator.NOT_CONTAINS,
    ComparisonOperator.NOT_CONTAINS: ComparisonOperator.CONTAINS,
    ComparisonOperator.GREATER_THAN: ComparisonOperator.LESS_THAN_EQUAL,
    ComparisonOperator.LESS_THAN: ComparisonOperator.GREATER_THAN_EQUAL,
    ComparisonOperator.GREATER_THAN_EQUAL: ComparisonOperator.LESS_THAN,
    ComparisonOperator.LESS_THAN_EQUAL: ComparisonOperator.GREATER_THAN,
}

SUPPORTED_BASE_MODIFIERS = {"contains", "startswith", "endswith", "re"}
SUPPORTED_COMPOUND_MODIFIERS = {"contains|all", "contains|any"}

SEVERITY_MAP = {
    "low": AlertSeverity.LOW,
    "medium": AlertSeverity.MEDIUM,
    "high": AlertSeverity.HIGH,
    "critical": AlertSeverity.CRITICAL,
}


class SigmaConversionError(ValueError):
    pass


class SigmaRuleConverter:
    """Converts Sigma rules to Cyberion AlertRule objects."""

    def __init__(self, field_mapper: SigmaFieldMapper | None = None):
        self.field_mapper = field_mapper or SigmaFieldMapper()
        self.logsource_mapper = SigmaLogsourceMapper()
        self.condition_parser = SigmaConditionParser()

    def load_sigma_documents(self, content: str) -> list[dict]:
        """Load one or more Sigma YAML docs from untrusted input safely."""
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception as exc:
            raise SigmaConversionError(f"Malformed Sigma YAML: {exc}") from exc

        valid_docs = []
        for item in docs:
            if item is None:
                continue
            if not isinstance(item, dict):
                raise SigmaConversionError("Sigma document must be a YAML mapping")
            valid_docs.append(item)
        if not valid_docs:
            raise SigmaConversionError("No Sigma rule documents found")
        return valid_docs

    def convert_sigma_dict(self, sigma_rule: dict, source_path: str = "") -> SigmaConversionResult:
        errors: list[str] = []
        warnings: list[str] = []

        metadata = self._parse_metadata(sigma_rule)
        sigma_id = metadata.sigma_id

        try:
            self._validate_sigma_basics(sigma_rule)
        except SigmaConversionError as exc:
            return SigmaConversionResult(
                status=ConversionStatus.INVALID,
                errors=[str(exc)],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        logsource = self._parse_logsource(sigma_rule)
        ok, platform, event_hint, ls_warnings = self.logsource_mapper.map_logsource(logsource)
        if not ok:
            return SigmaConversionResult(
                status=ConversionStatus.UNSUPPORTED,
                errors=ls_warnings,
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )
        warnings.extend(ls_warnings)

        detection = sigma_rule.get("detection") or {}
        selections = {k: v for k, v in detection.items() if k != "condition"}
        condition_text = str(detection.get("condition") or "").strip()
        if not condition_text:
            return SigmaConversionResult(
                status=ConversionStatus.INVALID,
                errors=["Sigma detection.condition is required"],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        if len(selections) > 200:
            return SigmaConversionResult(
                status=ConversionStatus.INVALID,
                errors=["Sigma rule exceeds supported complexity (too many selection blocks)"],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        selection_exprs: dict[str, DetectionExpr] = {}
        unsupported: list[str] = []

        for selection_name, selection_body in selections.items():
            try:
                selection_exprs[selection_name] = self._parse_selection_block(selection_body)
            except SigmaConversionError as exc:
                unsupported.append(f"{selection_name}: {exc}")

        if unsupported:
            return SigmaConversionResult(
                status=ConversionStatus.UNSUPPORTED,
                errors=unsupported,
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        try:
            cond_ast = self.condition_parser.parse(condition_text, list(selection_exprs.keys()))
        except ConditionSyntaxError as exc:
            return SigmaConversionResult(
                status=ConversionStatus.UNSUPPORTED,
                errors=[f"Unsupported condition syntax: {exc}"],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        try:
            root_expr = self._bind_condition_ast(cond_ast, selection_exprs)
        except SigmaConversionError as exc:
            return SigmaConversionResult(
                status=ConversionStatus.UNSUPPORTED,
                errors=[str(exc)],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
            )

        ir = CyberionDetectionIR(
            metadata=metadata,
            logsource=logsource,
            platform=platform,
            event_type_hint=event_hint,
            root_expr=root_expr,
            unsupported_features=[],
            warnings=warnings,
            source_path=source_path,
            original_sigma=sigma_rule,
        )

        try:
            query_def = self._to_query_definition(root_expr, platform=platform, event_hint=event_hint)
        except SigmaConversionError as exc:
            return SigmaConversionResult(
                status=ConversionStatus.UNSUPPORTED,
                errors=[str(exc)],
                sigma_id=sigma_id,
                sigma_title=metadata.title,
                ir=ir,
            )

        severity = SEVERITY_MAP.get((metadata.level or "medium").lower(), AlertSeverity.MEDIUM)

        sigma_meta_payload = {
            "sigma_id": metadata.sigma_id,
            "sigma_title": metadata.title,
            "sigma_status": metadata.status,
            "sigma_author": metadata.author,
            "sigma_date": metadata.date,
            "sigma_modified": metadata.modified,
            "sigma_references": metadata.references,
            "sigma_tags": metadata.tags,
            "sigma_falsepositives": metadata.falsepositives,
            "sigma_level": metadata.level,
            "sigma_logsource": {
                "product": logsource.product,
                "category": logsource.category,
                "service": logsource.service,
            },
            "sigma_source": source_path,
            "sigma_original": self._json_safe(sigma_rule),
        }

        generated_kql = "events"
        try:
            generated_kql = query_definition_to_kql(query_def)
        except Exception:
            warnings.append("Generated KQL preview unavailable; rule still supported by local evaluator")

        description = metadata.description or "Imported Sigma rule"

        rule = AlertRule(
            name=metadata.title or f"Sigma {metadata.sigma_id}",
            description=description,
            enabled=True,
            severity=severity,
            creator_name="Sigma Importer",
            query_definition=query_def,
            generated_kql=generated_kql,
            action=ActionConfig(ActionType.LOG_ALERT, {"sigma_metadata": sigma_meta_payload}),
        )

        status = ConversionStatus.SUPPORTED if not warnings else ConversionStatus.SUPPORTED_WITH_WARNINGS
        return SigmaConversionResult(
            status=status,
            warnings=warnings,
            sigma_id=sigma_id,
            sigma_title=metadata.title,
            ir=ir,
            local_rule=rule,
        )

    def _json_safe(self, value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, list):
            return [self._json_safe(item) for item in value]
        if isinstance(value, tuple):
            return [self._json_safe(item) for item in value]
        if isinstance(value, dict):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        return str(value)

    def _validate_sigma_basics(self, sigma_rule: dict) -> None:
        required = ["title", "detection", "logsource"]
        missing = [name for name in required if name not in sigma_rule]
        if missing:
            raise SigmaConversionError(f"Missing required Sigma fields: {', '.join(missing)}")
        if not isinstance(sigma_rule.get("detection"), dict):
            raise SigmaConversionError("Sigma detection must be a mapping")
        if not isinstance(sigma_rule.get("logsource"), dict):
            raise SigmaConversionError("Sigma logsource must be a mapping")

    def _parse_metadata(self, sigma_rule: dict) -> SigmaMetadata:
        def _list(value) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [value]
            if isinstance(value, list):
                return [str(item) for item in value]
            return [str(value)]

        return SigmaMetadata(
            title=str(sigma_rule.get("title") or ""),
            sigma_id=str(sigma_rule.get("id") or ""),
            status=str(sigma_rule.get("status") or ""),
            description=str(sigma_rule.get("description") or ""),
            author=str(sigma_rule.get("author") or ""),
            date=str(sigma_rule.get("date") or ""),
            modified=str(sigma_rule.get("modified") or ""),
            references=_list(sigma_rule.get("references")),
            tags=_list(sigma_rule.get("tags")),
            falsepositives=_list(sigma_rule.get("falsepositives")),
            level=str(sigma_rule.get("level") or "medium"),
        )

    def _parse_logsource(self, sigma_rule: dict) -> SigmaLogsource:
        src = sigma_rule.get("logsource") or {}
        return SigmaLogsource(
            product=str(src.get("product") or ""),
            category=str(src.get("category") or ""),
            service=str(src.get("service") or ""),
        )

    def _parse_selection_block(self, selection_body: Any) -> DetectionExpr:
        # Sigma allows list-of-maps as OR blocks.
        if isinstance(selection_body, list):
            children: list[DetectionExpr] = []
            for item in selection_body:
                if not isinstance(item, dict):
                    raise SigmaConversionError("Selection list entries must be mappings")
                children.append(self._parse_field_map(item))
            if not children:
                raise SigmaConversionError("Empty selection list")
            return DetectionExpr(kind="or", children=children)

        if not isinstance(selection_body, dict):
            raise SigmaConversionError("Selection must be a mapping or list of mappings")

        return self._parse_field_map(selection_body)

    def _parse_field_map(self, field_map: dict) -> DetectionExpr:
        children: list[DetectionExpr] = []
        for sigma_field_expr, value in field_map.items():
            if sigma_field_expr is None:
                raise SigmaConversionError("Encountered null field in Sigma selection")
            children.append(self._parse_field_condition(str(sigma_field_expr), value))

        if not children:
            raise SigmaConversionError("Empty selection mapping")
        if len(children) == 1:
            return children[0]
        return DetectionExpr(kind="and", children=children)

    def _parse_field_condition(self, sigma_field_expr: str, value: Any) -> DetectionExpr:
        parts = sigma_field_expr.split("|")
        sigma_field = parts[0].strip()
        modifiers = [p.strip().lower() for p in parts[1:] if p.strip()]

        cyber_field = self.field_mapper.map_field(sigma_field)
        if not cyber_field:
            raise SigmaConversionError(f"Unsupported field: {sigma_field}")

        if cyber_field == "event_id":
            # Current query model does not include event_id; map to message fallback.
            cyber_field = "message"

        modifier_signature = "|".join(modifiers)
        if modifier_signature in SUPPORTED_COMPOUND_MODIFIERS:
            base = "contains"
            mode = "all" if modifier_signature.endswith("|all") else "any"
        elif not modifiers:
            base = "equals"
            mode = "any"
        elif len(modifiers) == 1 and modifiers[0] in SUPPORTED_BASE_MODIFIERS:
            base = modifiers[0]
            mode = "any"
        else:
            unsupported = modifier_signature or ",".join(modifiers)
            raise SigmaConversionError(f"Unsupported Sigma modifier: {unsupported}")

        values: list[Any]
        if isinstance(value, list):
            values = value
        else:
            values = [value]
        if not values:
            raise SigmaConversionError(f"Empty value list for field {sigma_field_expr}")

        atom_children: list[DetectionExpr] = []
        op = self._modifier_to_operator(base)

        for raw in values:
            normalized = self._normalize_value(raw)
            if op == "regex":
                self._validate_regex_pattern(normalized)
            atom_children.append(
                DetectionExpr(
                    kind="atom",
                    atom=DetectionAtom(field=cyber_field, operator=op, values=[normalized]),
                )
            )

        if len(atom_children) == 1:
            return atom_children[0]

        if mode == "all":
            return DetectionExpr(kind="and", children=atom_children)
        return DetectionExpr(kind="or", children=atom_children)

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)):
            return value
        if value is None:
            return ""
        return str(value)

    def _validate_regex_pattern(self, pattern: Any) -> None:
        if not isinstance(pattern, str):
            raise SigmaConversionError("Regex values must be strings")
        if len(pattern) > 256:
            raise SigmaConversionError("Regex pattern exceeds safety length limit")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise SigmaConversionError(f"Invalid regex pattern: {exc}") from exc

    def _modifier_to_operator(self, modifier: str) -> str:
        mapping = {
            "equals": "equals",
            "contains": "contains",
            "startswith": "startswith",
            "endswith": "endswith",
            "re": "regex",
        }
        if modifier not in mapping:
            raise SigmaConversionError(f"Unsupported Sigma modifier: {modifier}")
        return mapping[modifier]

    def _bind_condition_ast(self, condition_ast: DetectionExpr, selections: dict[str, DetectionExpr]) -> DetectionExpr:
        if condition_ast.kind == "atom":
            selection_name = str(condition_ast.atom)
            if selection_name not in selections:
                raise SigmaConversionError(f"Unknown selection in condition: {selection_name}")
            return selections[selection_name]

        if condition_ast.kind in {"and", "or"}:
            return DetectionExpr(
                kind=condition_ast.kind,
                children=[self._bind_condition_ast(child, selections) for child in condition_ast.children],
            )

        if condition_ast.kind == "not":
            if len(condition_ast.children) != 1:
                raise SigmaConversionError("Invalid NOT expression")
            child = self._bind_condition_ast(condition_ast.children[0], selections)
            return DetectionExpr(kind="not", children=[child])

        raise SigmaConversionError(f"Unsupported condition node type: {condition_ast.kind}")

    def _to_query_definition(self, expr: DetectionExpr, platform: str, event_hint: str) -> QueryDefinition:
        root = self._expr_to_group(expr)

        # Apply platform/logsource guardrails so rules target intended telemetry only.
        guard_conditions: list[Condition] = []
        if platform:
            guard_conditions.append(
                Condition(field="os", operator=ComparisonOperator.EQUALS, value=platform)
            )
        if event_hint:
            guard_conditions.append(
                Condition(field="event_type", operator=ComparisonOperator.EQUALS, value=event_hint)
            )

        if guard_conditions:
            guarded = ConditionGroup(logical_operator=LogicalOperator.AND)
            for cond in guard_conditions:
                guarded.add_condition(cond)
            guarded.add_group(root)
            return QueryDefinition(root_group=guarded)

        return QueryDefinition(root_group=root)

    def _expr_to_group(self, expr: DetectionExpr) -> ConditionGroup:
        if expr.kind == "atom":
            if not isinstance(expr.atom, DetectionAtom):
                raise SigmaConversionError("Invalid atom payload")
            group = ConditionGroup(logical_operator=LogicalOperator.AND)
            group.add_condition(self._atom_to_condition(expr.atom))
            return group

        if expr.kind == "and":
            group = ConditionGroup(logical_operator=LogicalOperator.AND)
            for child in expr.children:
                group.add_group(self._expr_to_group(child))
            return group

        if expr.kind == "or":
            group = ConditionGroup(logical_operator=LogicalOperator.OR)
            for child in expr.children:
                group.add_group(self._expr_to_group(child))
            return group

        if expr.kind == "not":
            if len(expr.children) != 1:
                raise SigmaConversionError("Invalid NOT expression")
            return self._negate_group(self._expr_to_group(expr.children[0]))

        raise SigmaConversionError(f"Unsupported expression kind: {expr.kind}")

    def _atom_to_condition(self, atom: DetectionAtom) -> Condition:
        value = atom.values[0] if atom.values else ""
        if atom.operator == "equals":
            op = ComparisonOperator.EQUALS
        elif atom.operator == "contains":
            op = ComparisonOperator.CONTAINS
        elif atom.operator == "startswith":
            op = ComparisonOperator.STARTS_WITH
        elif atom.operator == "endswith":
            op = ComparisonOperator.ENDS_WITH
        elif atom.operator == "regex":
            # Stored as regex token for evaluator; query preview may fall back.
            op = ComparisonOperator.REGEX
        else:
            raise SigmaConversionError(f"Unsupported atom operator: {atom.operator}")

        return Condition(field=atom.field, operator=op, value=value)

    def _negate_group(self, group: ConditionGroup) -> ConditionGroup:
        # DeMorgan conversion into model-supported operators/groups.
        if group.conditions and not group.groups:
            neg = ConditionGroup(logical_operator=LogicalOperator.OR)
            for cond in group.conditions:
                neg.add_condition(self._invert_condition(cond))
            return neg

        if group.groups and not group.conditions:
            inverted_children = [self._negate_group(child) for child in group.groups]
            neg_op = LogicalOperator.OR if group.logical_operator == LogicalOperator.AND else LogicalOperator.AND
            neg = ConditionGroup(logical_operator=neg_op)
            for child in inverted_children:
                neg.add_group(child)
            return neg

        # Mixed conditions and groups: normalize into child groups then negate.
        normalized = ConditionGroup(logical_operator=group.logical_operator)
        for cond in group.conditions:
            child = ConditionGroup(logical_operator=LogicalOperator.AND)
            child.add_condition(cond)
            normalized.add_group(child)
        for child_group in group.groups:
            normalized.add_group(child_group)
        return self._negate_group(normalized)

    def _invert_condition(self, cond: Condition) -> Condition:
        inv = INVERTIBLE_OPERATORS.get(cond.operator)
        if inv:
            return Condition(field=cond.field, operator=inv, value=cond.value)

        if cond.operator == ComparisonOperator.STARTS_WITH:
            raise SigmaConversionError("Unsupported negation: NOT startswith")
        if cond.operator == ComparisonOperator.ENDS_WITH:
            raise SigmaConversionError("Unsupported negation: NOT endswith")
        if cond.operator == ComparisonOperator.REGEX:
            return Condition(field=cond.field, operator=ComparisonOperator.NOT_REGEX, value=cond.value)

        raise SigmaConversionError(f"Unsupported negation for operator: {cond.operator.value}")
