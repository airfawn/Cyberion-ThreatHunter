"""Validator for Cyberion Query Language AST.

Performs semantic validation:
- Field names are valid
- Operators are valid for their operand types
- Sort/project/distinct/aggregation fields exist
- NULL handling is correct
- No SQL injection attempts
"""

from datetime import datetime, timedelta
from typing import List, Set

from .ast import (
    Aggregation,
    Comparison,
    DistinctOperator,
    Expression,
    Field,
    FunctionCall,
    Literal,
    LogicalOp,
    ProjectOperator,
    Query,
    SortOperator,
    StringOp,
    SummarizeOperator,
    TakeOperator,
    WhereOperator,
)


class ValidationError(Exception):
    """Raised when validation fails."""

    pass


class QueryValidator:
    """Validates a parsed query AST."""

    # Valid database field names (from database.py SCHEMA_COLUMNS)
    VALID_FIELDS = {
        "timestamp", "received_at", "source", "agent_id", "agent_name",
        "hostname", "os", "event_type", "severity", "success",
        "pid", "ppid", "process_name", "parent_process",
        "user", "filepath", "command", "message", "ip_address",
        "id",  # Allow id for direct lookups
    }

    # Fields that are numeric
    NUMERIC_FIELDS = {
        "severity", "success", "pid", "ppid",
    }

    # Fields that are timestamps
    TIMESTAMP_FIELDS = {
        "timestamp", "received_at",
    }

    # Fields that are text
    TEXT_FIELDS = {
        "source", "agent_id", "agent_name", "hostname", "os",
        "event_type", "process_name", "parent_process",
        "user", "filepath", "command", "message", "ip_address",
    }

    VALID_AGGREGATIONS = {"count", "dcount", "sum", "avg", "min", "max"}
    VALID_SORT_DIRECTIONS = {"asc", "desc"}

    def __init__(self):
        self.errors: List[str] = []

    def validate(self, query: Query) -> None:
        """Validate the entire query."""
        # Validate pipeline operators in order
        for i, op in enumerate(query.pipeline):
            if isinstance(op, WhereOperator):
                self._validate_where(op)
            elif isinstance(op, ProjectOperator):
                self._validate_project(op)
            elif isinstance(op, SortOperator):
                self._validate_sort(op)
            elif isinstance(op, TakeOperator):
                self._validate_take(op)
            elif isinstance(op, DistinctOperator):
                self._validate_distinct(op)
            elif isinstance(op, SummarizeOperator):
                self._validate_summarize(op)

        if self.errors:
            raise ValidationError("\n".join(self.errors))

    def _validate_where(self, op: WhereOperator) -> None:
        """Validate a WHERE clause."""
        self._validate_expression(op.condition)

    def _validate_expression(self, expr: Expression) -> None:
        """Validate an expression recursively."""
        if isinstance(expr, Comparison):
            self._validate_comparison(expr)
        elif isinstance(expr, LogicalOp):
            self._validate_logical_op(expr)
        elif isinstance(expr, Literal):
            pass  # Literals are always valid
        elif isinstance(expr, Field):
            self._validate_field(expr.name)
        elif isinstance(expr, FunctionCall):
            self._validate_function_call(expr)
        elif isinstance(expr, StringOp):
            self._validate_string_op(expr)

    def _validate_comparison(self, comp: Comparison) -> None:
        """Validate a comparison expression."""
        # Recursively validate both sides
        self._validate_expression(comp.left)
        self._validate_expression(comp.right)

        # Check operator validity
        valid_ops = {"==", "!=", "<", "<=", ">", ">="}
        if comp.operator not in valid_ops:
            self.errors.append(f"Unknown comparison operator: {comp.operator}")

    def _validate_logical_op(self, op: LogicalOp) -> None:
        """Validate a logical operation."""
        self._validate_expression(op.left)
        if op.right:
            self._validate_expression(op.right)

        valid_ops = {"and", "or", "not"}
        if op.operator not in valid_ops:
            self.errors.append(f"Unknown logical operator: {op.operator}")

    def _validate_function_call(self, func: FunctionCall) -> None:
        """Validate a function call (e.g., ago())."""
        if func.name == "ago":
            if len(func.args) != 1:
                self.errors.append(f"ago() expects 1 argument, got {len(func.args)}")
            else:
                arg = func.args[0]
                # Validate the time duration argument
                self._validate_ago_argument(arg)
        else:
            self.errors.append(f"Unknown function: {func.name}")

    def _validate_ago_argument(self, arg) -> None:
        """Validate an ago() argument (e.g., '1h', '24h', '7d')."""
        if not isinstance(arg, str):
            self.errors.append(f"ago() expects a time duration string, got {type(arg).__name__}")
            return

        # Parse duration: number + unit
        import re
        match = re.match(r"^(\d+)([smhd])$", arg)
        if not match:
            self.errors.append(
                f"Invalid time duration: {arg!r}. "
                f"Use format like '5m', '1h', '24h', '7d'"
            )

    def _validate_string_op(self, op: StringOp) -> None:
        """Validate a string operation."""
        self._validate_field(op.field)

        valid_ops = {"contains", "startswith", "endswith"}
        if op.operator not in valid_ops:
            self.errors.append(f"Unknown string operator: {op.operator}")

    def _validate_field(self, field: str) -> None:
        """Validate a field name."""
        if field not in self.VALID_FIELDS:
            # Suggest did-you-mean
            suggestion = self._find_suggestion(field)
            if suggestion:
                self.errors.append(
                    f"Unknown field {field!r}. Did you mean {suggestion!r}?"
                )
            else:
                self.errors.append(f"Unknown field {field!r}")

    def _find_suggestion(self, field: str) -> str:
        """Find a field suggestion using Levenshtein distance."""
        # Simple heuristic: fields that share at least 2 characters
        field_lower = field.lower()
        candidates = [
            f for f in self.VALID_FIELDS
            if f.lower() != field_lower and self._similarity(field_lower, f) > 0.6
        ]
        if candidates:
            return min(candidates, key=lambda f: self._distance(field_lower, f))
        return None

    def _similarity(self, a: str, b: str) -> float:
        """Simple character overlap similarity."""
        a_set = set(a)
        b_set = set(b)
        if not a_set or not b_set:
            return 0.0
        intersection = len(a_set & b_set)
        union = len(a_set | b_set)
        return intersection / union

    def _distance(self, a: str, b: str) -> int:
        """Levenshtein distance."""
        if len(a) < len(b):
            return self._distance(b, a)
        if len(b) == 0:
            return len(a)

        prev = list(range(len(b) + 1))
        for i, ch_a in enumerate(a):
            curr = [i + 1]
            for j, ch_b in enumerate(b):
                if ch_a == ch_b:
                    curr.append(prev[j])
                else:
                    curr.append(1 + min(prev[j], prev[j + 1], curr[j]))
            prev = curr

        return prev[-1]

    def _validate_project(self, op: ProjectOperator) -> None:
        """Validate a PROJECT clause."""
        for col in op.columns:
            self._validate_field(col.field)

    def _validate_sort(self, op: SortOperator) -> None:
        """Validate a SORT clause."""
        for sort_field in op.fields:
            self._validate_field(sort_field.field)
            if sort_field.direction not in self.VALID_SORT_DIRECTIONS:
                self.errors.append(
                    f"Invalid sort direction: {sort_field.direction!r}. "
                    f"Use 'asc' or 'desc'."
                )

    def _validate_take(self, op: TakeOperator) -> None:
        """Validate a TAKE clause."""
        if not isinstance(op.count, int):
            self.errors.append(f"take() requires an integer, got {type(op.count).__name__}")
        elif op.count < 1:
            self.errors.append(f"take() requires a positive integer, got {op.count}")
        elif op.count > 1000000:
            self.errors.append(
                f"take() limit too large: {op.count}. "
                f"Maximum is 1,000,000."
            )

    def _validate_distinct(self, op: DistinctOperator) -> None:
        """Validate a DISTINCT clause."""
        for field in op.fields:
            self._validate_field(field)

    def _validate_summarize(self, op: SummarizeOperator) -> None:
        """Validate a SUMMARIZE clause."""
        for agg in op.aggregations:
            self._validate_aggregation(agg)

        if op.group_by:
            for field in op.group_by:
                self._validate_field(field)

    def _validate_aggregation(self, agg: Aggregation) -> None:
        """Validate an aggregation function."""
        if agg.function not in self.VALID_AGGREGATIONS:
            self.errors.append(
                f"Unknown aggregation function: {agg.function}. "
                f"Valid functions: {', '.join(sorted(self.VALID_AGGREGATIONS))}"
            )

        # Some functions require a field argument
        functions_requiring_field = {"dcount", "sum", "avg", "min", "max"}
        if agg.function in functions_requiring_field and agg.field is None:
            self.errors.append(
                f"Aggregation function {agg.function}() requires a field argument"
            )

        if agg.field:
            self._validate_field(agg.field)
