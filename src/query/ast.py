"""Abstract Syntax Tree (AST) node definitions for Cyberion Query Language.

The parser produces an AST, which is then validated and compiled to SQL.
No SQL logic should be in this file -- only data structures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Optional, Union


class ASTNode(ABC):
    """Base class for all AST nodes."""

    @abstractmethod
    def __repr__(self) -> str:
        pass


# ============================================================================
# Query Structure
# ============================================================================


@dataclass
class Query(ASTNode):
    """Root node representing an entire query."""

    source: "Source"
    pipeline: List["PipelineOperator"]

    def __repr__(self) -> str:
        ops = " -> ".join(repr(op) for op in self.pipeline) if self.pipeline else "(empty)"
        return f"Query({self.source} | {ops})"


@dataclass
class Source(ASTNode):
    """The data source (currently always 'events')."""

    name: str

    def __repr__(self) -> str:
        return f"Source({self.name})"


# ============================================================================
# Pipeline Operators
# ============================================================================


class PipelineOperator(ASTNode):
    """Base class for all pipeline operators."""

    pass


@dataclass
class WhereOperator(PipelineOperator):
    """Filters rows based on a boolean expression."""

    condition: "Expression"

    def __repr__(self) -> str:
        return f"Where({self.condition})"


@dataclass
class ProjectOperator(PipelineOperator):
    """Selects specific columns."""

    columns: List["ProjectColumn"]

    def __repr__(self) -> str:
        cols = ", ".join(repr(c) for c in self.columns)
        return f"Project({cols})"


@dataclass
class ProjectColumn(ASTNode):
    """A column in a project operation (with optional alias)."""

    field: str
    alias: Optional[str] = None

    def __repr__(self) -> str:
        if self.alias:
            return f"{self.field} as {self.alias}"
        return self.field


@dataclass
class SortOperator(PipelineOperator):
    """Sorts rows by one or more fields."""

    fields: List["SortField"]

    def __repr__(self) -> str:
        fields = ", ".join(repr(f) for f in self.fields)
        return f"Sort({fields})"


@dataclass
class SortField(ASTNode):
    """A sort field with direction (asc/desc)."""

    field: str
    direction: str = "asc"  # "asc" or "desc"

    def __repr__(self) -> str:
        return f"{self.field} {self.direction}"


@dataclass
class TakeOperator(PipelineOperator):
    """Limits the number of returned rows."""

    count: int

    def __repr__(self) -> str:
        return f"Take({self.count})"


@dataclass
class DistinctOperator(PipelineOperator):
    """Returns unique rows based on specified fields."""

    fields: List[str]

    def __repr__(self) -> str:
        fields = ", ".join(self.fields)
        return f"Distinct({fields})"


@dataclass
class SummarizeOperator(PipelineOperator):
    """Aggregates rows."""

    aggregations: List["Aggregation"]
    group_by: Optional[List[str]] = None

    def __repr__(self) -> str:
        aggs = ", ".join(repr(a) for a in self.aggregations)
        if self.group_by:
            by = ", ".join(self.group_by)
            return f"Summarize({aggs} by {by})"
        return f"Summarize({aggs})"


@dataclass
class Aggregation(ASTNode):
    """An aggregation function (e.g., count(), count(field), max(field))."""

    function: str  # "count", "dcount", "min", "max", "avg", etc.
    field: Optional[str] = None  # None for count(), field name for others
    alias: Optional[str] = None  # Optional alias for the result

    def __repr__(self) -> str:
        if self.field:
            result = f"{self.function}({self.field})"
        else:
            result = f"{self.function}()"
        if self.alias:
            return f"{result} as {self.alias}"
        return result


# ============================================================================
# Expressions
# ============================================================================


class Expression(ASTNode):
    """Base class for boolean expressions (used in WHERE clauses)."""

    pass


@dataclass
class Comparison(Expression):
    """A binary comparison: left <op> right."""

    left: "Expression"
    operator: str  # "==", "!=", ">", "<", ">=", "<=", etc.
    right: "Expression"

    def __repr__(self) -> str:
        return f"({self.left} {self.operator} {self.right})"


@dataclass
class LogicalOp(Expression):
    """Logical AND, OR, NOT."""

    operator: str  # "and", "or", "not"
    left: Expression
    right: Optional[Expression] = None  # None for "not"

    def __repr__(self) -> str:
        if self.operator == "not":
            return f"(NOT {self.left})"
        return f"({self.left} {self.operator.upper()} {self.right})"


@dataclass
class Literal(Expression):
    """A literal value: number, string, null, etc."""

    value: Any

    def __repr__(self) -> str:
        if isinstance(self.value, str):
            return f'"{self.value}"'
        if self.value is None:
            return "null"
        return str(self.value)


@dataclass
class Field(Expression):
    """A field reference."""

    name: str

    def __repr__(self) -> str:
        return self.name


@dataclass
class FunctionCall(Expression):
    """A function call, e.g., ago(1h)."""

    name: str
    args: List[Any]

    def __repr__(self) -> str:
        args = ", ".join(str(a) for a in self.args)
        return f"{self.name}({args})"


@dataclass
class StringOp(Expression):
    """String comparison: field [contains|startswith|endswith] value."""

    field: str
    operator: str  # "contains", "startswith", "endswith"
    value: str

    def __repr__(self) -> str:
        return f"{self.field} {self.operator} {self.value!r}"
