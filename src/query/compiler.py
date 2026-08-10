"""Compiler for Cyberion Query Language.

Transforms a validated AST into parameterized SQL and parameter values.
This is where SQL is generated, and it must be extremely careful about
SQL injection prevention.

No user input ever appears directly in SQL strings.
All values are parameterized.
Field names come only from a validated allowlist.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

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


class CompileError(Exception):
    """Raised when compilation fails."""

    pass


@dataclass
class CompiledQuery:
    """The result of compiling an AST to SQL."""

    sql: str
    params: List[Any]

    def __repr__(self) -> str:
        return f"CompiledQuery(sql={self.sql!r}, params={self.params!r})"


class QueryCompiler:
    """Compiles a validated AST into parameterized SQL."""

    # Valid database fields (must match the database schema)
    VALID_FIELDS = {
        "id", "timestamp", "received_at", "source", "agent_id", "agent_name",
        "hostname", "os", "event_type", "severity", "success",
        "pid", "ppid", "process_name", "parent_process",
        "user", "filepath", "command", "message", "ip_address",
    }

    # Maximum result limit
    MAX_LIMIT = 10000

    def __init__(self):
        self.params: List[Any] = []

    def compile(self, query: Query) -> CompiledQuery:
        """Compile a query AST to parameterized SQL."""
        self.params = []

        # Start with SELECT * FROM events
        from_clause = "FROM events"
        where_clause = ""
        group_by_clause = ""
        having_clause = ""
        order_by_clause = ""
        limit_clause = ""
        select_clause = "SELECT *"

        # Track what transformations we've applied
        has_where = False
        has_project = False
        has_sort = False
        has_take = False
        has_distinct = False
        has_summarize = False

        # Process pipeline operators in order
        for op in query.pipeline:
            if isinstance(op, WhereOperator):
                where_clause = self._compile_where(op)
                has_where = True
            elif isinstance(op, ProjectOperator):
                select_clause = self._compile_project(op)
                has_project = True
            elif isinstance(op, SortOperator):
                order_by_clause = self._compile_sort(op)
                has_sort = True
            elif isinstance(op, TakeOperator):
                limit_clause = self._compile_take(op)
                has_take = True
            elif isinstance(op, DistinctOperator):
                select_clause = self._compile_distinct(op)
                has_distinct = True
            elif isinstance(op, SummarizeOperator):
                select_clause, group_by_clause = self._compile_summarize(op)
                has_summarize = True

        # Build the final SQL statement
        sql_parts = [select_clause, from_clause]

        if where_clause:
            sql_parts.append(where_clause)

        if group_by_clause:
            sql_parts.append(group_by_clause)

        if having_clause:
            sql_parts.append(having_clause)

        if order_by_clause:
            sql_parts.append(order_by_clause)

        if limit_clause:
            sql_parts.append(limit_clause)

        sql = " ".join(sql_parts)

        return CompiledQuery(sql, self.params)

    def _compile_where(self, op: WhereOperator) -> str:
        """Compile a WHERE clause."""
        condition = self._compile_expression(op.condition)
        return f"WHERE {condition}"

    def _compile_expression(self, expr: Expression) -> str:
        """Compile an expression to SQL."""
        if isinstance(expr, Comparison):
            return self._compile_comparison(expr)
        elif isinstance(expr, LogicalOp):
            return self._compile_logical_op(expr)
        elif isinstance(expr, Literal):
            return self._compile_literal(expr)
        elif isinstance(expr, Field):
            return self._compile_field(expr)
        elif isinstance(expr, FunctionCall):
            return self._compile_function_call(expr)
        elif isinstance(expr, StringOp):
            return self._compile_string_op(expr)
        else:
            raise CompileError(f"Unknown expression type: {type(expr).__name__}")

    def _compile_comparison(self, comp: Comparison) -> str:
        """Compile a comparison expression."""
        left = self._compile_expression(comp.left)
        right = self._compile_expression(comp.right)

        op = comp.operator
        # Handle NULL comparisons specially
        if right == "NULL":
            if op == "==":
                return f"{left} IS NULL"
            elif op == "!=":
                return f"{left} IS NOT NULL"

        return f"{left} {op} {right}"

    def _compile_logical_op(self, op: LogicalOp) -> str:
        """Compile a logical operation."""
        if op.operator == "not":
            return f"NOT ({self._compile_expression(op.left)})"

        left = self._compile_expression(op.left)
        right = self._compile_expression(op.right)

        op_str = "AND" if op.operator == "and" else "OR"
        return f"({left} {op_str} {right})"

    def _compile_literal(self, lit: Literal) -> str:
        """Compile a literal value."""
        if lit.value is None:
            return "NULL"

        # Convert boolean to 0/1 for SQLite
        value = lit.value
        if isinstance(value, bool):
            value = 1 if value else 0

        # Add the value to parameters
        self.params.append(value)
        return "?"

    def _compile_field(self, field: Field) -> str:
        """Compile a field reference."""
        field_name = field.name
        if field_name not in self.VALID_FIELDS:
            raise CompileError(f"Invalid field: {field_name}")
        return field_name

    def _compile_function_call(self, func: FunctionCall) -> str:
        """Compile a function call like ago(1h)."""
        if func.name == "ago":
            if len(func.args) != 1:
                raise CompileError(f"ago() expects 1 argument, got {len(func.args)}")

            duration_str = func.args[0]
            if not isinstance(duration_str, str):
                raise CompileError(f"ago() expects a string duration, got {type(duration_str).__name__}")

            # Parse duration: e.g., "1h" -> 1 hour ago
            import re
            match = re.match(r"^(\d+)([smhd])$", duration_str)
            if not match:
                raise CompileError(f"Invalid time duration: {duration_str!r}")

            number = int(match.group(1))
            unit = match.group(2)

            # Calculate the timestamp
            now = datetime.now(timezone.utc)
            if unit == "s":
                target = now - timedelta(seconds=number)
            elif unit == "m":
                target = now - timedelta(minutes=number)
            elif unit == "h":
                target = now - timedelta(hours=number)
            elif unit == "d":
                target = now - timedelta(days=number)
            else:
                raise CompileError(f"Unknown time unit: {unit}")

            # Format as ISO 8601
            timestamp_str = target.strftime("%Y-%m-%dT%H:%M:%S")
            self.params.append(timestamp_str)
            return "?"

        raise CompileError(f"Unknown function: {func.name}")

    def _compile_string_op(self, op: StringOp) -> str:
        """Compile a string operation."""
        if op.field not in self.VALID_FIELDS:
            raise CompileError(f"Invalid field: {op.field}")

        self.params.append(op.value)

        if op.operator == "contains":
            # LIKE with wildcards
            return f"{op.field} LIKE '%' || ? || '%'"
        elif op.operator == "startswith":
            return f"{op.field} LIKE ? || '%'"
        elif op.operator == "endswith":
            return f"{op.field} LIKE '%' || ?"
        else:
            raise CompileError(f"Unknown string operator: {op.operator}")

    def _compile_project(self, op: ProjectOperator) -> str:
        """Compile a PROJECT clause."""
        columns = []
        for col in op.columns:
            if col.field not in self.VALID_FIELDS:
                raise CompileError(f"Invalid field in project: {col.field}")
            if col.alias:
                columns.append(f"{col.field} AS {col.alias}")
            else:
                columns.append(col.field)

        return f"SELECT {', '.join(columns)}"

    def _compile_sort(self, op: SortOperator) -> str:
        """Compile a SORT BY clause."""
        fields = []
        for sort_field in op.fields:
            if sort_field.field not in self.VALID_FIELDS:
                raise CompileError(f"Invalid field in sort: {sort_field.field}")
            direction = sort_field.direction.upper()
            fields.append(f"{sort_field.field} {direction}")

        return f"ORDER BY {', '.join(fields)}"

    def _compile_take(self, op: TakeOperator) -> str:
        """Compile a TAKE clause."""
        count = op.count
        if count > self.MAX_LIMIT:
            count = self.MAX_LIMIT
        return f"LIMIT {count}"

    def _compile_distinct(self, op: DistinctOperator) -> str:
        """Compile a DISTINCT clause."""
        columns = []
        for field in op.fields:
            if field not in self.VALID_FIELDS:
                raise CompileError(f"Invalid field in distinct: {field}")
            columns.append(field)

        return f"SELECT DISTINCT {', '.join(columns)}"

    def _compile_summarize(self, op: SummarizeOperator) -> Tuple[str, str]:
        """Compile a SUMMARIZE clause.

        Returns: (select_clause, group_by_clause)
        """
        select_parts = []

        for agg in op.aggregations:
            if agg.function == "count":
                if agg.field:
                    if agg.field not in self.VALID_FIELDS:
                        raise CompileError(f"Invalid field in aggregation: {agg.field}")
                    select_parts.append(f"COUNT({agg.field})")
                else:
                    select_parts.append("COUNT(*)")
            elif agg.function == "dcount":
                if not agg.field:
                    raise CompileError("dcount() requires a field argument")
                if agg.field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in aggregation: {agg.field}")
                select_parts.append(f"COUNT(DISTINCT {agg.field})")
            elif agg.function == "sum":
                if not agg.field:
                    raise CompileError("sum() requires a field argument")
                if agg.field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in aggregation: {agg.field}")
                select_parts.append(f"SUM({agg.field})")
            elif agg.function == "avg":
                if not agg.field:
                    raise CompileError("avg() requires a field argument")
                if agg.field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in aggregation: {agg.field}")
                select_parts.append(f"AVG({agg.field})")
            elif agg.function == "min":
                if not agg.field:
                    raise CompileError("min() requires a field argument")
                if agg.field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in aggregation: {agg.field}")
                select_parts.append(f"MIN({agg.field})")
            elif agg.function == "max":
                if not agg.field:
                    raise CompileError("max() requires a field argument")
                if agg.field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in aggregation: {agg.field}")
                select_parts.append(f"MAX({agg.field})")
            else:
                raise CompileError(f"Unknown aggregation: {agg.function}")

            # Add alias if present
            if agg.alias:
                select_parts[-1] = f"{select_parts[-1]} AS {agg.alias}"

        # Add group_by fields to select
        group_by_clause = ""
        if op.group_by:
            for field in op.group_by:
                if field not in self.VALID_FIELDS:
                    raise CompileError(f"Invalid field in group by: {field}")
                select_parts.insert(0, field)
            group_by_clause = f"GROUP BY {', '.join(op.group_by)}"

        select_clause = f"SELECT {', '.join(select_parts)}"
        return select_clause, group_by_clause
