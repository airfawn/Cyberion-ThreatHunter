"""Query Engine for Cyberion Query Language.

High-level API that orchestrates:
- Lexing
- Parsing
- Validation
- Compilation
- Execution

This is the main interface for GUI and future Alert Engine / Threat Analysis systems.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .compiler import QueryCompiler, CompileError
from .parser import Parser, ParseError
from .validator import QueryValidator, ValidationError


@dataclass
class QueryResult:
    """Result of executing a query."""

    rows: List[Dict[str, Any]]
    columns: List[str]
    execution_time_ms: float
    row_count: int
    query_text: str
    compiled_sql: str


class QueryEngineError(Exception):
    """Base exception for query engine errors."""

    pass


class CyberionQueryEngine:
    """High-level query engine for Cyberion.

    Usage:
        engine = CyberionQueryEngine(database)
        result = engine.execute('events | where severity >= 3 | take 100')
        for row in result.rows:
            print(row)
    """

    def __init__(self, db):
        """Initialize the query engine.

        Args:
            db: A CyberionDB instance or compatible object.
        """
        self.db = db

    def execute(self, query_text: str) -> QueryResult:
        """Execute a Cyberion query and return results.

        Args:
            query_text: The query string, e.g., 'events | where severity >= 3'

        Returns:
            QueryResult with rows, columns, and metadata.

        Raises:
            QueryEngineError: If any step fails (parse, validation, compilation, execution).
        """
        import time

        start_time = time.time()

        try:
            # Step 1: Parse
            parser = Parser.from_string(query_text)
            ast = parser.parse()
        except ParseError as e:
            raise QueryEngineError(f"Parse error: {e}")
        except Exception as e:
            raise QueryEngineError(f"Unexpected parse error: {e}")

        try:
            # Step 2: Validate
            validator = QueryValidator()
            validator.validate(ast)
        except ValidationError as e:
            raise QueryEngineError(f"Validation error: {e}")
        except Exception as e:
            raise QueryEngineError(f"Unexpected validation error: {e}")

        try:
            # Step 3: Compile
            compiler = QueryCompiler()
            compiled = compiler.compile(ast)
        except CompileError as e:
            raise QueryEngineError(f"Compilation error: {e}")
        except Exception as e:
            raise QueryEngineError(f"Unexpected compilation error: {e}")

        try:
            # Step 4: Execute
            rows, columns = self._execute_sql(compiled.sql, compiled.params)
        except Exception as e:
            raise QueryEngineError(f"Database error: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return QueryResult(
            rows=rows,
            columns=columns,
            execution_time_ms=elapsed_ms,
            row_count=len(rows),
            query_text=query_text,
            compiled_sql=compiled.sql,
        )

    def _execute_sql(self, sql: str, params: List[Any]) -> tuple:
        """Execute parameterized SQL and return rows + column names.

        Returns:
            (rows, columns) where rows is a list of dicts and columns is a list of field names.
        """
        lock = getattr(self.db, "_lock", None)

        def _run_query() -> tuple:
            cur = self.db.conn.cursor()

            # Execute the query
            cur.execute(sql, params)

            # Get column names
            columns = [desc[0] for desc in cur.description] if cur.description else []

            # Fetch all rows as dictionaries
            rows = []
            for row in cur.fetchall():
                row_dict = {}
                for i, col in enumerate(columns):
                    row_dict[col] = row[i]
                rows.append(row_dict)

            return rows, columns

        if lock is not None:
            with lock:
                return _run_query()
        return _run_query()
