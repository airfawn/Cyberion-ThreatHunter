"""Cyberion Query Language module.

A KQL-inspired query language for searching, filtering, and analyzing
security events stored in the Cyberion database.

Example:
    from src.query import CyberionQueryEngine
    
    engine = CyberionQueryEngine(database)
    result = engine.execute('events | where severity >= 3 | take 100')
"""

from .engine import CyberionQueryEngine, QueryEngineError, QueryResult
from .parser import Parser, ParseError
from .validator import QueryValidator, ValidationError
from .compiler import QueryCompiler, CompileError

__all__ = [
    "CyberionQueryEngine",
    "QueryEngineError",
    "QueryResult",
    "Parser",
    "ParseError",
    "QueryValidator",
    "ValidationError",
    "QueryCompiler",
    "CompileError",
]
