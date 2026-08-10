"""Parser for Cyberion Query Language.

Transforms a stream of tokens into an Abstract Syntax Tree (AST).
The parser uses recursive descent parsing for clarity and error recovery.

Example:
    events | where severity >= 3 | take 100
    
    → Tokens
    → Parser
    → Query(Source("events"), [Where(...), Take(...)])
"""

from typing import List, Optional

from .ast import (
    Aggregation,
    Comparison,
    DistinctOperator,
    Expression,
    Field,
    Literal,
    LogicalOp,
    ProjectColumn,
    ProjectOperator,
    Query,
    SortField,
    SortOperator,
    Source,
    StringOp,
    SummarizeOperator,
    TakeOperator,
    WhereOperator,
    FunctionCall,
)
from .tokens import Lexer, Token, TokenType


class ParseError(Exception):
    """Raised when the parser encounters an error."""

    pass


class Parser:
    """Recursive descent parser for Cyberion queries."""

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    @classmethod
    def from_string(cls, query: str) -> "Parser":
        """Create a parser from a query string."""
        lexer = Lexer(query)
        tokens = lexer.tokenize()
        return cls(tokens)

    def error(self, msg: str) -> None:
        """Raise a parse error with context."""
        token = self.current()
        raise ParseError(
            f"Parse error at line {token.line}, column {token.column}: {msg}\n"
            f"Got: {token}"
        )

    def current(self) -> Token:
        """Get the current token without consuming it."""
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]  # EOF token

    def peek(self, offset: int = 1) -> Token:
        """Peek ahead at a token."""
        pos = self.pos + offset
        if pos < len(self.tokens):
            return self.tokens[pos]
        return self.tokens[-1]  # EOF token

    def advance(self) -> Token:
        """Consume and return the current token."""
        token = self.current()
        if token.type != TokenType.EOF:
            self.pos += 1
        return token

    def expect(self, token_type: TokenType) -> Token:
        """Consume a token of the expected type or raise an error."""
        token = self.current()
        if token.type != token_type:
            self.error(f"Expected {token_type.name}, got {token.type.name}")
        return self.advance()

    def match(self, *token_types: TokenType) -> bool:
        """Check if the current token matches any of the given types."""
        return self.current().type in token_types

    def consume_if(self, token_type: TokenType) -> bool:
        """Consume a token if it matches the type."""
        if self.match(token_type):
            self.advance()
            return True
        return False

    def parse(self) -> Query:
        """Parse a complete query."""
        source = self.parse_source()
        pipeline = self.parse_pipeline()
        self.expect(TokenType.EOF)
        return Query(source, pipeline)

    def parse_source(self) -> Source:
        """Parse the query source (currently only 'events')."""
        if self.match(TokenType.EVENTS):
            token = self.advance()
            return Source(token.value.lower())
        self.error("Query must start with 'events'")

    def parse_pipeline(self) -> List:
        """Parse the pipeline of operators."""
        operators = []
        while self.consume_if(TokenType.PIPE):
            op = self.parse_operator()
            if op:
                operators.append(op)
        return operators

    def parse_operator(self):
        """Parse a single pipeline operator."""
        if self.match(TokenType.WHERE):
            return self.parse_where()
        elif self.match(TokenType.PROJECT):
            return self.parse_project()
        elif self.match(TokenType.SORT):
            return self.parse_sort()
        elif self.match(TokenType.TAKE):
            return self.parse_take()
        elif self.match(TokenType.DISTINCT):
            return self.parse_distinct()
        elif self.match(TokenType.SUMMARIZE):
            return self.parse_summarize()
        else:
            self.error(f"Unknown operator: {self.current().type.name}")

    def parse_where(self) -> WhereOperator:
        """Parse a WHERE clause."""
        self.expect(TokenType.WHERE)
        condition = self.parse_expression()
        return WhereOperator(condition)

    def parse_expression(self) -> Expression:
        """Parse a boolean expression (handles AND, OR, NOT, comparisons)."""
        return self.parse_or_expression()

    def parse_or_expression(self) -> Expression:
        """Parse OR expressions (lowest precedence)."""
        left = self.parse_and_expression()
        while self.match(TokenType.OR):
            self.advance()
            right = self.parse_and_expression()
            left = LogicalOp("or", left, right)
        return left

    def parse_and_expression(self) -> Expression:
        """Parse AND expressions (medium precedence)."""
        left = self.parse_not_expression()
        while self.match(TokenType.AND):
            self.advance()
            right = self.parse_not_expression()
            left = LogicalOp("and", left, right)
        return left

    def parse_not_expression(self) -> Expression:
        """Parse NOT expressions (high precedence)."""
        if self.match(TokenType.NOT):
            self.advance()
            operand = self.parse_not_expression()
            return LogicalOp("not", operand)
        return self.parse_comparison()

    def parse_comparison(self) -> Expression:
        """Parse comparison expressions."""
        left = self.parse_primary()

        # Check for comparison operators
        if self.match(TokenType.EQ, TokenType.NE, TokenType.LT, TokenType.LE,
                      TokenType.GT, TokenType.GE):
            op_token = self.advance()
            right = self.parse_primary()
            op_map = {
                TokenType.EQ: "==",
                TokenType.NE: "!=",
                TokenType.LT: "<",
                TokenType.LE: "<=",
                TokenType.GT: ">",
                TokenType.GE: ">=",
            }
            return Comparison(left, op_map[op_token.type], right)

        # Check for string operators
        if self.match(TokenType.CONTAINS, TokenType.STARTSWITH, TokenType.ENDSWITH):
            if not isinstance(left, Field):
                self.error("String operators require a field on the left side")
            op_token = self.advance()
            if not self.match(TokenType.STRING):
                self.error(f"Expected string value after {op_token.value}")
            value_token = self.advance()
            op_map = {
                TokenType.CONTAINS: "contains",
                TokenType.STARTSWITH: "startswith",
                TokenType.ENDSWITH: "endswith",
            }
            return StringOp(left.name, op_map[op_token.type], value_token.value)

        return left

    def parse_primary(self) -> Expression:
        """Parse primary expressions (literals, fields, parenthesized expressions)."""
        # Parenthesized expression
        if self.consume_if(TokenType.LPAREN):
            expr = self.parse_expression()
            self.expect(TokenType.RPAREN)
            return expr

        # NULL literal
        if self.consume_if(TokenType.NULL):
            return Literal(None)

        # Boolean literals
        if self.consume_if(TokenType.TRUE):
            return Literal(True)

        if self.consume_if(TokenType.FALSE):
            return Literal(False)

        # String literal
        if self.match(TokenType.STRING):
            token = self.advance()
            return Literal(token.value)

        # Number literal
        if self.match(TokenType.NUMBER):
            token = self.advance()
            # Try to parse as int, fall back to float
            try:
                return Literal(int(token.value))
            except ValueError:
                return Literal(float(token.value))

        # Identifier (field or function call)
        if self.match(TokenType.IDENTIFIER):
            name_token = self.advance()
            
            # Check for function call, e.g., ago(1h)
            if self.consume_if(TokenType.LPAREN):
                args = []
                if not self.match(TokenType.RPAREN):
                    # Parse function arguments
                    args.append(self.parse_function_argument())
                    while self.consume_if(TokenType.COMMA):
                        args.append(self.parse_function_argument())
                self.expect(TokenType.RPAREN)
                return FunctionCall(name_token.value.lower(), args)
            
            # Just a field reference
            return Field(name_token.value)

        self.error(f"Unexpected token: {self.current().type.name}")

    def parse_function_argument(self):
        """Parse a function argument (used for things like ago())."""
        if self.match(TokenType.NUMBER):
            token = self.advance()
            # Check if there's a unit suffix like "h", "m", "d", "s"
            if self.match(TokenType.IDENTIFIER) and len(self.current().value) == 1:
                unit = self.advance().value
                return f"{token.value}{unit}"
            try:
                return int(token.value)
            except ValueError:
                return float(token.value)
        if self.match(TokenType.STRING):
            return self.advance().value
        self.error("Invalid function argument")

    def parse_project(self) -> ProjectOperator:
        """Parse a PROJECT clause."""
        self.expect(TokenType.PROJECT)
        columns = []
        
        columns.append(self.parse_project_column())
        while self.consume_if(TokenType.COMMA):
            columns.append(self.parse_project_column())
        
        return ProjectOperator(columns)

    def parse_project_column(self) -> ProjectColumn:
        """Parse a single project column (with optional alias)."""
        if not self.match(TokenType.IDENTIFIER):
            self.error("Expected field name in project clause")
        field = self.advance().value
        
        alias = None
        if self.consume_if(TokenType.AS):
            if not self.match(TokenType.IDENTIFIER):
                self.error("Expected identifier after 'as'")
            alias = self.advance().value
        
        return ProjectColumn(field, alias)

    def parse_sort(self) -> SortOperator:
        """Parse a SORT BY clause."""
        self.expect(TokenType.SORT)
        self.expect(TokenType.BY)
        
        fields = []
        fields.append(self.parse_sort_field())
        while self.consume_if(TokenType.COMMA):
            fields.append(self.parse_sort_field())
        
        return SortOperator(fields)

    def parse_sort_field(self) -> SortField:
        """Parse a single sort field."""
        if not self.match(TokenType.IDENTIFIER):
            self.error("Expected field name in sort clause")
        field = self.advance().value
        
        direction = "asc"
        if self.consume_if(TokenType.ASC):
            direction = "asc"
        elif self.consume_if(TokenType.DESC):
            direction = "desc"
        
        return SortField(field, direction)

    def parse_take(self) -> TakeOperator:
        """Parse a TAKE clause."""
        self.expect(TokenType.TAKE)
        if not self.match(TokenType.NUMBER):
            self.error("Expected number after 'take'")
        token = self.advance()
        try:
            count = int(token.value)
        except ValueError:
            self.error(f"Invalid number in take clause: {token.value}")
        return TakeOperator(count)

    def parse_distinct(self):
        """Parse a DISTINCT clause."""
        self.expect(TokenType.DISTINCT)
        
        fields = []
        if self.match(TokenType.IDENTIFIER):
            fields.append(self.advance().value)
            while self.consume_if(TokenType.COMMA):
                if not self.match(TokenType.IDENTIFIER):
                    self.error("Expected field name in distinct clause")
                fields.append(self.advance().value)
        else:
            self.error("distinct requires at least one field")
        
        return DistinctOperator(fields)

    def parse_summarize(self) -> SummarizeOperator:
        """Parse a SUMMARIZE clause."""
        self.expect(TokenType.SUMMARIZE)
        
        aggregations = []
        aggregations.append(self.parse_aggregation())
        while self.consume_if(TokenType.COMMA):
            aggregations.append(self.parse_aggregation())
        
        group_by = None
        if self.consume_if(TokenType.BY):
            group_by = []
            if not self.match(TokenType.IDENTIFIER):
                self.error("Expected field name after 'by'")
            group_by.append(self.advance().value)
            while self.consume_if(TokenType.COMMA):
                if not self.match(TokenType.IDENTIFIER):
                    self.error("Expected field name in group by clause")
                group_by.append(self.advance().value)
        
        return SummarizeOperator(aggregations, group_by)

    def parse_aggregation(self) -> Aggregation:
        """Parse a single aggregation function."""
        if not self.match(TokenType.IDENTIFIER):
            self.error("Expected aggregation function name")
        func_token = self.advance()
        func_name = func_token.value.lower()
        # Don't validate function name here - let validator handle it
        # if func_name not in ("count", "dcount", "sum", "avg", "min", "max"):
        #     self.error(f"Unknown aggregation function: {func_name}")
        
        self.expect(TokenType.LPAREN)
        
        field = None
        if not self.match(TokenType.RPAREN):
            if not self.match(TokenType.IDENTIFIER):
                self.error("Expected field name in aggregation function")
            field = self.advance().value
        
        self.expect(TokenType.RPAREN)
        
        alias = None
        if self.consume_if(TokenType.AS):
            if not self.match(TokenType.IDENTIFIER):
                self.error("Expected identifier after 'as'")
            alias = self.advance().value
        
        return Aggregation(func_name, field, alias)
