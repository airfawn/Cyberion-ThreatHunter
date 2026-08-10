"""Token definitions and lexer for Cyberion Query Language.

Tokenizes a Cyberion query string into a stream of tokens for parsing.

Example:
    events | where severity >= 3 | take 100

Tokens: EVENTS | PIPE WHERE FIELD OP_GTE NUMBER PIPE TAKE NUMBER
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional


class TokenType(Enum):
    """Token types in the Cyberion query language."""

    # Structural
    EVENTS = auto()
    PIPE = auto()
    COMMA = auto()
    LPAREN = auto()
    RPAREN = auto()

    # Keywords / Operators
    WHERE = auto()
    PROJECT = auto()
    SORT = auto()
    BY = auto()
    TAKE = auto()
    DISTINCT = auto()
    SUMMARIZE = auto()

    # Directions
    ASC = auto()
    DESC = auto()

    # Logical operators
    AND = auto()
    OR = auto()
    NOT = auto()

    # Comparison operators
    EQ = auto()  # ==
    NE = auto()  # !=
    LT = auto()  # <
    LE = auto()  # <=
    GT = auto()  # >
    GE = auto()  # >=

    # String operators
    CONTAINS = auto()
    STARTSWITH = auto()
    ENDSWITH = auto()

    # Literals
    IDENTIFIER = auto()
    STRING = auto()
    NUMBER = auto()
    NULL = auto()
    TRUE = auto()
    FALSE = auto()

    # Special
    AS = auto()
    EOF = auto()


@dataclass
class Token:
    """A single lexical token."""

    type: TokenType
    value: str
    line: int = 1
    column: int = 1

    def __repr__(self):
        if self.value:
            return f"Token({self.type.name}, {self.value!r})"
        return f"Token({self.type.name})"


class Lexer:
    """Tokenizes a Cyberion query string."""

    KEYWORDS = {
        "events": TokenType.EVENTS,
        "where": TokenType.WHERE,
        "project": TokenType.PROJECT,
        "sort": TokenType.SORT,
        "by": TokenType.BY,
        "take": TokenType.TAKE,
        "distinct": TokenType.DISTINCT,
        "summarize": TokenType.SUMMARIZE,
        "and": TokenType.AND,
        "or": TokenType.OR,
        "not": TokenType.NOT,
        "asc": TokenType.ASC,
        "desc": TokenType.DESC,
        "null": TokenType.NULL,
        "true": TokenType.TRUE,
        "false": TokenType.FALSE,
        "as": TokenType.AS,
        "contains": TokenType.CONTAINS,
        "startswith": TokenType.STARTSWITH,
        "endswith": TokenType.ENDSWITH,
    }

    def __init__(self, query: str):
        self.query = query
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []

    def error(self, msg: str) -> None:
        """Raise a lexer error with position information."""
        raise SyntaxError(f"Lexer error at line {self.line}, column {self.column}: {msg}")

    def peek(self, offset: int = 0) -> Optional[str]:
        """Peek at a character without consuming it."""
        pos = self.pos + offset
        if pos < len(self.query):
            return self.query[pos]
        return None

    def advance(self) -> Optional[str]:
        """Consume and return the next character."""
        if self.pos < len(self.query):
            ch = self.query[self.pos]
            self.pos += 1
            if ch == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            return ch
        return None

    def skip_whitespace(self) -> None:
        """Skip whitespace and comments."""
        while self.peek() and self.peek() in " \t\n\r":
            self.advance()

    def read_string(self, quote_char: str) -> str:
        """Read a quoted string literal."""
        result = ""
        self.advance()  # consume opening quote
        while True:
            ch = self.peek()
            if ch is None:
                self.error(f"Unterminated string literal")
            if ch == quote_char:
                self.advance()
                break
            if ch == "\\":
                self.advance()
                next_ch = self.advance()
                if next_ch is None:
                    self.error("Unterminated escape sequence")
                # Handle common escapes
                escape_map = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}
                result += escape_map.get(next_ch, next_ch)
            else:
                result += self.advance()
        return result

    def read_number(self) -> str:
        """Read a numeric literal (integer or float)."""
        result = ""
        has_dot = False
        while self.peek() and (self.peek().isdigit() or self.peek() == "."):
            if self.peek() == ".":
                if has_dot:
                    break
                has_dot = True
            result += self.advance()
        return result

    def read_identifier(self) -> str:
        """Read an identifier or keyword."""
        result = ""
        while self.peek() and (self.peek().isalnum() or self.peek() in "_"):
            result += self.advance()
        return result

    def tokenize(self) -> List[Token]:
        """Tokenize the entire query string."""
        while self.pos < len(self.query):
            self.skip_whitespace()

            if self.pos >= len(self.query):
                break

            start_line = self.line
            start_column = self.column
            ch = self.peek()

            # Single-character tokens
            if ch == "|":
                self.advance()
                self.tokens.append(Token(TokenType.PIPE, "|", start_line, start_column))
            elif ch == ",":
                self.advance()
                self.tokens.append(Token(TokenType.COMMA, ",", start_line, start_column))
            elif ch == "(":
                self.advance()
                self.tokens.append(Token(TokenType.LPAREN, "(", start_line, start_column))
            elif ch == ")":
                self.advance()
                self.tokens.append(Token(TokenType.RPAREN, ")", start_line, start_column))

            # Operators
            elif ch == "=":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    self.tokens.append(Token(TokenType.EQ, "==", start_line, start_column))
                else:
                    self.error("Unexpected '='. Did you mean '=='?")
            elif ch == "!":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    self.tokens.append(Token(TokenType.NE, "!=", start_line, start_column))
                else:
                    self.error("Unexpected '!'. Did you mean '!='?")
            elif ch == "<":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    self.tokens.append(Token(TokenType.LE, "<=", start_line, start_column))
                else:
                    self.tokens.append(Token(TokenType.LT, "<", start_line, start_column))
            elif ch == ">":
                self.advance()
                if self.peek() == "=":
                    self.advance()
                    self.tokens.append(Token(TokenType.GE, ">=", start_line, start_column))
                else:
                    self.tokens.append(Token(TokenType.GT, ">", start_line, start_column))

            # String literals
            elif ch in ('"', "'"):
                string_val = self.read_string(ch)
                self.tokens.append(Token(TokenType.STRING, string_val, start_line, start_column))

            # Numbers
            elif ch.isdigit():
                num_val = self.read_number()
                self.tokens.append(Token(TokenType.NUMBER, num_val, start_line, start_column))

            # Identifiers and keywords
            elif ch.isalpha() or ch == "_":
                ident = self.read_identifier()
                token_type = self.KEYWORDS.get(ident.lower(), TokenType.IDENTIFIER)
                self.tokens.append(Token(token_type, ident, start_line, start_column))

            else:
                self.error(f"Unexpected character: {ch!r}")

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return self.tokens
