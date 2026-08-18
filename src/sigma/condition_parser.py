"""Parse Sigma detection condition strings into expression trees."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from .models import DetectionExpr


_TOKEN_RE = re.compile(r"\(|\)|\bnot\b|\band\b|\bor\b|[^\s()]+", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"^(?:(1)\s+of|(all)\s+of)\s+([A-Za-z0-9_*?-]+)$", re.IGNORECASE)


class ConditionSyntaxError(ValueError):
    pass


class SigmaConditionParser:
    def parse(self, condition: str, selection_names: list[str]) -> DetectionExpr:
        if not condition or not condition.strip():
            raise ConditionSyntaxError("Empty Sigma condition")

        tokens = self._tokenize(condition)
        tokens = self._expand_wildcards(tokens, selection_names)
        stream = _TokenStream(tokens)
        expr = self._parse_or(stream)
        if stream.has_more():
            raise ConditionSyntaxError(f"Unexpected token: {stream.peek()}")
        return expr

    def _tokenize(self, condition: str) -> list[str]:
        tokens = [tok.strip() for tok in _TOKEN_RE.findall(condition) if tok.strip()]
        if not tokens:
            raise ConditionSyntaxError("Condition tokenization failed")
        return tokens

    def _expand_wildcards(self, tokens: list[str], selection_names: list[str]) -> list[str]:
        expanded: list[str] = []
        idx = 0
        while idx < len(tokens):
            # Try 3-token pattern: "1" "of" "selection*"
            if idx + 2 < len(tokens):
                candidate = f"{tokens[idx]} {tokens[idx+1]} {tokens[idx+2]}"
                wildcard = self._expand_wildcard_expression(candidate, selection_names)
                if wildcard is not None:
                    expanded.extend(wildcard)
                    idx += 3
                    continue

            # Try 2-token pattern: "all" "of_selection*" isn't valid, keep token.
            expanded.append(tokens[idx])
            idx += 1

        return expanded

    def _expand_wildcard_expression(self, expr: str, selection_names: list[str]) -> list[str] | None:
        m = _WILDCARD_RE.match(expr)
        if not m:
            return None
        one_of, all_of, pattern = m.groups()

        regex = re.compile("^" + re.escape(pattern).replace("\\*", ".*") + "$")
        matches = sorted([name for name in selection_names if regex.match(name)])
        if not matches:
            raise ConditionSyntaxError(f"No selections match wildcard condition: {expr}")

        joiner = "or" if one_of else "and"
        parts: list[str] = ["("]
        for i, name in enumerate(matches):
            if i > 0:
                parts.append(joiner)
            parts.append(name)
        parts.append(")")
        return parts

    def _parse_or(self, stream: "_TokenStream") -> DetectionExpr:
        node = self._parse_and(stream)
        children = [node]
        while stream.match("or"):
            children.append(self._parse_and(stream))
        if len(children) == 1:
            return node
        return DetectionExpr(kind="or", children=children)

    def _parse_and(self, stream: "_TokenStream") -> DetectionExpr:
        node = self._parse_unary(stream)
        children = [node]
        while stream.match("and"):
            children.append(self._parse_unary(stream))
        if len(children) == 1:
            return node
        return DetectionExpr(kind="and", children=children)

    def _parse_unary(self, stream: "_TokenStream") -> DetectionExpr:
        if stream.match("not"):
            return DetectionExpr(kind="not", children=[self._parse_unary(stream)])
        return self._parse_primary(stream)

    def _parse_primary(self, stream: "_TokenStream") -> DetectionExpr:
        if stream.match("("):
            expr = self._parse_or(stream)
            if not stream.match(")"):
                raise ConditionSyntaxError("Missing closing parenthesis")
            return expr

        token = stream.next_token()
        if token is None:
            raise ConditionSyntaxError("Unexpected end of condition")
        if token.lower() in {"and", "or", "not", ")"}:
            raise ConditionSyntaxError(f"Unexpected token: {token}")

        return DetectionExpr(kind="atom", atom=token)


@dataclass
class _TokenStream:
    tokens: List[str]
    index: int = 0

    def has_more(self) -> bool:
        return self.index < len(self.tokens)

    def peek(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def next_token(self) -> str | None:
        token = self.peek()
        if token is not None:
            self.index += 1
        return token

    def match(self, expected: str) -> bool:
        token = self.peek()
        if token is None:
            return False
        if token.lower() != expected.lower():
            return False
        self.index += 1
        return True
