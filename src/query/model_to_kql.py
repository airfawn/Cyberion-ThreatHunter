"""Convert QueryDefinition model to KQL (Cyberion Query Language).

This module takes the visual query model and generates equivalent KQL,
which is then fed to the existing lexer/parser/validator/compiler pipeline.

The generated KQL should be clean, readable, and match what an advanced
user might hand-type.
"""

from typing import List, Tuple
from .query_model import (
    Condition,
    ConditionGroup,
    QueryDefinition,
    ComparisonOperator,
    FieldType,
    FIELD_DEFINITIONS,
)


class QueryModelError(Exception):
    """Raised when query model conversion fails."""
    pass


class QueryModelToKQL:
    """Converts QueryDefinition to KQL string."""
    
    # Map ComparisonOperator to KQL operators
    OPERATOR_MAP = {
        ComparisonOperator.EQUALS: "==",
        ComparisonOperator.NOT_EQUALS: "!=",
        ComparisonOperator.GREATER_THAN: ">",
        ComparisonOperator.LESS_THAN: "<",
        ComparisonOperator.GREATER_THAN_EQUAL: ">=",
        ComparisonOperator.LESS_THAN_EQUAL: "<=",
        ComparisonOperator.CONTAINS: "contains",
        ComparisonOperator.NOT_CONTAINS: "!contains",
        ComparisonOperator.STARTS_WITH: "startswith",
        ComparisonOperator.ENDS_WITH: "endswith",
        # The query language does not yet implement regex; map to contains
        # for preview compatibility while local detection evaluation uses
        # native regex support.
        ComparisonOperator.REGEX: "contains",
        ComparisonOperator.NOT_REGEX: "!contains",
        ComparisonOperator.IS_EMPTY: "isnull",
        ComparisonOperator.IS_NOT_EMPTY: "!isnull",
    }
    
    def __init__(self):
        pass
    
    def convert(self, query_def: QueryDefinition) -> str:
        """Convert QueryDefinition to KQL string.
        
        Args:
            query_def: The query definition model
            
        Returns:
            KQL string like "events | where ..."
            
        Raises:
            QueryModelError: If conversion fails
        """
        if query_def.is_empty():
            # Empty query just returns events with no filters
            return "events"
        
        try:
            where_clause = self._convert_group(query_def.root_group)
            if not where_clause or where_clause.strip() == "":
                return "events"
            
            return f"events | where {where_clause}"
        except Exception as e:
            raise QueryModelError(f"Failed to convert query model: {e}") from e
    
    def _convert_group(self, group: ConditionGroup, indent: int = 0) -> str:
        """Convert a ConditionGroup to KQL expression.
        
        Args:
            group: The condition group
            indent: Number of spaces to indent (for readability)
            
        Returns:
            KQL expression string
        """
        if group.is_empty():
            return ""
        
        parts: List[str] = []
        
        # Convert individual conditions
        for condition in group.conditions:
            parts.append(self._convert_condition(condition))
        
        # Convert nested groups
        for nested_group in group.groups:
            nested_expr = self._convert_group(nested_group, indent + 4)
            if nested_expr:
                # Wrap nested groups in parentheses for clarity
                parts.append(f"({nested_expr})")
        
        if not parts:
            return ""
        
        # Join with the logical operator
        logical_op = " " + group.logical_operator.value + " "
        return logical_op.join(parts)
    
    def _convert_condition(self, condition: Condition) -> str:
        """Convert a single Condition to KQL.
        
        Args:
            condition: The condition
            
        Returns:
            KQL expression like 'process_name == "cmd.exe"'
        """
        field = condition.field
        op = condition.operator
        value = condition.value
        
        # Get the KQL operator
        kql_op = self.OPERATOR_MAP.get(op)
        if kql_op is None:
            raise QueryModelError(f"Unknown operator: {op}")
        
        # Handle empty/not-empty operators (no value needed)
        if op in (ComparisonOperator.IS_EMPTY, ComparisonOperator.IS_NOT_EMPTY):
            return f"{field} {kql_op}"
        
        # Format the value based on field type
        field_info = FIELD_DEFINITIONS.get(field)
        if not field_info:
            raise QueryModelError(f"Unknown field: {field}")
        
        field_type = field_info[1]
        formatted_value = self._format_value(value, field_type)
        
        return f'{field} {kql_op} {formatted_value}'
    
    def _format_value(self, value: any, field_type: FieldType) -> str:
        """Format a value for KQL based on its type.
        
        Args:
            value: The value to format
            field_type: The field type
            
        Returns:
            Formatted KQL value
        """
        if value is None:
            return "null"
        
        if field_type == FieldType.BOOLEAN:
            # Convert Python bool to KQL true/false
            if isinstance(value, bool):
                return "true" if value else "false"
            elif isinstance(value, str):
                val_lower = value.lower()
                if val_lower in ("true", "1", "yes"):
                    return "true"
                elif val_lower in ("false", "0", "no"):
                    return "false"
                else:
                    return f'"{value}"'
            else:
                return str(value).lower()
        
        elif field_type == FieldType.NUMERIC:
            # Numeric values are not quoted
            try:
                if isinstance(value, (int, float)):
                    return str(value)
                else:
                    # Try to parse as number
                    float(str(value))
                    return str(value)
            except (ValueError, TypeError):
                # If not numeric, quote as string
                return f'"{value}"'
        
        else:  # STRING or TIMESTAMP
            # String values are quoted
            # Escape quotes in the value
            escaped = str(value).replace('"', '\\"')
            return f'"{escaped}"'


def query_definition_to_kql(query_def: QueryDefinition) -> str:
    """Convert a QueryDefinition to KQL.
    
    Convenience function for one-off conversions.
    
    Args:
        query_def: The query definition model
        
    Returns:
        KQL string
        
    Raises:
        QueryModelError: If conversion fails
    """
    converter = QueryModelToKQL()
    return converter.convert(query_def)


__all__ = [
    "QueryModelToKQL",
    "query_definition_to_kql",
    "QueryModelError",
]
