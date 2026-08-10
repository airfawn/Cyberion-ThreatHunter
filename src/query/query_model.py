"""Reusable query model for visual query building.

This module defines the internal representation of queries that can be built
visually (Search) or programmatically (Alerts). The model is independent of
KQL syntax and can be converted to/from KQL.

Classes:
    Condition: A single field/operator/value condition
    ConditionGroup: A group of conditions with AND/OR logic
    QueryDefinition: Top-level query containing condition groups
"""

from dataclasses import dataclass, field
from typing import List, Literal, Optional, Any, Union
from enum import Enum


class LogicalOperator(Enum):
    """Logical operators for combining conditions."""
    AND = "and"
    OR = "or"


class ComparisonOperator(Enum):
    """Comparison operators supported in query conditions."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_THAN_EQUAL = "greater_than_equal"
    LESS_THAN_EQUAL = "less_than_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    IS_EMPTY = "is_empty"
    IS_NOT_EMPTY = "is_not_empty"


class FieldType(Enum):
    """Data types for schema fields."""
    STRING = "string"
    NUMERIC = "numeric"
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"


# Field definitions: field_name -> (display_name, field_type)
FIELD_DEFINITIONS = {
    # Metadata
    "timestamp": ("Timestamp", FieldType.TIMESTAMP),
    "received_at": ("Received At", FieldType.TIMESTAMP),
    "source": ("Source", FieldType.STRING),
    
    # Agent info
    "agent_id": ("Agent ID", FieldType.STRING),
    "agent_name": ("Agent Name", FieldType.STRING),
    
    # System info
    "hostname": ("Hostname", FieldType.STRING),
    "os": ("Operating System", FieldType.STRING),
    
    # Event info
    "event_type": ("Event Type", FieldType.STRING),
    "severity": ("Severity", FieldType.NUMERIC),
    "success": ("Success", FieldType.BOOLEAN),
    
    # Process info
    "pid": ("Process ID", FieldType.NUMERIC),
    "ppid": ("Parent Process ID", FieldType.NUMERIC),
    "process_name": ("Process Name", FieldType.STRING),
    "parent_process": ("Parent Process", FieldType.STRING),
    
    # User info
    "user": ("User", FieldType.STRING),
    
    # File info
    "filepath": ("File Path", FieldType.STRING),
    "command": ("Command", FieldType.STRING),
    
    # Network/Message
    "ip_address": ("IP Address", FieldType.STRING),
    "message": ("Message", FieldType.STRING),
}


# Operators valid for each field type
VALID_OPERATORS_BY_TYPE = {
    FieldType.STRING: [
        ComparisonOperator.EQUALS,
        ComparisonOperator.NOT_EQUALS,
        ComparisonOperator.CONTAINS,
        ComparisonOperator.NOT_CONTAINS,
        ComparisonOperator.STARTS_WITH,
        ComparisonOperator.ENDS_WITH,
        ComparisonOperator.IS_EMPTY,
        ComparisonOperator.IS_NOT_EMPTY,
    ],
    FieldType.NUMERIC: [
        ComparisonOperator.EQUALS,
        ComparisonOperator.NOT_EQUALS,
        ComparisonOperator.GREATER_THAN,
        ComparisonOperator.LESS_THAN,
        ComparisonOperator.GREATER_THAN_EQUAL,
        ComparisonOperator.LESS_THAN_EQUAL,
    ],
    FieldType.BOOLEAN: [
        ComparisonOperator.EQUALS,
        ComparisonOperator.NOT_EQUALS,
    ],
    FieldType.TIMESTAMP: [
        ComparisonOperator.EQUALS,
        ComparisonOperator.NOT_EQUALS,
        ComparisonOperator.GREATER_THAN,
        ComparisonOperator.LESS_THAN,
        ComparisonOperator.GREATER_THAN_EQUAL,
        ComparisonOperator.LESS_THAN_EQUAL,
    ],
}


@dataclass
class Condition:
    """A single condition: field operator value."""
    
    field: str
    operator: ComparisonOperator
    value: Optional[Any] = None
    
    def __post_init__(self):
        """Validate the condition."""
        if self.field not in FIELD_DEFINITIONS:
            raise ValueError(f"Unknown field: {self.field}")
        
        field_type = FIELD_DEFINITIONS[self.field][1]
        if self.operator not in VALID_OPERATORS_BY_TYPE[field_type]:
            raise ValueError(
                f"Operator {self.operator.value} is not valid for "
                f"field type {field_type.value}"
            )
        
        # Empty/not empty operators don't require a value
        if self.operator not in (
            ComparisonOperator.IS_EMPTY,
            ComparisonOperator.IS_NOT_EMPTY,
        ):
            if self.value is None:
                raise ValueError(
                    f"Condition requires a value for operator {self.operator.value}"
                )
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Condition":
        """Deserialize from dictionary."""
        return cls(
            field=data["field"],
            operator=ComparisonOperator(data["operator"]),
            value=data.get("value"),
        )


@dataclass
class ConditionGroup:
    """A group of conditions combined with AND/OR logic.
    
    Can contain:
    - Conditions
    - Nested ConditionGroups
    """
    
    logical_operator: LogicalOperator = LogicalOperator.AND
    conditions: List[Condition] = field(default_factory=list)
    groups: List["ConditionGroup"] = field(default_factory=list)
    
    def add_condition(self, condition: Condition) -> None:
        """Add a condition to this group."""
        self.conditions.append(condition)
    
    def add_group(self, group: "ConditionGroup") -> None:
        """Add a nested group to this group."""
        self.groups.append(group)
    
    def remove_condition(self, index: int) -> None:
        """Remove a condition by index."""
        if 0 <= index < len(self.conditions):
            self.conditions.pop(index)
    
    def remove_group(self, index: int) -> None:
        """Remove a nested group by index."""
        if 0 <= index < len(self.groups):
            self.groups.pop(index)
    
    def is_empty(self) -> bool:
        """Check if this group has no conditions or nested groups."""
        return len(self.conditions) == 0 and len(self.groups) == 0
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "logical_operator": self.logical_operator.value,
            "conditions": [c.to_dict() for c in self.conditions],
            "groups": [g.to_dict() for g in self.groups],
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ConditionGroup":
        """Deserialize from dictionary."""
        group = cls(
            logical_operator=LogicalOperator(data["logical_operator"])
        )
        
        for cond_data in data.get("conditions", []):
            group.add_condition(Condition.from_dict(cond_data))
        
        for group_data in data.get("groups", []):
            group.add_group(cls.from_dict(group_data))
        
        return group


@dataclass
class QueryDefinition:
    """Top-level query definition using the visual builder model."""
    
    root_group: ConditionGroup = field(default_factory=ConditionGroup)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "root_group": self.root_group.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "QueryDefinition":
        """Deserialize from dictionary."""
        return cls(
            root_group=ConditionGroup.from_dict(data["root_group"])
        )
    
    @classmethod
    def empty(cls) -> "QueryDefinition":
        """Create an empty query definition."""
        return cls(root_group=ConditionGroup())
    
    def is_empty(self) -> bool:
        """Check if this query has no conditions."""
        return self.root_group.is_empty()


__all__ = [
    "Condition",
    "ConditionGroup",
    "QueryDefinition",
    "LogicalOperator",
    "ComparisonOperator",
    "FieldType",
    "FIELD_DEFINITIONS",
    "VALID_OPERATORS_BY_TYPE",
]
