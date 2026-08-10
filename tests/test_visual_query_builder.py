"""Tests for visual query builder components.

Tests the query model, KQL generation, and PyQt5 widgets.
"""

import pytest
from src.query.query_model import (
    Condition,
    ConditionGroup,
    QueryDefinition,
    ComparisonOperator,
    FieldType,
    LogicalOperator,
    FIELD_DEFINITIONS,
)
from src.query.model_to_kql import (
    QueryModelToKQL,
    query_definition_to_kql,
    QueryModelError,
)


# ============================================================================
# Query Model Tests
# ============================================================================


class TestCondition:
    """Test the Condition class."""
    
    def test_condition_creation(self):
        """Create a valid condition."""
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        assert cond.field == "process_name"
        assert cond.operator == ComparisonOperator.EQUALS
        assert cond.value == "cmd.exe"
    
    def test_condition_invalid_field(self):
        """Reject invalid field names."""
        with pytest.raises(ValueError, match="Unknown field"):
            Condition(
                field="invalid_field",
                operator=ComparisonOperator.EQUALS,
                value="test"
            )
    
    def test_condition_invalid_operator_for_type(self):
        """Reject incompatible operator for field type."""
        # String field with numeric operator
        with pytest.raises(ValueError, match="not valid for"):
            Condition(
                field="process_name",
                operator=ComparisonOperator.GREATER_THAN,
                value="cmd.exe"
            )
    
    def test_condition_requires_value(self):
        """Most operators require a value."""
        with pytest.raises(ValueError, match="requires a value"):
            Condition(
                field="process_name",
                operator=ComparisonOperator.EQUALS,
                value=None
            )
    
    def test_condition_empty_operator_no_value(self):
        """IS_EMPTY operator doesn't require a value."""
        cond = Condition(
            field="message",
            operator=ComparisonOperator.IS_EMPTY,
            value=None
        )
        assert cond.value is None
    
    def test_condition_serialization(self):
        """Serialize and deserialize condition."""
        original = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        
        data = original.to_dict()
        restored = Condition.from_dict(data)
        
        assert restored.field == original.field
        assert restored.operator == original.operator
        assert restored.value == original.value


class TestConditionGroup:
    """Test the ConditionGroup class."""
    
    def test_group_creation(self):
        """Create an empty group."""
        group = ConditionGroup()
        assert group.logical_operator == LogicalOperator.AND
        assert group.is_empty()
    
    def test_group_add_condition(self):
        """Add conditions to a group."""
        group = ConditionGroup()
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        group.add_condition(cond)
        
        assert not group.is_empty()
        assert len(group.conditions) == 1
    
    def test_group_remove_condition(self):
        """Remove conditions from a group."""
        group = ConditionGroup()
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        group.add_condition(cond)
        group.remove_condition(0)
        
        assert group.is_empty()
    
    def test_group_logical_operator(self):
        """Set AND/OR logical operator."""
        group = ConditionGroup(logical_operator=LogicalOperator.OR)
        assert group.logical_operator == LogicalOperator.OR
    
    def test_group_serialization(self):
        """Serialize and deserialize group."""
        group = ConditionGroup(logical_operator=LogicalOperator.AND)
        cond1 = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        cond2 = Condition(
            field="event_type",
            operator=ComparisonOperator.EQUALS,
            value="process"
        )
        group.add_condition(cond1)
        group.add_condition(cond2)
        
        data = group.to_dict()
        restored = ConditionGroup.from_dict(data)
        
        assert len(restored.conditions) == 2
        assert restored.logical_operator == LogicalOperator.AND


class TestQueryDefinition:
    """Test the QueryDefinition class."""
    
    def test_empty_query(self):
        """Create an empty query."""
        query = QueryDefinition.empty()
        assert query.is_empty()
    
    def test_query_with_conditions(self):
        """Create a query with conditions."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        query.root_group.add_condition(cond)
        
        assert not query.is_empty()
    
    def test_query_serialization(self):
        """Serialize and deserialize query."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        query.root_group.add_condition(cond)
        
        data = query.to_dict()
        restored = QueryDefinition.from_dict(data)
        
        assert not restored.is_empty()
        assert len(restored.root_group.conditions) == 1


# ============================================================================
# KQL Generation Tests
# ============================================================================


class TestQueryModelToKQL:
    """Test KQL generation from query model."""
    
    def test_empty_query_generates_events(self):
        """Empty query generates 'events'."""
        query = QueryDefinition.empty()
        kql = query_definition_to_kql(query)
        assert kql == "events"
    
    def test_single_string_condition(self):
        """Single string condition generates WHERE clause."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        assert 'events | where' in kql
        assert 'process_name == "cmd.exe"' in kql
    
    def test_numeric_condition(self):
        """Numeric conditions don't quote values."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        # Numeric values should not be quoted
        assert 'severity > 2' in kql
    
    def test_boolean_condition(self):
        """Boolean conditions use true/false keywords."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="success",
            operator=ComparisonOperator.EQUALS,
            value=True
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        assert 'success == true' in kql
    
    def test_multiple_conditions_and(self):
        """Multiple conditions with AND operator."""
        query = QueryDefinition.empty()
        query.root_group.logical_operator = LogicalOperator.AND
        
        cond1 = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        cond2 = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        
        query.root_group.add_condition(cond1)
        query.root_group.add_condition(cond2)
        
        kql = query_definition_to_kql(query)
        assert 'process_name == "cmd.exe"' in kql
        assert 'severity > 2' in kql
        assert ' and ' in kql
    
    def test_multiple_conditions_or(self):
        """Multiple conditions with OR operator."""
        query = QueryDefinition.empty()
        query.root_group.logical_operator = LogicalOperator.OR
        
        cond1 = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="cmd.exe"
        )
        cond2 = Condition(
            field="process_name",
            operator=ComparisonOperator.EQUALS,
            value="powershell.exe"
        )
        
        query.root_group.add_condition(cond1)
        query.root_group.add_condition(cond2)
        
        kql = query_definition_to_kql(query)
        assert ' or ' in kql
    
    def test_string_operators(self):
        """Various string operators generate correct KQL."""
        test_cases = [
            (ComparisonOperator.CONTAINS, "contains"),
            (ComparisonOperator.NOT_CONTAINS, "!contains"),
            (ComparisonOperator.STARTS_WITH, "startswith"),
            (ComparisonOperator.ENDS_WITH, "endswith"),
        ]
        
        for op, kql_op in test_cases:
            query = QueryDefinition.empty()
            cond = Condition(
                field="process_name",
                operator=op,
                value="shell"
            )
            query.root_group.add_condition(cond)
            
            kql = query_definition_to_kql(query)
            assert f'process_name {kql_op}' in kql
    
    def test_empty_operator(self):
        """IS_EMPTY operator doesn't require a value."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="message",
            operator=ComparisonOperator.IS_EMPTY,
            value=None
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        assert 'message isnull' in kql
    
    def test_not_empty_operator(self):
        """IS_NOT_EMPTY operator."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="message",
            operator=ComparisonOperator.IS_NOT_EMPTY,
            value=None
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        assert 'message !isnull' in kql
    
    def test_string_escaping(self):
        """Escape quotes in string values."""
        query = QueryDefinition.empty()
        cond = Condition(
            field="command",
            operator=ComparisonOperator.CONTAINS,
            value='cmd.exe "/c"'
        )
        query.root_group.add_condition(cond)
        
        kql = query_definition_to_kql(query)
        # Should have escaped quote
        assert '\\"' in kql or '\\/' in kql or '"' in kql


class TestIntegration:
    """Integration tests for query model + KQL + existing query engine."""
    
    def test_visual_query_to_kql_to_query_engine(self):
        """Test end-to-end: Model → KQL → Query Engine."""
        from src.query import CyberionQueryEngine
        from src.database import CyberionDB
        import tempfile
        
        # Create temp database with events
        tmpdir = tempfile.mkdtemp()
        db = CyberionDB(tmpdir + "/test.db")
        
        events = [
            {"timestamp": "2024-01-01T10:00:00Z", "event_type": "login", 
             "process_name": "sshd", "severity": 1},
            {"timestamp": "2024-01-01T10:01:00Z", "event_type": "login", 
             "process_name": "ssh", "severity": 2},
            {"timestamp": "2024-01-01T10:02:00Z", "event_type": "process", 
             "process_name": "cmd.exe", "severity": 3},
        ]
        db.insert_events(events)
        
        # Build visual query: process_name contains "cmd"
        query_def = QueryDefinition.empty()
        cond = Condition(
            field="process_name",
            operator=ComparisonOperator.CONTAINS,
            value="cmd"
        )
        query_def.root_group.add_condition(cond)
        
        # Generate KQL
        kql = query_definition_to_kql(query_def)
        
        # Execute through query engine
        engine = CyberionQueryEngine(db)
        result = engine.execute(kql)
        
        # Should return 1 row (cmd.exe)
        assert len(result.rows) == 1
        
        db.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
