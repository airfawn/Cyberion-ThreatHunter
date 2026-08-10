"""Tests for the alert management system.

Tests AlertRule, AlertStatistics, AlertManager persistence, and AlertEngine.
"""

import pytest
import tempfile
import json
from datetime import datetime

from src.alerts import (
    AlertRule,
    AlertSeverity,
    ActionType,
    ActionConfig,
    ActionStatus,
    AlertStatistics,
    AlertHistoryRecord,
)
from src.alerts.manager import AlertManager, AlertPersistenceError
from src.alerts.engine import AlertEngine, ActionExecutor
from src.query.query_model import (
    QueryDefinition,
    Condition,
    ComparisonOperator,
)
from src.database import CyberionDB


# ============================================================================
# Alert Model Tests
# ============================================================================


class TestAlertRule:
    """Test AlertRule model."""
    
    def test_create_rule(self):
        """Create an alert rule."""
        query_def = QueryDefinition.empty()
        cond = Condition(
            field="severity",
            operator=ComparisonOperator.GREATER_THAN,
            value=2
        )
        query_def.root_group.add_condition(cond)
        
        rule = AlertRule(
            name="High Severity",
            description="Alert on high severity events",
            severity=AlertSeverity.HIGH,
            query_definition=query_def,
            generated_kql="events | where severity > 2",
        )
        
        assert rule.name == "High Severity"
        assert rule.enabled is True
        assert rule.severity == AlertSeverity.HIGH
    
    def test_rule_serialization(self):
        """Serialize and deserialize rule."""
        rule = AlertRule(
            name="Test Rule",
            severity=AlertSeverity.CRITICAL,
            generated_kql="events | where severity > 3",
        )
        
        data = rule.to_dict()
        restored = AlertRule.from_dict(data)
        
        assert restored.name == rule.name
        assert restored.severity == rule.severity


class TestAlertStatistics:
    """Test AlertStatistics model."""
    
    def test_success_rate_calculation(self):
        """Calculate success rate."""
        stats = AlertStatistics(
            rule_id="test-rule",
            action_count=10,
            successful_action_count=8,
        )
        
        assert stats.success_rate == 80.0
    
    def test_success_rate_na_when_zero(self):
        """Return None when no actions attempted."""
        stats = AlertStatistics(
            rule_id="test-rule",
            action_count=0,
        )
        
        assert stats.success_rate is None


class TestActionConfig:
    """Test ActionConfig model."""
    
    def test_notification_config(self):
        """Create notification action config."""
        config = ActionConfig(
            action_type=ActionType.DESKTOP_NOTIFICATION,
            config={
                "title": "Alert!",
                "message": "High severity detected",
            }
        )
        
        assert config.action_type == ActionType.DESKTOP_NOTIFICATION
        assert config.config["title"] == "Alert!"
    
    def test_serialization(self):
        """Serialize and deserialize."""
        config = ActionConfig(
            action_type=ActionType.LOG_ALERT,
            config={"level": "error"},
        )
        
        data = config.to_dict()
        restored = ActionConfig.from_dict(data)
        
        assert restored.action_type == config.action_type


# ============================================================================
# Alert Persistence Tests
# ============================================================================


class TestAlertManager:
    """Test alert persistence manager."""
    
    @pytest.fixture
    def db(self):
        """Create temporary database for testing."""
        tmpdir = tempfile.mkdtemp()
        database = CyberionDB(tmpdir + "/test.db")
        yield database
        database.close()
    
    def test_create_rule(self, db):
        """Create and retrieve alert rule."""
        rule = AlertRule(
            name="Test Rule",
            severity=AlertSeverity.HIGH,
            generated_kql="events | where severity > 2",
        )
        
        created = db.alerts.create_rule(rule)
        assert created.id is not None
        
        retrieved = db.alerts.get_rule(created.id)
        assert retrieved is not None
        assert retrieved.name == "Test Rule"
    
    def test_update_rule(self, db):
        """Update an alert rule."""
        rule = AlertRule(
            name="Original Name",
            generated_kql="events",
        )
        created = db.alerts.create_rule(rule)
        
        created.name = "Updated Name"
        db.alerts.update_rule(created)
        
        retrieved = db.alerts.get_rule(created.id)
        assert retrieved.name == "Updated Name"
    
    def test_delete_rule(self, db):
        """Delete an alert rule."""
        rule = AlertRule(
            name="To Delete",
            generated_kql="events",
        )
        created = db.alerts.create_rule(rule)
        rule_id = created.id
        
        db.alerts.delete_rule(rule_id)
        
        retrieved = db.alerts.get_rule(rule_id)
        assert retrieved is None
    
    def test_enable_disable_rule(self, db):
        """Enable and disable rules."""
        rule = AlertRule(
            name="Test Rule",
            enabled=True,
            generated_kql="events",
        )
        created = db.alerts.create_rule(rule)
        
        # Disable it
        db.alerts.disable_rule(created.id)
        disabled = db.alerts.get_rule(created.id)
        assert disabled.enabled is False
        
        # Re-enable it
        db.alerts.enable_rule(created.id)
        enabled = db.alerts.get_rule(created.id)
        assert enabled.enabled is True
    
    def test_get_enabled_rules_only(self, db):
        """Get only enabled rules."""
        rule1 = AlertRule(name="Enabled", enabled=True, generated_kql="events")
        rule2 = AlertRule(name="Disabled", enabled=False, generated_kql="events")
        
        db.alerts.create_rule(rule1)
        db.alerts.create_rule(rule2)
        
        enabled_rules = db.alerts.get_all_rules(enabled_only=True)
        assert len(enabled_rules) == 1
        assert enabled_rules[0].name == "Enabled"
    
    def test_trigger_count_increment(self, db):
        """Increment trigger count."""
        rule = AlertRule(name="Test", generated_kql="events")
        created = db.alerts.create_rule(rule)
        
        db.alerts.increment_trigger_count(created.id)
        db.alerts.increment_trigger_count(created.id)
        
        stats = db.alerts.get_statistics(created.id)
        assert stats.trigger_count == 2
    
    def test_action_count_increment_success(self, db):
        """Increment successful action count."""
        rule = AlertRule(name="Test", generated_kql="events")
        created = db.alerts.create_rule(rule)
        
        db.alerts.increment_action_count(created.id, success=True)
        db.alerts.increment_action_count(created.id, success=True)
        db.alerts.increment_action_count(created.id, success=False)
        
        stats = db.alerts.get_statistics(created.id)
        assert stats.action_count == 3
        assert stats.successful_action_count == 2
        assert stats.failed_action_count == 1
    
    def test_add_history_record(self, db):
        """Add and retrieve history record."""
        rule = AlertRule(name="Test", generated_kql="events")
        created = db.alerts.create_rule(rule)
        
        record = AlertHistoryRecord(
            rule_id=created.id,
            action_type=ActionType.LOG_ALERT,
            action_status=ActionStatus.SUCCESS,
        )
        
        added = db.alerts.add_history_record(record)
        assert added.id is not None
        
        history = db.alerts.get_rule_history(created.id)
        assert len(history) == 1
        assert history[0].action_type == ActionType.LOG_ALERT


# ============================================================================
# Action Executor Tests
# ============================================================================


class TestActionExecutor:
    """Test action execution."""
    
    def test_log_alert_execution(self):
        """Execute log alert action."""
        executor = ActionExecutor()
        rule = AlertRule(
            name="Test",
            action=ActionConfig(ActionType.LOG_ALERT),
            generated_kql="events",
        )
        
        result = executor.execute(rule)
        assert result is True
    
    def test_notification_execution(self):
        """Execute notification action."""
        executor = ActionExecutor()
        rule = AlertRule(
            name="Test",
            action=ActionConfig(
                ActionType.DESKTOP_NOTIFICATION,
                config={"title": "Test", "message": "test"}
            ),
            generated_kql="events",
        )
        
        result = executor.execute(rule)
        assert result is True
    
    def test_custom_executor(self):
        """Register custom executor."""
        def custom_log(rule, event_id):
            # Custom implementation
            return True
        
        executor = ActionExecutor(
            custom_executors={
                ActionType.LOG_ALERT: custom_log
            }
        )
        
        rule = AlertRule(
            name="Test",
            action=ActionConfig(ActionType.LOG_ALERT),
            generated_kql="events",
        )
        
        result = executor.execute(rule)
        assert result is True


# ============================================================================
# Integration Tests
# ============================================================================


class TestAlertIntegration:
    """Integration tests for alert system."""
    
    @pytest.fixture
    def db(self):
        """Create temporary database for testing."""
        tmpdir = tempfile.mkdtemp()
        database = CyberionDB(tmpdir + "/test.db")
        yield database
        database.close()
    
    def test_full_rule_lifecycle(self, db):
        """Test creating, enabling, triggering, and disabling a rule."""
        # Create rule
        rule = AlertRule(
            name="High Severity Detection",
            description="Alert on events with severity > 2",
            severity=AlertSeverity.HIGH,
            generated_kql="events | where severity > 2",
        )
        created = db.alerts.create_rule(rule)
        
        # Verify it's enabled by default
        retrieved = db.alerts.get_rule(created.id)
        assert retrieved.enabled is True
        
        # Simulate triggers
        db.alerts.increment_trigger_count(created.id)
        db.alerts.increment_action_count(created.id, success=True)
        
        # Check statistics
        stats = db.alerts.get_statistics(created.id)
        assert stats.trigger_count == 1
        assert stats.action_count == 1
        assert stats.successful_action_count == 1
        assert stats.success_rate == 100.0
        
        # Disable rule
        db.alerts.disable_rule(created.id)
        disabled = db.alerts.get_rule(created.id)
        assert disabled.enabled is False
        
        # Delete rule
        db.alerts.delete_rule(created.id)
        deleted = db.alerts.get_rule(created.id)
        assert deleted is None
    
    def test_history_tracking(self, db):
        """Test alert history tracking."""
        rule = AlertRule(
            name="Test",
            generated_kql="events",
        )
        created = db.alerts.create_rule(rule)
        
        # Simulate multiple triggers
        for i in range(5):
            record = AlertHistoryRecord(
                rule_id=created.id,
                action_type=ActionType.LOG_ALERT,
                action_status=ActionStatus.SUCCESS if i < 4 else ActionStatus.FAILURE,
            )
            db.alerts.add_history_record(record)
        
        # Retrieve history
        history = db.alerts.get_rule_history(created.id)
        assert len(history) == 5
        
        # Last one should be failure
        assert history[0].action_status == ActionStatus.FAILURE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
