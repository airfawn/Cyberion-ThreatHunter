"""Tests for Sigma rule conversion/import into Cyberion local rules."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from src.database import CyberionDB
from src.detections.engine import DetectionEngine
from src.sigma.converter import SigmaRuleConverter
from src.sigma.importer import SigmaRuleImporter
from src.sigma.models import ConversionStatus


def _db(tmp_path: Path) -> CyberionDB:
    return CyberionDB(db_path=tmp_path / "sigma_test.db")


def _convert(rule_dict: dict):
    converter = SigmaRuleConverter()
    return converter.convert_sigma_dict(rule_dict)


def test_basic_contains_startswith_endswith_regex_conversion():
    sigma = {
        "title": "Suspicious PowerShell Encoded Command",
        "id": "sigma-1",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": "powershell.exe",
                "CommandLine|contains": "-enc",
                "User|startswith": "adm",
                "CommandLine|re": "encoded|enc",
            },
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
    }

    result = _convert(sigma)
    assert result.status in {ConversionStatus.SUPPORTED, ConversionStatus.SUPPORTED_WITH_WARNINGS}
    assert result.local_rule is not None
    assert result.local_rule.name == sigma["title"]


def test_value_list_and_boolean_logic_semantics(tmp_path: Path):
    sigma = {
        "title": "Cmd Or PowerShell Not System",
        "id": "sigma-2",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": ["cmd.exe", "powershell.exe"]},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        },
        "level": "medium",
    }

    result = _convert(sigma)
    assert result.status in {ConversionStatus.SUPPORTED, ConversionStatus.SUPPORTED_WITH_WARNINGS}

    db = _db(tmp_path)
    rule = db.alerts.create_rule(result.local_rule)
    engine = DetectionEngine(db)

    event_match = {
        "process_name": "powershell.exe",
        "user": "admin",
        "event_type": "process_start",
        "os": "windows",
    }
    event_filtered = {
        "process_name": "powershell.exe",
        "user": "SYSTEM",
        "event_type": "process_start",
        "os": "windows",
    }
    assert engine._rule_matches(rule, event_match) is True
    assert engine._rule_matches(rule, event_filtered) is False


def test_condition_one_of_and_all_of_selection_wildcards():
    sigma = {
        "title": "Wildcard Condition",
        "id": "sigma-3",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection_cmd": {"Image|endswith": "cmd.exe"},
            "selection_ps": {"Image|endswith": "powershell.exe"},
            "selection_user": {"User": "admin"},
            "condition": "1 of selection_* and all of selection_user",
        },
        "level": "low",
    }

    result = _convert(sigma)
    assert result.status in {ConversionStatus.SUPPORTED, ConversionStatus.SUPPORTED_WITH_WARNINGS}
    assert result.local_rule is not None


def test_metadata_preserved_in_action_config():
    sigma = {
        "title": "Metadata Rule",
        "id": "sigma-meta-1",
        "author": "Analyst",
        "references": ["https://example.test/rule"],
        "tags": ["attack.t1110"],
        "description": "desc",
        "logsource": {"product": "windows", "category": "authentication"},
        "detection": {
            "selection": {"Message|contains": "failed"},
            "condition": "selection",
        },
        "level": "high",
    }

    result = _convert(sigma)
    assert result.local_rule is not None
    sigma_meta = result.local_rule.action.config.get("sigma_metadata", {})
    assert sigma_meta.get("sigma_id") == "sigma-meta-1"
    assert sigma_meta.get("sigma_author") == "Analyst"
    assert "attack.t1110" in sigma_meta.get("sigma_tags", [])


def test_unsupported_modifier_is_explicitly_rejected():
    sigma = {
        "title": "Unsupported Modifier",
        "id": "sigma-unsupported-1",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"SourceIp|cidr": "10.0.0.0/24"},
            "condition": "selection",
        },
        "level": "medium",
    }

    result = _convert(sigma)
    assert result.status == ConversionStatus.UNSUPPORTED
    assert any("Unsupported Sigma modifier" in err for err in result.errors)


def test_duplicate_sigma_id_handling_with_update(tmp_path: Path):
    db = _db(tmp_path)
    importer = SigmaRuleImporter(db.alerts)

    sigma_doc_v1 = """
    title: Duplicate Rule
    id: sigma-dup-1
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: powershell.exe
      condition: selection
    level: medium
    """

    sigma_doc_v2 = """
    title: Duplicate Rule Updated
    id: sigma-dup-1
    modified: 2026-08-18
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: cmd.exe
      condition: selection
    level: high
    """

    p1 = tmp_path / "dup1.yml"
    p1.write_text(sigma_doc_v1, encoding="utf-8")
    first = importer.import_file(str(p1), update_existing=False)
    assert first[0].local_rule_id

    # Re-import without update -> warning and same mapping.
    second = importer.import_file(str(p1), update_existing=False)
    assert second[0].local_rule_id == first[0].local_rule_id
    assert second[0].warnings

    # Import updated content with update_existing=True.
    p2 = tmp_path / "dup2.yml"
    p2.write_text(sigma_doc_v2, encoding="utf-8")
    third = importer.import_file(str(p2), update_existing=True)
    assert third[0].local_rule_id == first[0].local_rule_id


def test_existing_local_rules_regression_not_affected(tmp_path: Path):
    db = _db(tmp_path)

    # Existing local rule flow still works.
    from src.alerts import AlertRule, AlertSeverity
    from src.query.query_model import QueryDefinition, ConditionGroup, Condition, ComparisonOperator

    root = ConditionGroup()
    root.add_condition(Condition("process_name", ComparisonOperator.EQUALS, "powershell.exe"))
    local_rule = AlertRule(
        name="Existing Local Rule",
        severity=AlertSeverity.HIGH,
        query_definition=QueryDefinition(root_group=root),
        generated_kql='events | where process_name == "powershell.exe"',
    )

    created = db.alerts.create_rule(local_rule)
    assert created.id
    fetched = db.alerts.get_rule(created.id)
    assert fetched is not None
    assert fetched.name == "Existing Local Rule"
