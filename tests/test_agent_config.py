import os
import tempfile
from pathlib import Path

from Agent.connector import load_agent_config, resolve_agent_target


def test_load_agent_config_from_yaml(tmp_path: Path):
    config_path = tmp_path / "agent.yaml"
    config_path.write_text(
        """
server:
  host: 10.0.0.5
  port: 9999
collector:
  interval: 15
  sources:
    - syslog
    - auth
""".strip(),
        encoding="utf-8",
    )

    config = load_agent_config(config_path)

    assert config["server"]["host"] == "10.0.0.5"
    assert config["server"]["port"] == 9999
    assert config["collector"]["interval"] == 15
    assert config["collector"]["sources"] == ["syslog", "auth"]


def test_resolve_agent_target_prefers_yaml_config(monkeypatch, tmp_path: Path):
    config_path = tmp_path / "agent.yaml"
    config_path.write_text(
        """
server:
  host: 10.2.3.4
  port: 7777
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setenv("THREATHUNTER_AGENT_CONFIG", str(config_path))
    host, port = resolve_agent_target()

    assert host == "10.2.3.4"
    assert port == 7777
