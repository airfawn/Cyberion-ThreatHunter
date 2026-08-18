import os
import tempfile
from pathlib import Path

from Agent.connector import (
  load_agent_config,
  resolve_agent_target,
  resolve_collector_sources,
  resolve_os_source_map,
  update_runtime_metadata,
)


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


def test_resolve_agent_target_prefers_env_over_yaml(monkeypatch, tmp_path: Path):
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
    monkeypatch.setenv("THREATHUNTER_SERVER_HOST", "127.0.0.1")
    monkeypatch.setenv("THREATHUNTER_PORT", "9090")
    host, port = resolve_agent_target()

    assert host == "127.0.0.1"
    assert port == 9090


def test_resolve_agent_target_supports_legacy_host_env(monkeypatch, tmp_path: Path):
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
    monkeypatch.delenv("THREATHUNTER_SERVER_HOST", raising=False)
    monkeypatch.setenv("THREATHUNTER_HOST_SERVER", "127.0.0.2")
    host, port = resolve_agent_target()

    assert host == "127.0.0.2"
    assert port == 7777


def test_resolve_collector_sources_by_os(tmp_path: Path):
    config_path = tmp_path / "agent.yaml"
    config_path.write_text(
        """
collector:
  interval: 10
  sources:
    default:
      - journald
    windows:
      - windows_security
      - sysmon
runtime:
  os: windows
""".strip(),
        encoding="utf-8",
    )

    config = load_agent_config(config_path)
    sources = resolve_collector_sources(config)
    assert sources == ["windows_security", "sysmon"]


def test_resolve_os_source_map_with_list_and_runtime(monkeypatch):
    config = {
        "collector": {"sources": ["syslog", "auth"]},
        "runtime": {"os": "linux"},
    }
    mapping = resolve_os_source_map(config)
    assert mapping == {"linux": ["syslog", "auth"]}


def test_update_runtime_metadata_writes_fields(tmp_path: Path):
    config = {
        "server": {"host": "127.0.0.1", "port": 9090},
        "collector": {"sources": {"default": ["journald"]}},
    }
    config_path = tmp_path / "agent.yaml"
    updated = update_runtime_metadata(config, config_path=config_path)

    assert "runtime" in updated
    assert updated["runtime"]["os"] in {"linux", "macos", "windows"}
    assert updated["runtime"]["architecture"]
    assert config_path.exists()
