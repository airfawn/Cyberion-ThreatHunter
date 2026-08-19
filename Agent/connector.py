import socket
import time
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_ROOT = Path(__file__).resolve().parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

try:
    from .collector import Collector, detect_runtime_platform, gather_initial_data
    from .log_queue import LogQueue, LogSender, LogEntry
except ImportError:
    from Agent.collector import Collector, detect_runtime_platform, gather_initial_data
    from Agent.log_queue import LogQueue, LogSender, LogEntry


def _get_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"Invalid integer for {name}: {raw!r}. Using {default}.")
        return default
    if value <= 0 or value > 65535:
        print(f"Out-of-range port for {name}: {value}. Using {default}.")
        return default
    return value


def _default_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "agent.yaml"


def load_agent_config(config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Load agent configuration from YAML if available, falling back to environment defaults."""
    config_file = Path(config_path or os.getenv("THREATHUNTER_AGENT_CONFIG") or _default_config_path())
    if not config_file.exists():
        return {}

    if yaml is None:
        print("[Agent] PyYAML is not installed; ignoring agent configuration file")
        return {}

    try:
        with config_file.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
    except Exception as exc:  # pragma: no cover
        print(f"[Agent] Failed to read agent config {config_file}: {exc}")
        return {}

    if not isinstance(loaded, dict):
        return {}
    return loaded


def update_runtime_metadata(config: dict[str, Any], config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Populate runtime OS/architecture fields in config and persist them."""
    runtime = detect_runtime_platform()
    runtime_cfg = config.get("runtime", {}) if isinstance(config.get("runtime"), dict) else {}
    runtime_cfg.update(
        {
            "os": runtime.get("os_family", "linux"),
            "os_name": runtime.get("os_name", ""),
            "architecture": runtime.get("architecture", ""),
            "hostname": runtime.get("hostname", ""),
            "last_detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
    )
    config["runtime"] = runtime_cfg

    config_file = Path(config_path or os.getenv("THREATHUNTER_AGENT_CONFIG") or _default_config_path())
    if yaml is not None:
        try:
            with config_file.open("w", encoding="utf-8") as handle:
                yaml.safe_dump(config, handle, sort_keys=False)
        except Exception as exc:
            print(f"[Agent] Failed to write runtime metadata to {config_file}: {exc}")

    return config


def resolve_agent_target(config: dict[str, Any] | None = None) -> tuple[str, int]:
    """Resolve agent destination from config, environment variables, or defaults."""
    config = config or load_agent_config()
    server_cfg = config.get("server", {}) if isinstance(config.get("server"), dict) else {}

    # Environment variables intentionally take precedence so operators can
    # redirect agents at runtime without editing YAML.
    server_host = (
        os.getenv("THREATHUNTER_SERVER_HOST")
        or os.getenv("THREATHUNTER_HOST_SERVER")
        or server_cfg.get("host")
    )
    if server_host:
        host = str(server_host)
    else:
        bind_host = os.getenv("THREATHUNTER_BIND_HOST", "0.0.0.0")
        host = "127.0.0.1" if bind_host in {"0.0.0.0", "::"} else bind_host

    port_value = os.getenv("THREATHUNTER_PORT") or server_cfg.get("port")
    if port_value is None:
        port = 9090
    else:
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            port = _get_env_int("THREATHUNTER_PORT", 9090)
    return host, port


def resolve_collector_sources(config: dict[str, Any] | None = None) -> list[str]:
    config = config or load_agent_config()
    collector_cfg = config.get("collector", {}) if isinstance(config.get("collector"), dict) else {}

    runtime_cfg = config.get("runtime", {}) if isinstance(config.get("runtime"), dict) else {}
    os_name = str(runtime_cfg.get("os") or detect_runtime_platform().get("os_family") or "linux").lower()

    sources = collector_cfg.get("sources") or []
    if isinstance(sources, dict):
        os_specific = sources.get(os_name)
        default_sources = sources.get("default")
        sources = os_specific if os_specific is not None else default_sources or []
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, list):
        return []
    return [str(source) for source in sources if str(source)]


def resolve_os_source_map(config: dict[str, Any] | None = None) -> dict[str, list[str]]:
    config = config or load_agent_config()
    collector_cfg = config.get("collector", {}) if isinstance(config.get("collector"), dict) else {}
    raw = collector_cfg.get("sources") or {}

    if isinstance(raw, dict):
        result: dict[str, list[str]] = {}
        for key, values in raw.items():
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                result[str(key).lower()] = [str(item) for item in values if str(item)]
        return result

    selected = resolve_collector_sources(config)
    runtime_os = str((config.get("runtime") or {}).get("os") or detect_runtime_platform().get("os_family") or "linux").lower()
    return {runtime_os: selected}


class connector:
    def __init__(self, server_ip="127.0.0.1", server_port=9090, config: dict[str, Any] | None = None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.config = config or load_agent_config()
        self.collector_sources = resolve_collector_sources(self.config)
        self.os_sources = resolve_os_source_map(self.config)
        self.runtime_info = detect_runtime_platform()
        self.socket = None
        self.reconnect_delay = _get_env_int("THREATHUNTER_RECONNECT_DELAY", 3)
        self.connect_timeout = self._resolve_connect_timeout()

        # Agent identity
        self.agent_id = str(__import__('uuid').getnode())

        # Log queue and sender
        self.log_queue = LogQueue(max_size=10000)
        self.log_sender = LogSender(
            log_queue=self.log_queue,
            send_func=self._send_raw,
            agent_id=self.agent_id,
            batch_size=50,
            batch_timeout=5.0,
            ack_timeout=30.0,
            max_retries=5,
        )

        # Collector
        self.collector = None
        self._running = False
        self._initial_data_sent = False
        self._sender_active = False
        self.collector_interval = self._resolve_collector_interval()

        # Heartbeat
        self._last_heartbeat = 0.0
        self.heartbeat_interval = 60.0

    def connect(self):
        """Connect to the server."""
        try:
            self.close_socket()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.settimeout(self.connect_timeout)
            self.socket.connect((self.server_ip, self.server_port))
            self.socket.settimeout(None)
            print(f"Agent connected to server at {self.server_ip}:{self.server_port}")
            return True
        except socket.timeout:
            self.close_socket()
            print(
                f"Connection timeout after {self.connect_timeout}s to "
                f"{self.server_ip}:{self.server_port}."
            )
            return False
        except Exception as e:
            self.close_socket()
            print(f"Connection error: {e}")
            return False

    def _send_raw(self, message: str) -> bool:
        """Low-level send without queueing."""
        try:
            if self.socket:
                self.socket.sendall(message.encode())
                return True
        except Exception as e:
            print(f"[Agent] Send error: {e}")
            self.close_socket()
        return False

    def send_initial_data(self):
        """Send initial system identification data to server."""
        data = gather_initial_data()
        payload = {
            "source": "InitialData",
            "raw_event": json.dumps(data),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event_type": "agent_info",
        }
        return self._send_raw(json.dumps(payload) + "\n")

    def _resolve_collector_interval(self) -> int:
        collector_cfg = self.config.get("collector", {}) if isinstance(self.config.get("collector"), dict) else {}
        interval = collector_cfg.get("interval")
        if isinstance(interval, (int, float)):
            return int(interval)
        try:
            return int(os.getenv("THREATHUNTER_COLLECTOR_INTERVAL", "10"))
        except ValueError:
            return 10

    def _resolve_connect_timeout(self) -> float:
        server_cfg = self.config.get("server", {}) if isinstance(self.config.get("server"), dict) else {}
        raw = server_cfg.get("connect_timeout")
        if raw is None:
            raw = os.getenv("THREATHUNTER_CONNECT_TIMEOUT", "8")
        try:
            timeout = float(raw)
        except (TypeError, ValueError):
            timeout = 8.0
        return min(max(timeout, 1.0), 60.0)

    def _start_collector(self):
        """Start the log collector thread."""
        if self.collector is not None:
            return
        self.collector = Collector(
            send_callback=self._queue_collected_event,
            interval=self.collector_interval,
            selected_sources=self.collector_sources,
            os_sources=self.os_sources,
            runtime_info=self.runtime_info,
        )
        self.collector.start()
        print("[Agent] Log collector started")

    def _stop_collector(self):
        """Stop the log collector thread."""
        if self.collector is not None:
            self.collector.stop()
            self.collector = None
            print("[Agent] Log collector stopped")

    def _teardown_connection_runtime(self):
        """Stop background workers tied to a live server connection."""
        self._stop_collector()
        if self._sender_active:
            self.log_sender.stop()
            self._sender_active = False

    def _queue_collected_event(self, event: dict):
        """Callback for collector to queue events."""
        log_entry = LogEntry(
            log_id=str(__import__('uuid').uuid4()),
            source=event["source"],
            raw_event=event["raw_event"],
            timestamp=event["timestamp"],
            event_type=event["event_type"],
            agent_id=self.agent_id,
        )
        if not self.log_queue.put(log_entry):
            print("[Agent] Log queue full, dropping event")

    def close_socket(self):
        if self.socket is None:
            return
        try:
            self.socket.close()
        except Exception:
            pass
        self.socket = None

    def run(self):
        """Maintain persistent server connection and reconnect on failures."""
        print("Agent run loop started. Press Ctrl+C to stop.")
        self._running = True
        try:
            while self._running:
                # Connect if not connected
                if self.socket is None:
                    self._initial_data_sent = False
                    self._teardown_connection_runtime()
                    if not self.connect():
                        time.sleep(self.reconnect_delay)
                        continue

                # Send initial data once per connection
                if not self._initial_data_sent:
                    if not self.send_initial_data():
                        print("[Agent] Failed to send initial data, disconnecting")
                        self.close_socket()
                        time.sleep(self.reconnect_delay)
                        continue
                    self._initial_data_sent = True
                    self._start_collector()
                    # Start log sender with this socket for receiving ACKs
                    self.log_sender.start(recv_socket=self.socket)
                    self._sender_active = True

                # Send heartbeat if interval elapsed
                self._maybe_send_heartbeat()

                # Check for ACK timeouts
                self.log_sender.check_timeouts()

                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping agent.")
        finally:
            self._running = False
            self._teardown_connection_runtime()
            self.close_socket()

    def _maybe_send_heartbeat(self):
        """Send heartbeat if interval elapsed and connected."""
        if not self.socket:
            return
        now = time.time()
        if now - self._last_heartbeat >= self.heartbeat_interval:
            if self.log_sender.send_heartbeat():
                self._last_heartbeat = now
                print("[Agent] Heartbeat sent")

    def stop(self):
        """Stop the agent gracefully."""
        self._running = False


def install_autostart_linux() -> bool:
    """Install a systemd user service for Linux autostart."""
    if platform.system() != "Linux":
        return False
    service_path = Path.home() / ".config/systemd/user/cyberion-agent.service"
    service_path.parent.mkdir(parents=True, exist_ok=True)
    config_path = Path(os.getenv("THREATHUNTER_AGENT_CONFIG") or _default_config_path())
    cmd = sys.executable
    content = f"""[Unit]
Description=Cyberion Agent
After=network-online.target

[Service]
Type=simple
ExecStart={cmd} -m Agent.connector --config {config_path}
Environment=THREATHUNTER_AGENT_CONFIG={config_path}
WorkingDirectory={Path(__file__).resolve().parent.parent}
Restart=on-failure

[Install]
WantedBy=default.target
"""
    service_path.write_text(content, encoding="utf-8")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "--user", "enable", "cyberion-agent.service"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def install_autostart_windows() -> bool:
    """Prepare a Windows startup shortcut for future use."""
    if platform.system() != "Windows":
        return False
    startup_dir = Path(os.getenv("APPDATA", "")) / "Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    if str(startup_dir) == "Microsoft\\Windows\\Start Menu\\Programs\\Startup":
        return False
    startup_dir.mkdir(parents=True, exist_ok=True)
    target = startup_dir / "cyberion-agent.bat"
    config_path = Path(os.getenv("THREATHUNTER_AGENT_CONFIG") or _default_config_path())
    target.write_text(
        f'@echo off\n"{sys.executable}" -m Agent.connector --config "{config_path}"\n',
        encoding="utf-8",
    )
    return True


def install_autostart_macos() -> bool:
    """Install a launch agent plist for macOS autostart."""
    if platform.system() != "Darwin":
        return False
    launch_agents = Path.home() / "Library/LaunchAgents"
    launch_agents.mkdir(parents=True, exist_ok=True)
    plist = launch_agents / "com.cyberion.agent.plist"
    config_path = Path(os.getenv("THREATHUNTER_AGENT_CONFIG") or _default_config_path())
    program_args = [sys.executable, "-m", "Agent.connector", "--config", str(config_path)]
    program_xml = "".join(f"\n        <string>{arg}</string>" for arg in program_args)

    content = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.cyberion.agent</string>
    <key>ProgramArguments</key>
    <array>{program_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>THREATHUNTER_AGENT_CONFIG</key>
        <string>{config_path}</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>{Path(__file__).resolve().parent.parent}</string>
    <key>StandardOutPath</key>
    <string>{Path.home() / 'Library/Logs/cyberion-agent.log'}</string>
    <key>StandardErrorPath</key>
    <string>{Path.home() / 'Library/Logs/cyberion-agent.err.log'}</string>
</dict>
</plist>
"""
    plist.write_text(content, encoding="utf-8")
    subprocess.run(["launchctl", "unload", str(plist)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["launchctl", "load", str(plist)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def install_autostart() -> bool:
    if platform.system() == "Windows":
        return install_autostart_windows()
    if platform.system() == "Darwin":
        return install_autostart_macos()
    return install_autostart_linux()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cyberion Agent")
    parser.add_argument("--config", default=None, help="Path to the agent YAML config")
    parser.add_argument("--install-autostart", action="store_true", help="Install startup entry for the current platform")
    args = parser.parse_args()

    config_path = args.config
    if args.install_autostart:
        print("Installing autostart entry...")
        print("Autostart installed" if install_autostart() else "Autostart not supported on this platform")
        sys.exit(0)

    config = load_agent_config(config_path)
    config = update_runtime_metadata(config, config_path=config_path)
    target_host, target_port = resolve_agent_target(config)
    print(f"Starting agent; target server {target_host}:{target_port}")
    conn = connector(server_ip=target_host, server_port=target_port, config=config)
    conn.run()