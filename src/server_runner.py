"""Headless Cyberion server runtime for background service execution."""

from __future__ import annotations

import json
import os
import queue
import signal
import sys
import time
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

try:
    from .database import CyberionDB, EventPersistenceWorker  # type: ignore
    from .server import ServerThread  # type: ignore
except ImportError:
    from src.database import CyberionDB, EventPersistenceWorker  # type: ignore
    from src.server import ServerThread  # type: ignore


SETTINGS_FILE = "cyberion_settings.json"


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
        print(f"Out-of-range value for {name}: {value}. Using {default}.")
        return default
    return value


def get_runtime_network_config() -> tuple[str, int]:
    bind_host = os.getenv("THREATHUNTER_BIND_HOST", "0.0.0.0")
    port = _get_env_int("THREATHUNTER_PORT", 9090)

    config_path = Path(__file__).resolve().parent.parent / SETTINGS_FILE
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                saved = json.load(handle)
            bind_host = str(saved.get("bind_host", bind_host))
            port = int(saved.get("port", port))
        except Exception as exc:
            print(f"Ignoring invalid settings file {config_path}: {exc}")

    return bind_host, port


def main() -> int:
    bind_host, port = get_runtime_network_config()
    print(f"Starting Cyberion headless server on {bind_host}:{port}")

    event_queue: "queue.Queue[tuple[str, str, str, str, dict[str, str]]]" = queue.Queue()
    persist_queue: "queue.Queue[tuple[str, str, str, str, dict[str, str]]]" = queue.Queue()

    db = CyberionDB()
    worker = EventPersistenceWorker(db, event_queue, persist_queue)
    worker.start()

    status_value = {"status": "Waiting for connection"}

    def _status_cb(new_status: str):
        status_value["status"] = new_status
        print(f"[ServerStatus] {new_status}")

    server = ServerThread(bind_host, port, event_queue, status_callback=_status_cb)
    server.start()

    running = True

    def _stop(_signum=None, _frame=None):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        while running:
            time.sleep(1)
    finally:
        server.stop()
        server.join(timeout=2)
        worker.stop()
        db.close()

    print("Cyberion headless server stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
