import socket
import time
import json
import os
import threading
from datetime import datetime, timezone

from .collector import Collector, gather_initial_data
from .log_queue import LogQueue, LogSender, LogEntry


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


def get_agent_target() -> tuple[str, int]:
    """Resolve agent destination from environment variables."""
    server_host = os.getenv("THREATHUNTER_SERVER_HOST")
    if server_host:
        host = server_host
    else:
        bind_host = os.getenv("THREATHUNTER_BIND_HOST", "0.0.0.0")
        host = "127.0.0.1" if bind_host in {"0.0.0.0", "::"} else bind_host
    port = _get_env_int("THREATHUNTER_PORT", 9090)
    return host, port


class connector:
    def __init__(self, server_ip="127.0.0.1", server_port=9090):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.reconnect_delay = _get_env_int("THREATHUNTER_RECONNECT_DELAY", 3)

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

        # Heartbeat
        self._last_heartbeat = 0.0
        self.heartbeat_interval = 60.0

    def connect(self):
        """Connect to the server."""
        try:
            self.close_socket()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.connect((self.server_ip, self.server_port))
            print(f"Agent connected to server at {self.server_ip}:{self.server_port}")
            return True
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

    def _start_collector(self):
        """Start the log collector thread."""
        if self.collector is not None:
            return
        self.collector = Collector(send_callback=self._queue_collected_event)
        self.collector.start()
        print("[Agent] Log collector started")

    def _stop_collector(self):
        """Stop the log collector thread."""
        if self.collector is not None:
            self.collector.stop()
            self.collector = None
            print("[Agent] Log collector stopped")

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
                    self._stop_collector()
                    self.log_sender.stop()
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

                # Send heartbeat if interval elapsed
                self._maybe_send_heartbeat()

                # Check for ACK timeouts
                self.log_sender.check_timeouts()

                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping agent.")
        finally:
            self._running = False
            self._stop_collector()
            self.log_sender.stop()
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


if __name__ == "__main__":
    target_host, target_port = get_agent_target()
    print(f"Starting agent; target server {target_host}:{target_port}")
    conn = connector(server_ip=target_host, server_port=target_port)
    conn.run()