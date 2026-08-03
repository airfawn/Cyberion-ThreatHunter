# python src/server.py
import json
import socket
import threading
from datetime import datetime
from queue import Queue


class ServerThread(threading.Thread):
    """
    TCP server that accepts a single agent connection at a time.
    Each event is expected to be a JSON object terminated by a newline.
    """

    def __init__(self, host: str, port: int,
                 event_queue: Queue,
                 status_callback=None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.event_queue = event_queue
        self.status_cb = status_callback or (lambda s: None)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            while True:
                try:
                    conn, addr = srv.accept()
                    self.status_cb("● Connected")
                    with conn:
                        buffer = ""
                        while True:
                            data = conn.recv(4096).decode("utf-8")
                            if not data:
                                break
                            buffer += data
                            # process lines one by one
                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)
                                self._handle_line(line.strip())
                    self.status_cb("● Disconnected")
                except Exception as exc:
                    # A socket error means the listening loop should stop
                    print(f"[Server] Error: {exc}")
                    break

    def _handle_line(self, line: str):
        if not line:
            return
        try:
            msg = json.loads(line)
            source = msg.get("source", "Unknown")
            raw_event = msg.get("raw_event", "")
            # If the agent sent a timestamp use it; otherwise use now.
            ts_agent = msg.get("timestamp")
            received_at = (
                datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ") if not ts_agent else ts_agent
            )
            self.event_queue.put((received_at, source, raw_event))
        except json.JSONDecodeError:
            # Malformed JSON – ignore for robustness
            pass

    def stop(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=1):
                pass  # just to unblock accept()
        except Exception:
            pass