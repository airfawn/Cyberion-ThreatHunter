# python src/server.py
import json
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from queue import Queue


class ServerThread(threading.Thread):
    """
    TCP server that accepts a single agent connection at a time.
    Each event is expected to be a JSON object terminated by a newline.
    Supports LOG_BATCH for batched log delivery with ACKs.
    """

    def __init__(self, host: str, port: int,
                 event_queue: Queue,
                 status_callback=None):
        super().__init__(daemon=True)
        # Respect caller-provided bind settings (main module defines defaults).
        self.host = host
        self.port = port
        self.event_queue = event_queue
        self.status_cb = status_callback or (lambda s: None)
        self._stop_event = threading.Event()
        self._listen_socket = None
        # Bounded dedup of processed log_ids so retransmitted batches (e.g.
        # when an ACK was lost) are not inserted twice into the DB/GUI.
        self._processed_ids: set[str] = set()
        self._processed_order: deque[str] = deque(maxlen=10000)

    def run(self):
        while not self._stop_event.is_set():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    srv.bind((self.host, self.port))
                except OSError as exc:
                    # Port in use (or another bind error): report and retry
                    # instead of crashing the thread with a traceback.
                    self.status_cb(f"Bind failed: {exc}")
                    print(f"[Server] Bind failed on {self.host}:{self.port}: {exc}")
                    time.sleep(1)
                    continue
                srv.listen(1)
                srv.settimeout(1.0)
                self._listen_socket = srv
                self.status_cb("Waiting for connection")
                while not self._stop_event.is_set():
                    try:
                        # Waiting state: blocked until a client connects.
                        conn, addr = srv.accept()
                        self.status_cb("Connected")
                        with conn:
                            conn.settimeout(1.0)
                            buffer = ""
                            # Connected state: actively receive and process messages.
                            while not self._stop_event.is_set():
                                try:
                                    data = conn.recv(4096).decode("utf-8")
                                except socket.timeout:
                                    continue
                                if not data:
                                    break
                                buffer += data
                                # process lines one by one
                                while "\n" in buffer:
                                    line, buffer = buffer.split("\n", 1)
                                    self._handle_line(line.strip(), conn)
                        self.status_cb("Waiting for connection")
                    except socket.timeout:
                        continue
                    except Exception as exc:
                        if self._stop_event.is_set():
                            break
                        # A socket error means the listening loop should stop
                        print(f"[Server] Error: {exc}")
                        self.status_cb("Waiting for connection")
                self._listen_socket = None

    def _handle_line(self, line: str, conn):
        if not line:
            return

        # Allow browser/HTTP health probes on the same port without hanging.
        # The agent protocol remains newline-delimited JSON.
        if self._respond_if_http_probe(line, conn):
            return

        try:
            msg = json.loads(line)
            msg_type = msg.get("type", "EVENT")

            if msg_type == "LOG_BATCH":
                logs = msg.get("logs", [])
                agent_id = msg.get("agent_id", "unknown")
                received_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                ack_ids = []

                for log_entry in logs:
                    source = log_entry.get("source", "Unknown")
                    raw_event = log_entry.get("raw_event", "")
                    ts_agent = log_entry.get("timestamp")
                    log_time = ts_agent if ts_agent else received_at
                    log_id = log_entry.get("log_id")

                    if log_id:
                        ack_ids.append(log_id)
                        if self._is_duplicate(log_id):
                            continue

                    raw_message = json.dumps(log_entry)
                    structured = self._parse_raw_event(raw_event)
                    structured["raw_message"] = raw_message
                    self.event_queue.put((log_time, source, raw_event, raw_message, structured))

                if ack_ids:
                    ack_msg = {
                        "type": "ACK",
                        "log_ids": ack_ids,
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    }
                    try:
                        conn.sendall((json.dumps(ack_msg) + "\n").encode("utf-8"))
                    except Exception as e:
                        print(f"[Server] Failed to send ACK: {e}")

            elif msg_type == "HEARTBEAT":
                ack_msg = {
                    "type": "HEARTBEAT_ACK",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                }
                try:
                    conn.sendall((json.dumps(ack_msg) + "\n").encode("utf-8"))
                except Exception as e:
                    print(f"[Server] Failed to send HEARTBEAT_ACK: {e}")

            else:
                source = msg.get("source", "Unknown")
                raw_event = msg.get("raw_event", "")
                ts_agent = msg.get("timestamp")
                received_at = (
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    if not ts_agent
                    else ts_agent
                )
                raw_message = json.dumps(msg)
                structured = self._parse_raw_event(raw_event)
                structured["raw_message"] = raw_message
                self.event_queue.put((received_at, source, raw_event, raw_message, structured))

        except json.JSONDecodeError:
            pass

    def _respond_if_http_probe(self, line: str, conn) -> bool:
        first = line.upper()
        if not (first.startswith("GET ") or first.startswith("HEAD ")):
            return False

        body = (
            "{\"service\":\"cyberion-server\","
            "\"protocol\":\"tcp-json-lines\","
            "\"status\":\"ok\"}"
        )
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        try:
            conn.sendall(response.encode("utf-8"))
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        return True

    def _is_duplicate(self, log_id: str) -> bool:
        """Return True if log_id was already processed (retransmission)."""
        if log_id in self._processed_ids:
            return True
        self._processed_ids.add(log_id)
        if len(self._processed_order) >= self._processed_order.maxlen:
            self._processed_ids.discard(self._processed_order.popleft())
        self._processed_order.append(log_id)
        return False

    def _parse_raw_event(self, raw_event: str) -> dict[str, str]:
        """Parse raw_event string into structured fields."""
        result: dict[str, str] = {}
        if not isinstance(raw_event, str):
            return result
        try:
            payload = json.loads(raw_event)
        except (json.JSONDecodeError, TypeError):
            if raw_event:
                result["message"] = raw_event
            return result

        if not isinstance(payload, dict):
            if raw_event:
                result["message"] = raw_event
            return result

        result["event_type"] = str(payload.get("event_type", ""))
        result["process"] = str(payload.get("process", ""))
        result["pid"] = str(payload.get("pid", ""))
        result["user"] = str(payload.get("user", ""))
        result["ip_address"] = str(payload.get("ip_address", ""))

        message = payload.get("message") or payload.get("raw_event") or ""
        if not message:
            message = raw_event
        result["message"] = str(message)

        for key, value in payload.items():
            if key not in result and key not in {"timestamp", "source", "raw_event", "message"}:
                result[key] = str(value)

        return result

    def stop(self):
        self._stop_event.set()
        srv = self._listen_socket
        if srv is not None:
            try:
                srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass
        else:
            try:
                # Fallback: connect to the local port just to unblock accept().
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    pass
            except Exception:
                pass