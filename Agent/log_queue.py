import json
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Dict, List, Optional, Callable


class LogEntry:
    """Represents a single log entry in the queue."""

    def __init__(
        self,
        log_id: str,
        source: str,
        raw_event: str,
        timestamp: str,
        event_type: str,
        agent_id: str = "",
    ):
        self.log_id = log_id
        self.source = source
        self.raw_event = raw_event
        self.timestamp = timestamp
        self.event_type = event_type
        self.agent_id = agent_id
        self.sent_count = 0
        self.last_sent = 0.0
        self.acked = False

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "source": self.source,
            "raw_event": self.raw_event,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
        }

    @classmethod
    def from_dict(cls, data: dict, agent_id: str = "") -> "LogEntry":
        entry = cls(
            log_id=data["log_id"],
            source=data["source"],
            raw_event=data["raw_event"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            agent_id=agent_id or data.get("agent_id", ""),
        )
        entry.sent_count = data.get("sent_count", 0)
        entry.last_sent = data.get("last_sent", 0.0)
        entry.acked = data.get("acked", False)
        return entry


class LogQueue:
    """Thread-safe queue for log entries with ACK tracking."""

    def __init__(self, max_size: int = 10000):
        self._queue: Queue = Queue(maxsize=max_size)
        self._pending: Dict[str, LogEntry] = {}  # log_id -> LogEntry (sent but not acked)
        self._lock = threading.RLock()
        self._max_size = max_size

    def put(self, entry: LogEntry) -> bool:
        """Add a log entry to the queue. Returns True if added, False if queue full."""
        with self._lock:
            if self._queue.qsize() >= self._max_size:
                return False
            self._queue.put(entry)
            return True

    def get_batch(self, batch_size: int, max_age_seconds: float = 30.0) -> List[LogEntry]:
        """Get a batch of logs ready to send (new or retry)."""
        batch = []
        now = time.time()

        with self._lock:
            # First, collect pending entries that need retry
            for log_id, entry in list(self._pending.items()):
                if entry.acked:
                    del self._pending[log_id]
                    continue
                # Retry if not sent recently
                if now - entry.last_sent >= max_age_seconds:
                    batch.append(entry)
                    if len(batch) >= batch_size:
                        return batch

            # Then collect new entries from queue
            while len(batch) < batch_size:
                try:
                    entry = self._queue.get_nowait()
                    if not entry.acked:
                        batch.append(entry)
                except Empty:
                    break

        return batch

    def mark_sent(self, entries: List[LogEntry]):
        """Mark entries as sent (move to pending)."""
        now = time.time()
        with self._lock:
            for entry in entries:
                entry.sent_count += 1
                entry.last_sent = now
                self._pending[entry.log_id] = entry

    def mark_acked(self, log_ids: List[str]):
        """Mark entries as acknowledged (remove from pending)."""
        with self._lock:
            for log_id in log_ids:
                if log_id in self._pending:
                    del self._pending[log_id]

    def requeue_pending(self, log_ids: List[str]):
        """Re-queue entries that were sent but not acked (e.g., on disconnect).

        sent_count is preserved so max_retries can be enforced across retries.
        """
        with self._lock:
            for log_id in log_ids:
                if log_id in self._pending:
                    entry = self._pending[log_id]
                    if not entry.acked:
                        entry.last_sent = 0.0
                        try:
                            self._queue.put_nowait(entry)
                        except:
                            pass  # queue full, keep in pending
                    del self._pending[log_id]

    def requeue_entries(self, entries: List[LogEntry]):
        """Return entries back to the queue for retry.

        Entries that are still tracked in pending are left alone so they are
        not duplicated; entries that were popped from the queue for sending
        (but never acknowledged) are put back so no logs are lost on failure.
        """
        with self._lock:
            for entry in entries:
                if entry.log_id in self._pending:
                    continue
                try:
                    self._queue.put_nowait(entry)
                except Exception:
                    pass  # queue full, keep as best-effort

    def drop(self, log_ids: List[str]):
        """Drop entries from pending tracking (used after max retries)."""
        with self._lock:
            for log_id in log_ids:
                self._pending.pop(log_id, None)

    def get_stats(self) -> dict:
        """Get queue statistics."""
        with self._lock:
            return {
                "queued": self._queue.qsize(),
                "pending": len(self._pending),
                "max_size": self._max_size,
            }

    def clear(self):
        """Clear all entries (use with caution)."""
        with self._lock:
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
            self._pending.clear()


class LogSender:
    """Batches and sends logs from queue, handles ACKs and retries."""

    def __init__(
        self,
        log_queue: LogQueue,
        send_func: Callable[[str], bool],
        agent_id: str,
        batch_size: int = 50,
        batch_timeout: float = 5.0,
        ack_timeout: float = 30.0,
        max_retries: int = 5,
    ):
        self.log_queue = log_queue
        self.send_func = send_func
        self.agent_id = agent_id
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.ack_timeout = ack_timeout
        self.max_retries = max_retries

        self._stop_event = threading.Event()
        self._sender_thread: Optional[threading.Thread] = None
        self._receiver_thread: Optional[threading.Thread] = None
        self._recv_socket = None
        self._pending_acks: Dict[str, float] = {}  # log_id -> sent_time

    def start(self, recv_socket=None):
        """Start sender and receiver threads."""
        if self._sender_thread and self._sender_thread.is_alive():
            return
        self._stop_event.clear()
        self._recv_socket = recv_socket
        self._sender_thread = threading.Thread(target=self._send_loop, daemon=True)
        self._sender_thread.start()
        if recv_socket:
            self._receiver_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._receiver_thread.start()
        print(f"[Agent] Log sender started (batch_size={self.batch_size})")

    def stop(self):
        """Stop sender and receiver threads."""
        sender_was_running = bool(self._sender_thread and self._sender_thread.is_alive())
        receiver_was_running = bool(self._receiver_thread and self._receiver_thread.is_alive())
        self._stop_event.set()
        if self._sender_thread:
            self._sender_thread.join(timeout=5)
        if self._receiver_thread:
            self._receiver_thread.join(timeout=5)
        if sender_was_running or receiver_was_running:
            print("[Agent] Log sender stopped")
        self._sender_thread = None
        self._receiver_thread = None

    def _send_loop(self):
        """Main sending loop - batches logs and sends packets."""
        while not self._stop_event.is_set():
            try:
                batch = self.log_queue.get_batch(self.batch_size)
                if batch:
                    self._send_batch(batch)
                else:
                    self._stop_event.wait(self.batch_timeout)
            except Exception as e:
                print(f"[LogSender] Error in send loop: {e}")
                self._stop_event.wait(1)

    def _send_batch(self, batch: List[LogEntry]):
        """Send a batch of logs as a single packet."""
        if not batch:
            return

        # Enforce max_retries: drop entries that have exceeded their send attempts.
        dropped = [e for e in batch if e.sent_count >= self.max_retries]
        retryable = [e for e in batch if e.sent_count < self.max_retries]
        if dropped:
            for entry in dropped:
                self._pending_acks.pop(entry.log_id, None)
            self.log_queue.drop([e.log_id for e in dropped])
            print(f"[LogSender] Dropping {len(dropped)} logs after {self.max_retries} send attempts")
        if not retryable:
            return
        batch = retryable

        packet = {
            "type": "LOG_BATCH",
            "agent_id": self.agent_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "logs": [entry.to_dict() for entry in batch],
        }

        message = json.dumps(packet) + "\n"
        sent = self.send_func(message)

        if sent:
            # Mark as sent (move to pending for ACK tracking)
            self.log_queue.mark_sent(batch)
            for entry in batch:
                self._pending_acks[entry.log_id] = time.time()
            print(f"[LogSender] Sent batch of {len(batch)} logs")
        else:
            # Send failed, put entries back into the queue for retry.
            self.log_queue.requeue_entries(batch)
            print(f"[LogSender] Failed to send batch, will retry")

    def _recv_loop(self):
        """Receive ACKs from server."""
        buffer = ""
        while not self._stop_event.is_set():
            try:
                if not self._recv_socket:
                    time.sleep(0.5)
                    continue

                self._recv_socket.settimeout(1.0)
                data = self._recv_socket.recv(4096).decode("utf-8")
                if not data:
                    break
                buffer += data

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self._handle_line(line.strip())

            except socket.timeout:
                continue
            except Exception as e:
                print(f"[LogSender] Receive error: {e}")
                break

    def _handle_line(self, line: str):
        """Process incoming line from server (ACKs)."""
        if not line:
            return
        try:
            msg = json.loads(line)
            if msg.get("type") == "ACK":
                log_ids = msg.get("log_ids", [])
                if log_ids:
                    self.log_queue.mark_acked(log_ids)
                    for lid in log_ids:
                        self._pending_acks.pop(lid, None)
                    print(f"[LogSender] ACK received for {len(log_ids)} logs")
            elif msg.get("type") == "HEARTBEAT_ACK":
                pass  # heartbeat acknowledged
        except json.JSONDecodeError:
            pass

    def check_timeouts(self):
        """Check for ACK timeouts and re-queue stale entries."""
        now = time.time()
        timed_out = []
        for log_id, sent_time in list(self._pending_acks.items()):
            if now - sent_time > self.ack_timeout:
                timed_out.append(log_id)
        if timed_out:
            print(f"[LogSender] ACK timeout for {len(timed_out)} logs, re-queueing")
            self.log_queue.requeue_pending(timed_out)
            for lid in timed_out:
                self._pending_acks.pop(lid, None)

    def send_heartbeat(self) -> bool:
        """Send a heartbeat packet."""
        packet = {
            "type": "HEARTBEAT",
            "agent_id": self.agent_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        return self.send_func(json.dumps(packet) + "\n")