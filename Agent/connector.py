import socket
import time
import json
import os
from datetime import datetime


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
            
    def send_message(self, message):
        """Send a message to the server."""
        try:
            if self.socket:
                self.socket.sendall(message.encode())
                print(f"Message sent: {message}")
                return True
        except Exception as e:
            self.close_socket()
            print(f"Send error: {e}")
        return False

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
        try:
            while True:
                if self.socket is None and not self.connect():
                    time.sleep(self.reconnect_delay)
                    continue

                time.sleep(5)
                payload = {
                    "source": "Agent",
                    "raw_event": "Test Message from Agent",
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                }
                sent = self.send_message(json.dumps(payload) + "\n")
                if not sent:
                    print(
                        f"Disconnected. Retrying in {self.reconnect_delay}s..."
                    )
                    time.sleep(self.reconnect_delay)
        except KeyboardInterrupt:
            print("Stopping agent.")
        finally:
            self.close_socket()
        
if __name__ == "__main__":
    target_host, target_port = get_agent_target()
    print(f"Starting agent; target server {target_host}:{target_port}")
    conn = connector(server_ip=target_host, server_port=target_port)
    conn.run()