import socket
import threading
import time

class connector:
    def __init__(self, server_ip="localhost", server_port=12345):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        
    def connect(self):
        """Connect to the server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            print(f"Agent connected to server at {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
            
    def send_message(self, message):
        """Send a message to the server."""
        try:
            if self.socket:
                self.socket.sendall(message.encode())
                print(f"Message sent: {message}")
        except Exception as e:
            print(f"Send error: {e}")
            
    def run(self):
        """Start the agent with connection and periodic messaging."""
        if not self.connect():
            return
            
        # Start a separate thread to keep sending messages
        def send_test_messages():
            while True:
                time.sleep(5)  # Send a message every 5 seconds
                self.send_message("Test Message from Agent")
                
        threading.Thread(target=send_test_messages).start()
        
if __name__ == "__main__":
    conn = connector()
    conn.run()