Run from the project root directory.

1. Create and activate a virtual environment (optional but recommended):
python3 -m venv venv
source venv/bin/activate

2. Install dependencies:
pip install -r src/requirements.txt

3. Start the UI/server:
python3 -m src.main

4. In another terminal, start the sample agent sender:
python3 -m Agent.connector

Network configuration (professional/VM-friendly):

- THREATHUNTER_BIND_HOST: address for UI server bind (default 0.0.0.0)
- THREATHUNTER_PORT: shared TCP port for server and agent (default 9090)
- THREATHUNTER_SERVER_HOST: agent target host override (recommended for VM setups)
- THREATHUNTER_AUX_HOST: auxiliary listener host (default 127.0.0.1)
- THREATHUNTER_AUX_PORT: auxiliary listener port (default 12345)
- THREATHUNTER_RECONNECT_DELAY: agent reconnect delay in seconds (default 3)

Connection behavior:

- Server state is Waiting for connection until an agent connects.
- When connected, server state changes to Connected and it receives/processes data.
- If the agent disconnects, server state returns to Waiting for connection.
- Agent stays in a persistent run loop and auto-reconnects on connection loss.

Examples:

Local machine only:
THREATHUNTER_BIND_HOST=127.0.0.1 THREATHUNTER_PORT=9090 python3 -m src.main
THREATHUNTER_SERVER_HOST=127.0.0.1 THREATHUNTER_PORT=9090 python3 -m Agent.connector

VM agent connecting to host machine:
THREATHUNTER_BIND_HOST=0.0.0.0 THREATHUNTER_PORT=9090 python3 -m src.main
THREATHUNTER_SERVER_HOST=<HOST_MACHINE_IP> THREATHUNTER_PORT=9090 python3 -m Agent.connector
