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

Threat Hunting page:

- A dedicated Threat Hunting tab is available in the top navigation.
- Hunts are hypothesis-driven and run in background threads, so the UI remains responsive.
- Investigation outputs include suspicious events, correlation timeline, extracted indicators, optional IP enrichment, and analyst conclusion text.
- Hypotheses are persisted in data/threat_hypotheses.json.
- Investigation snapshots are persisted in data/threat_investigations.json.

Optional IP reputation configuration:

- THREATHUNTER_IPREP_API_URL: endpoint URL (use {ip} placeholder or query param style)
- THREATHUNTER_IPREP_API_KEY: bearer token for the configured service (optional if service does not require auth)
- THREATHUNTER_IPREP_SOURCE: display name for the external source (default: Configured Reputation API)
- THREATHUNTER_IPREP_TIMEOUT: HTTP timeout seconds for enrichment calls (default: 4)

Example:
THREATHUNTER_IPREP_API_URL=https://example-intel.local/reputation/{ip} THREATHUNTER_IPREP_API_KEY=<token> python3 -m src.main

Run tests:

- Core threat hunting tests: pytest -q tests/test_threat_hunting.py
- Regression tests used during implementation: pytest -q tests/test_detections.py tests/test_alerts.py tests/test_query_language.py
