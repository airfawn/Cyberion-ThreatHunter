# Cyberion Installers (Release Bundle)

This folder contains the two cross-platform installer entrypoints:

- `cyberion-server` (server installer and service manager)
- `cyberion-agent` (agent installer and service manager)

Install order:

1. Install server first.
2. Install agent second.

---

## macOS (Intel and Apple Silicon)

### 1) Open terminal in project root

```bash
cd /path/to/Cyberion-ThreatHunter
chmod +x ./releases/cyberion-server ./releases/cyberion-agent
```

### 2) Install server

Interactive:

```bash
./releases/cyberion-server install
```

Silent:

```bash
./releases/cyberion-server install --silent
```

### 3) Install agent

Interactive:

```bash
./releases/cyberion-agent install
```

Silent:

```bash
./releases/cyberion-agent install --silent --server https://server.example.com --token XXXXX --name HOST-001
```

### 4) Verify

```bash
./releases/cyberion-server status
./releases/cyberion-agent status
```

### 5) Diagnostics

```bash
./releases/cyberion-server diagnostics
./releases/cyberion-agent diagnostics
```

Note: For system-wide launchd installation use admin privileges.

---

## Linux (x64 and ARM64)

### 1) Open terminal in project root

```bash
cd /path/to/Cyberion-ThreatHunter
chmod +x ./releases/cyberion-server ./releases/cyberion-agent
```

### 2) Install server

System-wide (root/systemd):

```bash
sudo ./releases/cyberion-server install --silent
```

User-mode:

```bash
./releases/cyberion-server install --silent
```

### 3) Install agent

System-wide:

```bash
sudo ./releases/cyberion-agent install --silent --server https://server.example.com --token XXXXX --name HOST-001
```

User-mode:

```bash
./releases/cyberion-agent install --silent --server https://server.example.com --token XXXXX --name HOST-001
```

### 4) Verify

```bash
./releases/cyberion-server status
./releases/cyberion-agent status
```

### 5) Diagnostics

```bash
./releases/cyberion-server diagnostics
./releases/cyberion-agent diagnostics
```

---

## Windows 10/11 (x64 and ARM64)

Run from PowerShell in project root.

### 1) Install server

```powershell
python .\releases\cyberion-server install --silent
```

### 2) Install agent

```powershell
python .\releases\cyberion-agent install --silent --server https://server.example.com --token XXXXX --name HOST-001
```

### 3) Verify

```powershell
python .\releases\cyberion-server status
python .\releases\cyberion-agent status
```

### 4) Diagnostics

```powershell
python .\releases\cyberion-server diagnostics
python .\releases\cyberion-agent diagnostics
```

Use an elevated PowerShell session for system-wide Windows Service installation.

---

## Common lifecycle commands

Server:

```bash
./releases/cyberion-server upgrade
./releases/cyberion-server repair
./releases/cyberion-server restart
./releases/cyberion-server uninstall
./releases/cyberion-server uninstall --purge
```

Agent:

```bash
./releases/cyberion-agent upgrade
./releases/cyberion-agent repair
./releases/cyberion-agent restart
./releases/cyberion-agent uninstall
./releases/cyberion-agent uninstall --purge
```

---

## Help

```bash
./releases/cyberion-server --help
./releases/cyberion-agent --help
```

On Windows:

```powershell
python .\releases\cyberion-server --help
python .\releases\cyberion-agent --help
```
