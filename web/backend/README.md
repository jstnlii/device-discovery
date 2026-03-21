# Device Discovery — Backend

FastAPI backend for the Device Discovery web UI. Handles scan start/cancel, progress, and scan history.

---

## Setup (first time)

```bash
cd device_discover/web/backend
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Run the server

### Development (auto-reload on file changes)

```bash
source .venv/bin/activate
uvicorn app.main:app --reload --port 8008
```

### Production-style (no reload, just start)

```bash
uvicorn app.main:app --port 8008
```

### Bind to all interfaces (e.g. access from another device)

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8008
```

---

## Stop / kill the server

| Method | When |
|--------|------|
| **Ctrl+C** | Server is in the foreground |
| **`kill <PID>`** | From another terminal: `lsof -nP -iTCP:8008 -sTCP:LISTEN` to get PID, then `kill <PID>` |
| **`kill -9 <PID>`** | Force kill if it doesn’t stop |

---

## Uvicorn options (reference)

| Option | Meaning |
|--------|---------|
| `--reload` | Watch for file changes and restart (dev only) |
| `--port 8008` | Port to listen on |
| `--host 0.0.0.0` | Listen on all interfaces (default: 127.0.0.1) |

Omit `--reload` if you want a simple start without auto-restart.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) |
| `SCANS_DIR` | `./data/scans` | Directory for scan data |
| `MAX_SCAN_HOSTS` | `1024` | Max hosts per scan (safety cap) |
| `DEVICE_DISCOVER_MANUF_PATH` | *(unset)* | Optional path to a Wireshark-format `manuf` OUI file. If unset, the copy bundled with the `manuf` PyPI package is used (offline). |

Scan data is stored as `data/scans/<scan_id>/inventory.json` and `status.json`.

Vendor names come from the Wireshark OUI database loaded by [`manuf`](https://pypi.org/project/manuf/) (no network calls at lookup time). Hostnames use reverse DNS first, then fall back to mDNS (Bonjour) via [`zeroconf`](https://pypi.org/project/zeroconf/) when reverse DNS returns nothing—common on home networks.
