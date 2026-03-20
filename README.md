# Device Discovery

Network asset discovery tool: discovers live hosts on a subnet, enriches them with hostname, MAC, manufacturer, and open ports, then outputs a JSON inventory.

**Two ways to use it:**

| Mode | Description |
|------|-------------|
| **CLI** | Run `devicefinder.py` from the terminal. Writes `inventory_*.json` to disk. |
| **Web UI** | React frontend + FastAPI backend. Start a scan from the browser, view results in a table. |

---

## Quick start

### CLI (no server needed)

```bash
cd device_discover
python3 devicefinder.py --subnet 172.22.172.92
```

- Subnet can be **CIDR** (`172.22.172.0/24`) or **plain IP** (`172.22.172.92`) — auto-resolves using your local network.
- Use `--skip-ping-sweep` if ICMP is blocked on your network.
- Run `python3 devicefinder.py --help` for all options.

### Web UI (backend + frontend)

**Terminal 1 — Backend**
```bash
cd device_discover/web/backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — Frontend**
```bash
cd device_discover/web/frontend
npm install
npm run dev -- --port 5173
```

Then open **http://localhost:5173**.

---

## Project structure

```
device_discover/
├── devicefinder.py       # CLI entry point
├── scanner.py            # Core scanning logic (ping sweep, port scan, etc.)
├── networking.py         # Subnet detection, CIDR normalization
├── web/
│   ├── backend/          # FastAPI API + scan orchestration
│   └── frontend/         # React + Vite UI
```

- **scanner.py** — Used by both CLI and web backend.
- **networking.py** — Used for subnet detection and input normalization.

---

## Docs

- [web/backend/README.md](web/backend/README.md) — Backend setup, uvicorn options, env vars
- [web/frontend/README.md](web/frontend/README.md) — Frontend setup, build, proxy
