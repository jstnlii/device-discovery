# Device Discovery Web (FastAPI)

## Run (development)
From `device_discover/web/backend`:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Environment variables
- `ALLOWED_ORIGINS` (optional, comma-separated; default `*`)
- `SCANS_DIR` (optional; default `./data/scans`)

Scans are persisted to `data/scans/<scan_id>/inventory.json` and `status.json`.

