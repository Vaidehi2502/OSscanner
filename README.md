# OSscanner

![CI](https://github.com/Vaidehi2502/OSscanner/actions/workflows/ci.yml/badge.svg)

A local security posture scanner. The backend runs a set of scanners against
the host machine (processes, network connections, listening ports, startup
persistence, file permissions, auth logs, user accounts), scores the combined
findings, stores results in SQLite, and can export a PDF report. The frontend
is a small React dashboard that triggers scans and displays results.

## Project layout

```
backend/
  app.py                  Flask API (POST /api/scan, GET /api/scans, ...)
  scanners/                One module per check, each exposing scan() -> list[dict]
  ai/analyzer.py           Aggregates/scores/dedupes findings into a report
  reports/pdf.py           Renders a report to PDF (falls back to .txt without reportlab)
  rules/*.json             Signatures used by the process/port scanners
  utils/                   Hashing + scoring helpers
  database/                SQLite schema + persistence (scans.db)
frontend/                 React dashboard (create-react-app style)
```

## Running the backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

The API listens on `http://localhost:5000`. `psutil` and `reportlab` are
optional: scanners fall back to `/proc`/`ss`/`systemctl` parsing without
`psutil`, and PDF generation falls back to a plain-text report without
`reportlab`.

Some scanners (log_scanner, permission_scanner reading `/etc/shadow` via
user_scanner) return more complete results when run as root.

By default the server binds to `127.0.0.1:5000` with the Flask debugger
off. Override with environment variables if needed:

```bash
FLASK_DEBUG=1 FLASK_HOST=0.0.0.0 FLASK_PORT=5000 python3 app.py
```

Only set `FLASK_DEBUG=1` or `FLASK_HOST=0.0.0.0` on a trusted network —
Flask's debug mode exposes an interactive console that can execute code.

CORS defaults to allowing only `http://localhost:3000` (the frontend dev
server) under `/api/*`. Override with a comma-separated list if you serve
the frontend from elsewhere:

```bash
CORS_ORIGINS=http://localhost:3000,https://your-deployed-frontend python3 app.py
```

Do not set this to `*` - this API returns detailed system information
(processes, users, permissions) and a wildcard origin lets any website
open in the browser call it and read the response.

## Running tests

```bash
cd backend
source .venv/bin/activate
pip install pytest
pytest tests/ -v
```

CI runs this same command on every push/PR via
`.github/workflows/ci.yml`.

## Running the frontend

```bash
cd frontend
npm install
npm start
```

This starts the dev server on `http://localhost:3000` and proxies `/api/*`
requests to the Flask backend on port 5000 (see `"proxy"` in
`frontend/package.json`).

## API

| Method | Path                    | Description                          |
|--------|-------------------------|--------------------------------------|
| POST   | `/api/scan`             | Run all scanners, persist, return report |
| GET    | `/api/scans`            | List past scan summaries             |
| GET    | `/api/scans/<id>`       | Fetch a full stored report           |
| GET    | `/api/scans/<id>/pdf`   | Download the report (PDF or .txt fallback) |
| GET    | `/api/health`           | Health check                         |

## Extending

- Add a new check: create `backend/scanners/<name>.py` with a `scan()`
  function returning a list of finding dicts, then register it in
  `backend/scanners/__init__.py`'s `SCANNERS` dict.
- Add a new signature: edit the relevant JSON file under `backend/rules/`.
- Swap the scoring model: `backend/ai/analyzer.py` is currently rule-based
  (see `backend/utils/score.py`) — replace `summarize()` with an LLM call if
  you want narrative summaries instead of the templated one.

## License

MIT — see [LICENSE](LICENSE).
