# OSscanner

![CI](https://github.com/Vaidehi2502/OSscanner/actions/workflows/ci.yml/badge.svg)

Inspects core OS state - running processes, network connections, listening
ports, startup persistence, authentication logs, file permissions, and user
accounts - to surface security risks and misconfigurations. Findings are
correlated into a unified risk score, stored as historical scans in SQLite,
and presented through a React dashboard with downloadable PDF reports.

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

By default the API has no authentication - fine for a quick local check,
but anything reachable beyond your own machine should set an API key:

```bash
API_KEY=some-long-random-secret python3 app.py
```

When set, every `/api/*` route except `/api/health` requires a matching
`X-API-Key` header, returning `401` otherwise. With no `API_KEY` set, a
startup warning is printed and all endpoints stay open. The frontend
needs the same value in `REACT_APP_API_KEY` (see below) to authenticate
its requests.

## Running the backend in Docker

```bash
docker build -t osscanner-backend ./backend
docker run --rm -p 5000:5000 -e API_KEY=some-long-random-secret osscanner-backend
```

This works, but by default every scanner only sees the **container's own**
isolated processes, network state, and filesystem - not your actual
machine. That's fine for poking at the API, but it is not a real scan of
your host. To make scanners see the real host:

```bash
docker run --rm \
  --pid=host \
  --network=host \
  -v /var/log:/var/log:ro \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/shadow:/etc/shadow:ro \
  -v /etc/crontab:/etc/crontab:ro \
  -v /etc/cron.d:/etc/cron.d:ro \
  -v /etc/xdg/autostart:/etc/xdg/autostart:ro \
  -v /tmp:/tmp \
  -v /var/tmp:/var/tmp \
  -v /dev/shm:/dev/shm \
  -e API_KEY=some-long-random-secret \
  osscanner-backend
```

- `--pid=host` + `--network=host` give `process_scanner`, `network_scanner`,
  and `port_scanner` a real view of host processes/connections/ports.
- The bind mounts give `log_scanner`, `user_scanner`, and the cron/autostart
  parts of `startup_scanner` a real view, since those read fixed absolute
  paths (e.g. `/var/log/auth.log`, `/etc/shadow`) that must exist at the
  same path inside the container to be found at all.
- The container runs as root by default (no `USER` directive) because
  reading `/etc/shadow` and enumerating other users' processes needs it -
  same tradeoff the README already notes for running natively as root.

Two real gaps even with all of this:
- **`permission_scanner` cannot see the host's real binaries.** It scans
  `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` for SUID/SGID/world-writable
  files - but those paths inside the container are the *container's own*
  binaries (needed for Python etc. to keep working), not the host's.
  Bind-mounting the host's copies over them would likely break the
  container itself, and the scanner's target directories aren't
  configurable via env var today, so this scanner's results only reflect
  the container image while running this way.
- **systemd-based enabled-service detection in `startup_scanner` generally
  won't work** - it shells out to `systemctl`, which needs a running
  systemd instance most containers don't have. It fails gracefully (empty
  results, no crash) rather than erroring.

If you want full, accurate host visibility, running the backend natively
(see above) is simpler and has none of these gaps.

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

If the backend has `API_KEY` set, create `frontend/.env.local` with the
same value (Create React App only exposes env vars prefixed
`REACT_APP_`, and only picks up changes after restarting `npm start`):

```
REACT_APP_API_KEY=some-long-random-secret
```

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
