# OSscanner

![CI](https://github.com/Vaidehi2502/OSscanner/actions/workflows/ci.yml/badge.svg)

Inspects core OS state - running processes, network connections, listening
ports, startup persistence, authentication logs, file permissions, and user
accounts - to surface security risks and misconfigurations. Findings are
correlated into a unified risk score, stored as historical scans in SQLite,
and presented through a React dashboard with downloadable PDF reports.

## Features

- Eight scanners covering processes, network connections, listening ports,
  startup persistence (cron/systemd/autostart), auth logs, file
  permissions (SUID/SGID/world-writable), user accounts, and YARA rule
  matching against dropper-prone directories (`/tmp`, `/var/tmp`,
  `/dev/shm`).
- A single 0-100 risk score with a NONE/LOW/MEDIUM/HIGH/CRITICAL level,
  weighted by severity with diminishing returns for repeated findings so a
  large pile of routine low-severity findings can't alone saturate the
  score (see `backend/utils/score.py`).
- Every scan is persisted to SQLite; the dashboard shows a risk-score trend
  chart plus a scan history table, and clicking any past scan loads its
  full report (findings, summary, score) back into the main view.
- Findings table with severity filter tabs (with live counts), free-text
  search, and pagination - built to stay usable even at 100+ findings.
- Downloadable PDF report per scan (falls back to plain text without
  `reportlab`).
- Optional live monitoring: set `MONITOR_INTERVAL_SECONDS` to run scans
  automatically on a fixed interval in the background (off/manual-only by
  default). The dashboard has its own "Live" toggle that polls for newly
  completed scans (from the background monitor, a manual run, or any other
  client) and follows the latest one automatically - unless you're
  deliberately viewing an older scan, in which case it leaves you there.
- Optional `X-API-Key` auth and an origin-restricted CORS policy, since the
  API returns sensitive host data (processes, users, permissions).
- Backend (106 pytest) and frontend (40 Jest/RTL) test suites, run on every
  push/PR via GitHub Actions CI.

## Limitations

- The report "summary" is templated/rule-based (see `ai/analyzer.py`), not
  an actual model call - the module name is aspirational, not descriptive
  of current behavior.
- No in-UI way to dismiss or allowlist a finding; false positives (e.g. an
  unrecognized SUID binary) require editing the scanner's whitelist in
  code and redeploying.
- Auth is a single shared API key with no user accounts or roles.
- `permission_scanner` caps its directory walk at 5000 entries per
  sensitive directory, so it may miss files on very large filesystems.
- The background monitor (`MONITOR_INTERVAL_SECONDS`) is a single
  in-process thread, not a real job scheduler - it only runs while
  `python3 app.py` is running, doesn't persist across restarts, and (if you
  ever run multiple backend processes/workers behind a load balancer) each
  one would run its own independent monitor rather than coordinating.
- Running the backend in Docker has real visibility gaps (`permission_scanner`
  only sees the container's own binaries, not the host's; systemd-based
  checks don't work without a running systemd instance) - see "Running the
  backend in Docker" below for details.
- The shipped YARA rule set (`backend/rules/yara/`) is a small starter set
  (an EICAR test-string rule and two generic dropper/reverse-shell
  patterns), not real-world malware coverage - drop in rules from a source
  like YARA-Forge or your own for meaningful detection.

## Project layout

```
backend/
  app.py                    Flask API (POST /api/scan, GET /api/scans, ...)
  scan_service.py           Shared run-scanners-and-persist pipeline (used by app.py and monitor.py)
  monitor.py                Optional background thread for live/periodic scanning
  scanners/                 One module per check, each exposing scan() -> list[dict]
  ai/analyzer.py            Aggregates/scores/dedupes findings into a report
  reports/pdf.py            Renders a report to PDF (falls back to .txt without reportlab)
  rules/*.json              Signatures used by the process/port scanners
  rules/yara/*.yar          YARA rules used by yara_scanner
  utils/                    Hashing + scoring helpers
  database/                 SQLite schema + persistence (scans.db)
  Dockerfile                Backend image
frontend/                   React dashboard (create-react-app style)
  Dockerfile                Multi-stage build -> nginx (used by docker-compose.yml)
  nginx.conf                Serves the built app, proxies /api/* to the backend container
docker-compose.yml          Runs backend + frontend together (see "Running with Docker Compose")
```

## Running the backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

The API listens on `http://localhost:5000`. `psutil`, `reportlab`, and
`yara-python` are all optional: scanners fall back to `/proc`/`ss`/`systemctl`
parsing without `psutil`, PDF generation falls back to a plain-text report
without `reportlab`, and `yara_scanner` simply returns no findings (rather
than erroring) if `yara-python` isn't installed.

`backend/.env.example` lists every environment variable below in one place
(there's no dotenv loader, so it's a copy-paste reference, not something
auto-loaded - see the comment at its top for how to actually use it).

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

Scans are manual-only (`POST /api/scan`) unless you turn on live
monitoring - a background thread that scans on a fixed interval for as
long as the process runs:

```bash
MONITOR_INTERVAL_SECONDS=300 python3 app.py
```

`GET /api/monitor` reports whether it's running and at what interval; the
dashboard's "Live" toggle polls for newly completed scans (from the
monitor, a manual run, or any other client) and follows the latest one
automatically. This is a single in-process thread, not a real scheduler -
see the Limitations section above for what that means in practice.

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

## Running with Docker Compose

Runs both the backend and a production build of the frontend (served via
nginx, proxying `/api/*` to the backend container) together:

```bash
cp .env.example .env   # optional - only needed if you want an API key
docker compose up --build
```

The frontend is published at `http://localhost:3000`, the backend at
`http://localhost:5000`. `scans.db` persists across restarts in a named
volume (`scans-db`); the SQLite schema is (re-)initialized automatically
on first run.

Set `MONITOR_INTERVAL_SECONDS` in `.env` to have the backend container scan
on its own on a fixed interval, same as running natively (see "Running the
backend" above) - useful since a container has no other way to trigger a
scan except through the API.

Like a plain `docker run` (see above), this defaults to each container's
own **isolated** view of processes/network/filesystem, not your real
host - `docker-compose.yml` deliberately doesn't default to
`--pid=host`/`--network=host`/the `/etc/*` bind mounts, since that's a
much larger privilege footprint than a bare `docker compose up` should
silently opt you into. If you want real host visibility, add the
equivalent host/PID-namespace and volume settings from the "Running the
backend in Docker" section above to the `backend` service in
`docker-compose.yml` (same gaps apply: `permission_scanner` still only
sees the container's own binaries, and systemd-based checks still won't
work without a running systemd instance).

If you set `API_KEY` in `.env`, it's passed to the backend at runtime and
baked into the frontend at *build* time (Create React App inlines
`REACT_APP_*` vars when `npm run build` runs) - changing it later needs
`docker compose build frontend` (or `up --build`) to take effect, not
just a restart.

## Running tests

```bash
cd backend
source .venv/bin/activate
pip install pytest
pytest tests/ -v
```

```bash
cd frontend
npm install
CI=true npm test -- --watchAll=false
```

CI runs both of these on every push/PR via `.github/workflows/ci.yml`.
Frontend tests use Jest (via `react-scripts test`) and React Testing
Library; `App.test.js` mocks `./api` so component tests don't depend on a
running backend, while `api.test.js` mocks `fetch` directly to test the
request/auth-header/PDF-download logic in `api.js` itself.

## Running the frontend

```bash
cd frontend
npm install
npm start
```

This starts the dev server on `http://localhost:3000` and proxies `/api/*`
requests to the Flask backend on port 5000 (see `"proxy"` in
`frontend/package.json`).

If the backend has `API_KEY` set, copy `frontend/.env.example` to
`frontend/.env.local` and fill in the same value (Create React App only
exposes env vars prefixed `REACT_APP_`, and only picks up changes after
restarting `npm start`):

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
| GET    | `/api/monitor`          | Background monitor status (enabled, interval_seconds) |
| GET    | `/api/health`           | Health check                         |

## Extending

- Add a new check: create `backend/scanners/<name>.py` with a `scan()`
  function returning a list of finding dicts, then register it in
  `backend/scanners/__init__.py`'s `SCANNERS` dict.
- Add a new signature: edit the relevant JSON file under `backend/rules/`.
- Add a YARA rule: drop a `.yar`/`.yara` file into `backend/rules/yara/` -
  `yara_scanner` compiles every rule file in that directory automatically.
  Set `meta.severity` (`low`/`medium`/`high`/`critical`) and
  `meta.description` on a rule to control how a match is reported;
  otherwise it defaults to `high` with a generic description.
- Swap the scoring model: `backend/ai/analyzer.py` is currently rule-based
  (see `backend/utils/score.py`) — replace `summarize()` with an LLM call if
  you want narrative summaries instead of the templated one.

## License

MIT — see [LICENSE](LICENSE).
