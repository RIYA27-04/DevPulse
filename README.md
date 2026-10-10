# DevPulse - Uptime & Latency Monitor (FastAPI)

Add any website or API URL; DevPulse checks it on a schedule and tracks **uptime %**,
**average latency** and **recent history** on a live dashboard. Think of a tiny self-hosted UptimeRobot.

Built with **Python 3.12, FastAPI, asyncio**, containerized with Docker, tested with pytest, CI on GitHub Actions.
Interactive API docs are generated automatically at `/docs` (Swagger UI).

## Features

- Add / remove monitors, "Check now", auto-refreshing dashboard with per-check latency chart (inline SVG)
- Background scheduler (asyncio task, default every 30 s) - blocking probes run in worker threads so the event loop never stalls
- Uptime %, average latency, last error, history of the last 100 checks per monitor
- Atomic JSON persistence (write to temp file + `os.replace`) and a flush on graceful shutdown
- `/healthz` endpoint and Docker `HEALTHCHECK`
- **Security**
  - **SSRF protection:** a monitoring tool fetches user-supplied URLs, so it blocks loopback, private LAN, link-local
    (including the cloud metadata address `169.254.169.254`), CGNAT and reserved ranges.
    Hostnames are resolved and validated at creation **and again right before connecting**; the probe then connects
    to the *validated IP itself* (keeping the correct Host header / TLS SNI), which defeats DNS-rebinding attacks.
  - Only `http(s)` URLs, no embedded credentials, URL length limit, Pydantic request validation
  - Per-IP sliding-window rate limiting on write endpoints (FastAPI dependency)
  - Security headers (CSP, `X-Frame-Options`, `nosniff`), non-root container user
  - All dynamic content is HTML-escaped in the frontend

## Run locally (Windows / macOS / Linux)

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8080
```

Open `http://localhost:8080` (dashboard) and `http://localhost:8080/docs` (API docs).

Optional: use a virtual environment first
(`python -m venv .venv`, then activate it: `.venv\Scripts\Activate.ps1` on Windows PowerShell, `source .venv/bin/activate` elsewhere).

### Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

`tests/test_core.py` (13 tests, standard library only) covers SSRF validation, the prober (up / down / refused / blocked),
statistics, persistence and limits. `tests/test_api.py` covers the HTTP API end to end with FastAPI's `TestClient`.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8080 | Used by the Docker image (`uvicorn --port`) |
| `CHECK_INTERVAL_SEC` | 30 | Seconds between checks (`0` disables the scheduler) |
| `MAX_MONITORS` | 20 | Cap on monitors |
| `DATA_FILE` | `./data/monitors.json` | Where state is stored |
| `ALLOW_PRIVATE` | off | `1` allows monitoring private IPs - local development only |

## Docker

```bash
docker build -t devpulse .
docker run -p 8080:8080 devpulse
```

## Deploy with Mini PaaS

In the Mini PaaS dashboard: name `devpulse`, repo `https://github.com/<you>/devpulse.git`,
branch `main`, port `8080`. Then open `http://devpulse.localhost:3000`.

> Container storage is ephemeral, so history resets on every redeploy.
> Production next step: mount a volume, or move the store to SQLite/PostgreSQL.

## API

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness probe |
| GET | `/api/info` | Version, uptime, monitor count |
| GET | `/api/monitors` | List monitors with computed stats |
| POST | `/api/monitors` | Create `{ "name": "...", "url": "https://..." }` |
| GET | `/api/monitors/{id}` | One monitor |
| POST | `/api/monitors/{id}/check` | Run a check immediately |
| DELETE | `/api/monitors/{id}` | Remove a monitor |

## Project structure

```
app/core.py          SSRF-safe validation, pinned-IP prober, thread-safe JSON store (stdlib only)
app/main.py          FastAPI app: routes, scheduler, rate limiter, security headers
static/index.html    dashboard (vanilla JS + SVG charts)
tests/               test_core.py (unittest-style) + test_api.py (pytest/TestClient)
Dockerfile           python:3.12-slim, non-root, healthcheck
.github/workflows/   CI: runs pytest on every push / pull request
```

## Resume entry (replace the [brackets] with your real numbers)

**DevPulse - Uptime & Latency Monitoring Service** | Python, FastAPI, asyncio, Docker, GitHub Actions | [GitHub] | [Live demo]
- Built a full-stack monitoring platform (FastAPI REST API + dashboard) that probes user-defined URLs on an asyncio scheduler and visualizes uptime %, average latency and per-check history in real time.
- Engineered SSRF protection (private/metadata IP blocking with connection-time DNS validation and IP pinning to defeat DNS rebinding), per-IP rate limiting, CSP headers and Pydantic input validation.
- Wrote [N] automated tests (pytest) run by a GitHub Actions CI pipeline; containerized with a non-root Docker image and health checks, with graceful-shutdown state flushing.
- Deployed through a self-built PaaS with zero-downtime releases; monitored [N] endpoints at [X]-second intervals with [Y]% measured uptime.
