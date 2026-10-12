# Deployment

Cyberjection runs as a plain Python application: the CLI, the dashboard
API and the built web dashboard are all served by one process started
with `cyberjection serve`. There are no container images; the project
ships no Dockerfile or compose file (they were removed in 0.11.0). If you
want to containerize or orchestrate it, wrap the commands on this page in
whatever runtime your organization uses.

## Deployment model: single trusted team, one instance

The dashboard API has no authentication of its own (see
`docs/COMPLIANCE.md`'s ASVS-V2/ASVS-V13 entries), and persistence is
SQLite by default. Everything here assumes **one Cyberjection instance
serving one trusted team**, inside a network perimeter that team already
controls: a VPN, an internal network, or a reverse proxy with its own
SSO/auth in front. It is not a multi-tenant deployment model. There is no
per-team data isolation, per-user login, or per-team rate limiting.

To require a token on the API, set `CYBERJECTION_API_TOKEN` (or pass
`--api-token`; prefer the variable, since command-line arguments are visible
to other local users). Every `/api/` request except `/api/health` must then
carry `Authorization: Bearer <token>`; the dashboard asks for it once and keeps
it in the tab's `sessionStorage`. `serve` prints a warning if it is bound to a
non-loopback address without a token.

If the dashboard must be reachable beyond a trusted team's own network,
put an authenticating reverse proxy (an OAuth2 proxy, or your cloud
provider's identity-aware proxy) in front of it first. Do not expose
`cyberjection serve`'s port directly to the public internet.

## 1. Install

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[api]"            # pulls in uvicorn
```

`serve` requires the `api` extra (`uvicorn`). Without it, the command
exits with a clear environment error (exit code 3) rather than a bare
`ImportError`.

## 2. Build the web dashboard (optional)

Requires Node.js 18+:

```bash
cd apps/dashboard
npm install
npm run build        # writes apps/dashboard/dist
```

## 3. Serve the API and the dashboard together

```bash
cyberjection serve --host 127.0.0.1 --port 8000 --dashboard-dir apps/dashboard/dist
```

Open `http://127.0.0.1:8000/` for the dashboard. The API is on the same
origin at `http://127.0.0.1:8000/api/...`, so the dashboard's relative
`/api/` fetches work with no proxy configuration. Without
`--dashboard-dir`, `serve` runs the API alone.

How `--dashboard-dir` behaves (`cyberjection/api/static.py`):

- `/api/...` always goes to the API. An unknown API path returns a JSON
  404, never the dashboard page.
- Any other path serves the matching file from the dashboard directory.
  Paths with no file extension (client-side routes such as
  `/campaigns/<id>`) fall back to `index.html`, so deep links and reloads
  work.
- Path traversal (`..`, encoded or backslash variants, NUL bytes) and
  symlinks pointing outside the directory are refused.
- Responses carry `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` and a same-origin `Content-Security-Policy`.
  `index.html` is never cached; Vite's content-hashed `assets/` files are
  cached as immutable.
- If the directory has no `index.html`, `serve` exits with a usage error
  telling you to build the dashboard first.

## Development

For dashboard development, run the API and Vite's hot-reloading dev
server side by side:

```bash
cyberjection serve --port 8000                  # terminal 1
cd apps/dashboard && npm run dev                 # terminal 2, http://127.0.0.1:5173
```

The dev server proxies `/api` to `http://127.0.0.1:8000` (see
`apps/dashboard/vite.config.ts`).

## Running as a service

Any process supervisor works. A minimal systemd unit:

```ini
[Unit]
Description=Cyberjection dashboard
After=network.target

[Service]
User=cyberjection
WorkingDirectory=/opt/cyberjection
Environment=CYBERJECTION_AUDIT_LOG=/var/lib/cyberjection/audit.jsonl
Environment=CYBERJECTION_DASHBOARD_DIR=/opt/cyberjection/apps/dashboard/dist
ExecStart=/opt/cyberjection/.venv/bin/cyberjection serve --host 127.0.0.1 --port 8000 \
  --db-url sqlite+aiosqlite:////var/lib/cyberjection/results.db
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/cyberjection

[Install]
WantedBy=multi-user.target
```

Run it as an unprivileged user, bind to `127.0.0.1`, and terminate TLS
in the reverse proxy in front of it.

## Redis (optional, distributed workers only)

Only needed if you run the Phase 7 distributed Celery workers
(`cyberjection/distributed/`). Neither the API nor the dashboard uses
it. Install Redis from your platform's package manager (for example
`apt install redis-server` or `brew install redis`), or use a managed
Redis service, then point `CYBERJECTION_CELERY_BROKER_URL` at it.

The unit tests don't need Redis at all; they use in-memory `fakeredis`
servers (see `docs/TESTING.md`).

## Configuration

| Variable / flag | Purpose |
|---|---|
| `cyberjection serve --db-url` | Database URL the API reads campaign history from (same format as `cyberjection run --db-url`). Defaults to the local SQLite results DB. |
| `--dashboard-dir` / `CYBERJECTION_DASHBOARD_DIR` | Built dashboard directory to serve on the same origin as the API. |
| `CYBERJECTION_AUDIT_LOG` | Where `cyberjection.security.audit_log.AuditLogger` writes. Defaults to `.cyberjection/audit.jsonl` in the working directory. |
| `CYBERJECTION_AUDIT_KEY` | Optional secret that turns the audit log into an HMAC chain; verify with `cyberjection audit --verify-log`. Keep it outside the log's host if you can. |
| `--api-token` / `CYBERJECTION_API_TOKEN` | Optional bearer token required on `/api/*` (except `/api/health`). |
| `CYBERJECTION_CELERY_BROKER_URL` | Redis URL for the optional distributed workers. |
| `HF_TOKEN`, `HF_ENDPOINT` | Hugging Face credentials and endpoint for HubGuard (Phase 11). The token is only ever sent to the Hub endpoint's own host. |

## What's not in scope

- **Authentication and multi-tenancy.** See "Deployment model" above.
  `docs/COMPLIANCE.md` tracks this as `PARTIAL` (ASVS-V2/ASVS-V13).
- **TLS termination.** `cyberjection serve` speaks plain HTTP. Put a
  TLS-terminating reverse proxy or load balancer in front of any
  deployment reachable over an untrusted network.
- **Horizontal scaling.** One process serves one team. Nothing here
  coordinates several API instances.
- **Database backups.** Nothing in this repository backs up the SQLite
  file. For PostgreSQL (`--db-url postgresql+asyncpg://...`), use your
  database provider's backup tooling.
