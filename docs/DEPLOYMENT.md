# Deployment (Phase 10)

Cyberjection ships two ways to run the dashboard API and web dashboard
alongside the existing CLI: directly via `pip install` + `cyberjection
serve`, or as containers via the repo-root `Dockerfile` /
`apps/dashboard/Dockerfile` / `docker-compose.yml`. This page covers the
container path, the deployment model it assumes, and what's deliberately
out of scope.

## Deployment model: single trusted team, one instance

Every artifact in this phase -- the dashboard API's lack of
authentication (see `docs/COMPLIANCE.md`'s ASVS-V2/ASVS-V13 entries),
`docker-compose.yml`'s single `api` + `dashboard` (+ optional `redis`)
service set, the SQLite-by-default persistence layer -- assumes **one
Cyberjection instance serving one trusted team**, run inside a network
perimeter that team already controls (a VPN, an internal network, a
reverse proxy with its own SSO/auth in front). It is not a multi-tenant
SaaS deployment model: there is no per-team data isolation, no
per-user login, no per-team billing or rate limiting anywhere in this
codebase.

If your threat model requires exposing the dashboard beyond a trusted
team's own network, put an authenticating reverse proxy (e.g. an
OAuth2 proxy, or your cloud provider's identity-aware proxy) in front of
it first -- do not expose `cyberjection serve`'s port directly to the
public internet.

## Running via Docker Compose

```bash
docker compose up --build
```

This builds and starts two services:

- **`api`** (`Dockerfile`, port `8000`): the CLI image, running
  `cyberjection serve --host 0.0.0.0 --port 8000 --db-url
  sqlite+aiosqlite:////data/results.db`. Campaign history persists in the
  `cyberjection-data` named volume.
- **`dashboard`** (`apps/dashboard/Dockerfile`, port `3000`): the built
  React SPA served by nginx, which proxies `/api/` to the `api` service
  (see `apps/dashboard/nginx.conf`).

Open `http://localhost:3000` for the dashboard, or call the API directly
at `http://localhost:8000/api/...`.

To also start the Phase 7 Redis broker (only needed if you're running
distributed Celery workers against `cyberjection/distributed/` --
see `docs/ARCHITECTURE.md`'s "distributed queue remains unwired" note;
neither the API nor the dashboard requires it):

```bash
docker compose --profile distributed up --build
```

Stop everything and remove the persisted database with:

```bash
docker compose down -v
```

## Running without Docker

```bash
pip install "cyberjection[api]"     # pulls in uvicorn
cyberjection serve --host 0.0.0.0 --port 8000
```

`serve` requires the `api` extra (`uvicorn`); without it, the command
exits with a clear environment error rather than a bare `ImportError`
(the same degrade-gracefully contract `cyberjection inspect` already
uses for a missing SQLAlchemy install -- see
`cyberjection.api.server.UvicornUnavailableError`).

For the dashboard itself outside a container:

```bash
cd apps/dashboard
npm install
npm run build   # outputs apps/dashboard/dist -- serve it with any static file server
```

or `npm run dev` for a hot-reloading dev server (proxies `/api` to
`http://127.0.0.1:8000` -- see `apps/dashboard/vite.config.ts`).

## Configuration

| Variable / flag | Where | Purpose |
|---|---|---|
| `cyberjection serve --db-url` | CLI, or the `api` service's `command:` in `docker-compose.yml` | Database URL the API reads campaign history from (same format as `cyberjection run --db-url`); the compose file bakes in `sqlite+aiosqlite:////data/results.db` by default. |
| `API_UPSTREAM` | `apps/dashboard/Dockerfile` / nginx env | Where the dashboard's nginx proxy forwards `/api/` requests; defaults to `http://cyberjection-api:8000`, the compose service name. |
| `CYBERJECTION_AUDIT_LOG` | CLI / Dockerfile `ENV` | Where `cyberjection.security.audit_log.AuditLogger` writes; defaults to `/data/audit.jsonl` in the container image. |

## What's not in scope

- **Authentication and multi-tenancy.** See "Deployment model" above --
  this is a deliberate scope boundary for Phase 10, not an oversight.
  `docs/COMPLIANCE.md` tracks it as `PARTIAL` (ASVS-V2/ASVS-V13), not
  `IMPLEMENTED`.
- **TLS termination.** Neither the API nor the dashboard's nginx config
  terminates TLS itself; put a TLS-terminating reverse proxy or load
  balancer in front in any deployment reachable over an untrusted
  network.
- **Horizontal scaling / orchestration manifests.** `docker-compose.yml`
  is a single-host deployment. A Kubernetes/Helm deployment is possible
  (the images are plain OCI images with no compose-specific assumptions
  baked in) but no manifests are provided; the "single trusted team, one
  instance" model this phase targets doesn't call for one.
- **Database backups.** The named Docker volume persists data across
  container restarts, but nothing in this repository automates backing
  it up. For a PostgreSQL deployment (`--db-url
  postgresql+asyncpg://...`), use your database provider's own backup
  tooling.
