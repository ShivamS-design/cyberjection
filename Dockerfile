# Cyberjection CLI + dashboard API image.
#
# Two-stage build: the `builder` stage installs the package (plus the
# optional `api`/`onnx`/`security` extras) into a self-contained virtual
# environment; the final stage copies only that venv into a slim runtime
# image, so build tooling (a C compiler, pip's own cache) never ships in
# the image that actually runs. Runs as a non-root user, per Task 10.3's
# "single trusted team, one instance" deployment model (see
# docs/DEPLOYMENT.md) -- this image has no built-in authentication layer,
# so it's meant to sit behind your own network perimeter/reverse proxy,
# not be exposed directly to the public internet.
#
# Build:  docker build -t cyberjection:0.10.0 .
# Run:    docker run --rm -p 8000:8000 -v cyberjection-data:/data \
#           -e CYBERJECTION_DB_URL=sqlite+aiosqlite:////data/results.db \
#           cyberjection:0.10.0 serve --host 0.0.0.0 --port 8000
#
# See docker-compose.yml for the full stack (API + dashboard) wired
# together with a named volume for persisted campaign history.

FROM python:3.12-slim AS builder

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY cyberjection ./cyberjection

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[api,security]"

FROM python:3.12-slim AS runtime

RUN groupadd --system cyberjection \
    && useradd --system --gid cyberjection --home-dir /app --create-home cyberjection

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CYBERJECTION_AUDIT_LOG=/data/audit.jsonl

WORKDIR /app
RUN mkdir -p /data && chown -R cyberjection:cyberjection /data /app
VOLUME ["/data"]
USER cyberjection

EXPOSE 8000
ENTRYPOINT ["cyberjection"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
