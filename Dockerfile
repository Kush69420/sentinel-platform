# SENTINEL Platform — application image (gunicorn + wsgi.py).
#
# Runtime model is identical to deploy/sentinel.service, which this replaces for the
# containerised homelab deploy: one gunicorn process, gthread workers.
#   --workers 1  : _rate_limiter in app.py is an in-process sliding window with no
#                  shared store, so a second worker would multiply every configured
#                  limit by the worker count. Do not raise this until the limiter is
#                  moved to Redis/the DB (tracked in CLAUDE.md, Medium).
#   --threads 8  : lets several 600s /api/events SSE streams interleave with normal
#                  requests inside the single process.
#   --timeout 630: must exceed EVENT_STREAM_MAX_SECONDS (600) so the arbiter never
#                  recycles a worker mid-stream.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# curl is used by the compose healthcheck; nothing else needs a compiler because every
# pinned dependency (cryptography, reportlab, pillow) ships manylinux wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root. UID is fixed (not auto-assigned) because deploy/prepare-host.sh chowns the
# bind-mounted uploads directory to this exact UID on the host.
RUN groupadd --gid 10001 sentinel \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /app/uploads \
    && chown -R sentinel:sentinel /app/uploads
USER sentinel

EXPOSE 8000

CMD ["gunicorn", \
     "--worker-class", "gthread", "--workers", "1", "--threads", "8", \
     "--timeout", "630", "--graceful-timeout", "30", \
     "--bind", "0.0.0.0:8000", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "wsgi:app"]
