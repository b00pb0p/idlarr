FROM python:3.13-alpine

# Alpine has a much smaller attack surface than Debian slim — fewer OS-level
# packages means fewer CVEs that have nothing to do with this application.
RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN pip install --no-cache-dir -r requirements.lock \
    && apk del gcc musl-dev libffi-dev

# idlarr.user.js is the TEMPLATE the /idlarr.user.js route fills in from live
# config — it is not a static asset.
COPY app.py idlarr.user.js ./

# Runs as a non-root user. PUID defaults to 1001; override at build time:
#   docker compose build --build-arg PUID=1000
ARG PUID=1001
RUN adduser -D -u ${PUID} idlarr \
    && mkdir -p /data /data/backups /config \
    && chown -R idlarr:idlarr /data /config
USER idlarr

VOLUME ["/data", "/config"]

ENV IDLARR_DB=/data/idlarr.db \
    IDLARR_CONFIG=/config/trackers.yml \
    PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
