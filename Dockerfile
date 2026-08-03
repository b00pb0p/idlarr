FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# idlarr.user.js is the TEMPLATE the /idlarr.user.js route fills in from live
# config — it is not a static asset. Leave it out and that route 500s with
# "cannot read the userscript template".
COPY app.py idlarr.user.js ./

# Runs as a non-root user. PUID defaults to 1001 (the usual NAS/appdata
# convention); override at build time if your host uses something else:
#   docker compose build --build-arg PUID=1000
# Whatever you pick must own the ./data and ./config bind mounts on the host,
# or startup dies with sqlite3.OperationalError: unable to open database file.
ARG PUID=1001
RUN useradd -u ${PUID} -m idlarr && mkdir -p /data && chown idlarr /data
USER idlarr

ENV IDLARR_DB=/data/idlarr.db \
    IDLARR_CONFIG=/config/trackers.yml \
    PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
