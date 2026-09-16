FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PRISMA_HOME_DIR=/app

# clamav/clamav-daemon: services/clamav_scanner.py talks to the daemon.
# libgl1/libglib2.0-0: required by opencv-python, imported via services/image_scanner.py.
RUN apt-get update && apt-get install -y --no-install-recommends \
        clamav \
        clamav-daemon \
        libgl1 \
        libglib2.0-0 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# clamav_scanner.py tries TCP 127.0.0.1:3310 before the Unix socket, so bind both.
# User root: the app hands clamd paths to 0600 temp files it wrote itself, which a
# clamd running as the clamav user cannot read.
RUN printf '%s\n' \
        'TCPSocket 3310' \
        'TCPAddr 127.0.0.1' \
        'LocalSocket /var/run/clamav/clamd.ctl' \
        'User root' \
        'Foreground false' \
        'MaxFileSize 100M' \
        'MaxScanSize 100M' \
        > /etc/clamav/clamd.conf \
    && printf '%s\n' \
        'DatabaseMirror database.clamav.net' \
        'CompressLocalDatabase yes' \
        > /etc/clamav/freshclam.conf \
    && mkdir -p /var/run/clamav /var/lib/clamav

# Bake the signature database into the image so a cold start does not wait on a
# ~250MB download. Non-fatal: the entrypoint refreshes and can recover at runtime.
RUN freshclam --quiet || echo "freshclam failed at build time; entrypoint will retry"

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# Generate against PRISMA_HOME_DIR=/app so the query engine is baked into the image.
COPY prisma ./prisma
RUN prisma py fetch && prisma generate

COPY . .
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
