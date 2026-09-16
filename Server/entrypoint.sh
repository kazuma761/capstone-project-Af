#!/bin/sh
set -e

PORT="${PORT:-8000}"
CLAMD_STARTUP_TIMEOUT="${CLAMD_STARTUP_TIMEOUT:-180}"

if [ "${ENABLE_CLAMAV:-true}" = "true" ]; then
    echo "==> Refreshing ClamAV signatures"
    freshclam --quiet || echo "    freshclam failed; using signatures baked into the image"

    echo "==> Starting clamd"
    clamd &

    # ScannerRouter builds ClamAVScanner at import time, so clamd has to be
    # answering before uvicorn starts or the scanner falls back for the life of
    # the process. Loading the signature database takes ~60-90s.
    i=0
    while [ "$i" -lt "$CLAMD_STARTUP_TIMEOUT" ]; do
        if clamdscan --ping 1 >/dev/null 2>&1; then
            echo "==> clamd ready after ${i}s"
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    if [ "$i" -ge "$CLAMD_STARTUP_TIMEOUT" ]; then
        echo "==> clamd not ready after ${CLAMD_STARTUP_TIMEOUT}s; starting API without it"
    fi
else
    echo "==> ENABLE_CLAMAV=false; skipping clamd"
fi

exec uvicorn main:app --host 0.0.0.0 --port "$PORT"
