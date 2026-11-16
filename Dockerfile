# CertWatch Lab - Ubuntu 24.04 base, Python 3.12
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv curl ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/certwatch
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Non-root runtime user; data/ holds the sqlite db, ACME keys and certs.
RUN useradd --system --home /srv/certwatch certwatch \
    && mkdir -p /srv/certwatch/data \
    && chown -R certwatch:certwatch /srv/certwatch
USER certwatch

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# 2 sync workers: sized for the 2 vCPU / 2 GB VPS (scheduler runs separately).
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:8000", "--timeout", "120", "wsgi:app"]
