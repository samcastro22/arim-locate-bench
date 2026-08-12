FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pin to the exact commit immediately before the real fix for
# GHSA-655q-fx9r-782v / CVE-2025-1716 (pip.main() detection bypass).
RUN git clone --quiet https://github.com/mmaitre314/picklescan.git . && \
    git checkout --quiet 25d753f4b9a27ce141a43df3bf88d731800593d9

RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir pytest pytest-json-ctrf

WORKDIR /app
