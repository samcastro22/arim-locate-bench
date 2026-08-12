FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pin to the exact commit immediately before the real fix for
# CVE-2026-32714 (SQL injection in KeyCache via str.format()).
RUN git clone --quiet https://github.com/scitokens/scitokens.git . && \
    git checkout --quiet 66b075c35da18f8364276553513a53c596b4b8e3

RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir pytest pytest-json-ctrf

WORKDIR /app
