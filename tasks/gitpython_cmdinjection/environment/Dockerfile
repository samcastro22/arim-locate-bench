FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN git config --global user.email "test@test" && \
    git config --global user.name "test" && \
    git config --global init.defaultBranch main

WORKDIR /app

# Pin to the exact commit immediately before the real fix for
# CVE-2026-42215 / GHSA-rpm5-65cw-6hj4 (unsafe-option bypass via
# underscored kwargs).
RUN git clone --quiet https://github.com/gitpython-developers/GitPython.git . && \
    git checkout --quiet da545232d0401fb9fb7660f9ff67991996674dda

RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir pytest pytest-json-ctrf

WORKDIR /app
