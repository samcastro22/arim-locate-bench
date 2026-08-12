FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pin to the exact commit immediately before the real fix for
# CVE-2026-21892 / GHSA-f2mf-q878-gh58 (SQL injection via '%' string
# formatting in the monitoring visualization views).
RUN git clone --quiet https://github.com/Parsl/parsl.git . && \
    git checkout --quiet 2c37ae3e75137095302dac5f9cd3ca956cb51a47

RUN pip install --no-cache-dir -e . --no-deps && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        "sqlalchemy>=2,<2.1" \
        "flask>=1.0.2" \
        flask_sqlalchemy \
        "pandas<3,>=2.2" \
        plotly \
        pydot \
        "networkx>=3.2,<3.3" \
        python-daemon \
        pytest \
        pytest-json-ctrf

WORKDIR /app
