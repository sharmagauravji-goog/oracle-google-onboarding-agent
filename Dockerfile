# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for Oracle Database@Google Cloud Onboarding & Infrastructure Agent

FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create non-root user for secure container execution
RUN groupadd --gid 10001 odbagent && \
    useradd --uid 10001 --gid odbagent --shell /bin/bash --create-home odbagent

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=odbagent:odbagent agent ./agent
COPY --chown=odbagent:odbagent templates ./templates
COPY --chown=odbagent:odbagent pyproject.toml README.md ./

RUN mkdir -p /app/output && chown -R odbagent:odbagent /app/output

USER odbagent

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "agent/web.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
