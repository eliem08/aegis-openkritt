# Control-plane API image. Build:  docker build -t aegis-control-plane .
# Run:    docker run -p 8000:8000 --env-file .env aegis-control-plane
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8000

WORKDIR /app

# Install dependencies first (better layer caching).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[api]"

# Drop privileges.
RUN useradd --create-home --uid 10001 aegis
USER aegis

EXPOSE 8000

# Basic container healthcheck against the liveness probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f\"http://127.0.0.1:{os.environ.get('AEGIS_PORT','8000')}/healthz\"; \
sys.exit(0 if urllib.request.urlopen(url, timeout=2).status==200 else 1)"

CMD ["python", "-m", "aegis.api"]
