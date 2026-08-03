ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[api,postgres]" "redis>=5.0,<6" \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin aegis
USER 10001:10001
ENTRYPOINT ["python", "-m"]
