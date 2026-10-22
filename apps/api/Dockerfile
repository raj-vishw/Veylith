# syntax=docker/dockerfile:1
FROM python:3.12.8-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --upgrade "pip>=26.2"
RUN useradd --system --uid 10001 --create-home veylith && mkdir -p /app /data && chown veylith:veylith /data
WORKDIR /app

# ---- production API / worker image: no dev tools, no WeasyPrint ----
FROM base AS prod
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY alembic.ini .
COPY alembic alembic
COPY app app
COPY scripts scripts
USER veylith
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

# ---- development / test image ----
FROM base AS dev
COPY requirements-dev.txt requirements.txt ./
RUN pip install -r requirements-dev.txt
COPY alembic.ini .
COPY alembic alembic
COPY app app
COPY scripts scripts
COPY tests tests
COPY pytest.ini .
USER veylith
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
