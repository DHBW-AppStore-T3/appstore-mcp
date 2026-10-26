FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv && /opt/venv/bin/pip install .

FROM python:3.12-slim
# Security fixes of Debian newer than the base image.
# SECURITY_REFRESH changes in every CI build (the workflow passes the run id), so the upgrade below never comes from
# the build cache: a cached layer keeps the package state of its first build and misses every fix released since.
ARG SECURITY_REFRESH
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data
COPY --from=build /opt/venv /opt/venv
# UID 10001, no shell login; /data is the only writable path (mount a volume there).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
ENTRYPOINT ["appstore-mcp"]
