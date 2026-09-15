# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

# Optional corporate CA (e.g. behind an SSL-inspecting proxy - see
# app/llm/client.py's CA_BUNDLE for the same concern at runtime, backed by
# the same CA_BUNDLE_HOST_PATH). Mounted from an arbitrary host path
# (compose.yaml's `ca_bundle` build secret) only for this one RUN step -
# never copied into the build context or persisted in any layer. Where
# CA_BUNDLE_HOST_PATH is unset, the secret resolves to an empty file, the
# `-s` check is false, update-ca-certificates never runs, and this is a
# complete no-op: same build, same image, as if these two lines did not
# exist.
RUN --mount=type=secret,id=ca_bundle,target=/usr/local/share/ca-certificates/corporate-ca.crt \
    if [ -s /usr/local/share/ca-certificates/corporate-ca.crt ]; then update-ca-certificates; fi
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt

# The package is installed from pyproject.toml, so the sources are copied
# before the install. Changing app/ therefore reinstalls the dependencies;
# that costs a few seconds and keeps a single source of truth for them.
COPY pyproject.toml README.md ./
COPY app ./app
COPY scripts ./scripts
RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]


# Test image: dev dependencies on top of the real one, so tests run against the
# same base. Installed editable, and app/ and tests/ are bind-mounted by the
# `test` compose service, so a code change needs no rebuild.
FROM base AS test

RUN pip install --no-cache-dir -e ".[dev]"

CMD ["pytest"]
