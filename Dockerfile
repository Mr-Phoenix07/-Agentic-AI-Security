# AEGIS — minimal, offline-capable image.
# The core needs no third-party packages; [extras] adds yaml/jinja2/requests for
# richer config and real (authorized) HTTP providers.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_HOME=/work

WORKDIR /work

# Install the package first (layer-cached) then copy source.
COPY pyproject.toml README.md LICENSE ./
COPY aegis ./aegis
RUN python -m pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[extras]"

COPY examples ./examples

# Non-root by default.
RUN useradd -m aegis && mkdir -p /work/aegis_runs && chown -R aegis /work
USER aegis

# `docker run aegis <subcommand> ...`  →  aegis run/demo/mutate/scope-check/agents
ENTRYPOINT ["aegis"]
CMD ["demo"]
