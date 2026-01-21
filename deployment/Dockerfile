FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Disable Python downloads to use the system interpreter across both images
ENV UV_PYTHON_DOWNLOADS=0

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
  --mount=type=bind,source=uv.lock,target=uv.lock \
  --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
  uv sync --locked --no-install-project --no-dev

COPY . /app

RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev

# Use final image without the uv
FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends netcat-openbsd \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chown=app:app /app /app

COPY /deployment/scripts /scripts
RUN chmod +x /scripts/*.sh
RUN sed -i 's/\r$//g' /scripts/entrypoint.sh
RUN sed -i 's/\r$//g' /scripts/wait_db.sh
RUN sed -i 's/\r$//g' /scripts/start-django-dev.sh
RUN sed -i 's/\r$//g' /scripts/start-django-prod.sh

ENV PATH="/app/.venv/bin:$PATH"
ENV DJANGO_SETTINGS_MODULE=config.settings

EXPOSE 8000

ENTRYPOINT ["/scripts/entrypoint.sh"]
