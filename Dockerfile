FROM docker:29.6.1-cli AS docker_cli

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY services ./services
RUN pip install --no-cache-dir .

FROM python:3.12-slim

RUN useradd --create-home --uid 1000 gateway

WORKDIR /app
COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY services ./services
COPY sample_target ./sample_target
COPY policies ./policies
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts ./scripts

USER gateway
EXPOSE 8000
CMD ["uvicorn", "services.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
