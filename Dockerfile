FROM python:3.12-slim

LABEL org.opencontainers.image.title="Egyxos Scanner" \
      org.opencontainers.image.description="Authorized, modular security reconnaissance CLI" \
      org.opencontainers.image.source="https://github.com/zezo7amaad/Egyxos-Scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY egyxos ./egyxos

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 egyxos
USER egyxos
WORKDIR /workspace

ENTRYPOINT ["egyxos"]
CMD ["--help"]
