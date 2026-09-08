FROM python:3.12-slim

LABEL org.opencontainers.image.title="Egyxos Scanner" \
      org.opencontainers.image.description="Authorized, modular security reconnaissance CLI" \
      org.opencontainers.image.source="https://github.com/zezo7amaad/Egyxos-Scanner"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/go/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
       ca-certificates \
       git \
       golang \
       nmap \
       sqlmap \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY egyxos ./egyxos

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . paramspider arjun

RUN useradd --create-home --uid 10001 egyxos \
    && mkdir -p /app/results /workspace \
    && chown -R egyxos:egyxos /app/results /workspace
USER egyxos
WORKDIR /workspace

ENTRYPOINT ["egyxos"]
CMD ["--help"]
