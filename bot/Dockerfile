FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# wireguard-tools gives us `wg genkey` / `wg pubkey` for keypair generation.
# docker.io CLI is not required (we use the docker Python SDK against the
# mounted unix socket), but keeping it out keeps the image small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wireguard-tools \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data
VOLUME ["/data"]

CMD ["python", "-m", "app.main"]
