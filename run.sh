#!/usr/bin/env bash
# Rebuild both images from scratch (no cache) and restart the stack.
set -euo pipefail

cd "$(dirname "$0")"

echo "[run] building images with --no-cache"
docker compose build --no-cache

echo "[run] restarting stack (force-recreate)"
docker compose up -d --force-recreate

echo "[run] status:"
docker compose ps
