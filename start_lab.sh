#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

docker build -f Dockerfile.lab -t lab-creacion-dataset:local .

docker rm -f lab-creacion-dataset-ui >/dev/null 2>&1 || true
docker run --name lab-creacion-dataset-ui \
  -p 8000:8000 \
  -e VIRUSHARE_API_KEY="${VIRUSHARE_API_KEY:-}" \
  -e VIRUSHARE_INTERVAL_SECONDS="${VIRUSHARE_INTERVAL_SECONDS:-16}" \
  -e VIRUSHARE_URL_TEMPLATE="${VIRUSHARE_URL_TEMPLATE:-}" \
  -v "$(pwd)/data:/lab/data" \
  lab-creacion-dataset:local
