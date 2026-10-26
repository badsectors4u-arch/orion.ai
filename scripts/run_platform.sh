#!/usr/bin/env bash
set -e

if [ ! -f .env ]; then
  echo ".env not found. Copy .env.example to .env and fill it in first."
  exit 1
fi

docker compose up --build -d
echo "Platform starting... open http://localhost"
