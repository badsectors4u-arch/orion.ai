@echo off
if not exist .env (
  echo .env not found. Copy .env.example to .env and fill it in first.
  exit /b 1
)

docker compose up --build -d
echo Platform starting... open http://localhost
