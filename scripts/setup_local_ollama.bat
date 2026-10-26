@echo off
where ollama >nul 2>nul
if %errorlevel% neq 0 (
  echo Ollama is not installed. Install it from https://ollama.com before continuing.
  exit /b 1
)

echo Pulling llama3 model...
ollama pull llama3

echo Done. Ollama is ready on http://localhost:11434