set -e

echo "Checking for Ollama..."
if ! command -v ollama &> /dev/null; then
  echo "Ollama is not installed. Install it from https://ollama.com before continuing."
  exit 1
fi

echo "Pulling llama3 model..."
ollama pull llama3

echo "Done. Ollama is ready on http://localhost:11434"
