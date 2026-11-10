#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "Setting up Auronix..."
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .

echo "Installing system deps..."
brew install ffmpeg ollama 2>/dev/null || echo "(brew install skipped or failed)"

echo "Pulling LLM model..."
ollama pull qwen2.5:7b

echo ""
echo "Setup complete."
echo "Run: source .venv/bin/activate && ./scripts/dev.sh"

