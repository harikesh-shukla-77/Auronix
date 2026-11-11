#!/bin/zsh
# Launch Auronix 2.0 Full-Stack Web Server + JARVIS Dashboard (and optional Voice Daemon)

set -u

REPO_DIR="/Users/harikeshshukla/Auronix"
VENV_DIR="${REPO_DIR}/.venv"
UVICORN_BIN="${VENV_DIR}/bin/uvicorn"
HOST="127.0.0.1"
PORT="8000"
URL="http://localhost:${PORT}"

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PYTHONUNBUFFERED=1
export PYTHONPATH="${REPO_DIR}/src"

cd "${REPO_DIR}" || exit 1

if [[ -f "${REPO_DIR}/.env" ]]; then
    set -a
    source "${REPO_DIR}/.env"
    set +a
fi

KEEPALIVE=false
OPEN_BROWSER=true
START_VOICE=false

for arg in "$@"; do
    case "${arg}" in
        --keepalive) KEEPALIVE=true ;;
        --no-browser) OPEN_BROWSER=false ;;
        --voice) START_VOICE=true ;;
    esac
done

# Ensure local Ollama service is running
if command -v ollama >/dev/null 2>&1 && ! pgrep -x "ollama" >/dev/null 2>&1; then
    ollama serve >/tmp/ollama.log 2>&1 &
    sleep 2
fi

UVICORN_PID=""
if lsof -i ":${PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[auronix] Backend already listening on ${URL}"
else
    echo "[auronix] Starting FastAPI backend on ${URL}..."
    "${UVICORN_BIN}" auronix_product.api.server:app --host "${HOST}" --port "${PORT}" \
        >>/tmp/auronix.log 2>>/tmp/auronix.err.log &
    UVICORN_PID=$!

    # Wait up to 10s for backend health readiness
    for _ in {1..20}; do
        if curl -sf "${URL}/api/status" >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
fi

if [[ "${START_VOICE}" == "true" ]]; then
    echo "[auronix] Starting headless voice daemon..."
    "${VENV_DIR}/bin/python" -u -m auronix_product --background \
        >>/tmp/auronix_voice.log 2>>/tmp/auronix_voice.err.log &
fi

if [[ "${OPEN_BROWSER}" == "true" ]]; then
    open "${URL}" >/dev/null 2>&1 || true
fi

if [[ "${KEEPALIVE}" == "true" && -n "${UVICORN_PID}" ]]; then
    wait "${UVICORN_PID}"
fi

