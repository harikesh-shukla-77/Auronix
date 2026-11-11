"""Auronix configuration."""

import json
from pathlib import Path

OLLAMA_URL = "http://localhost:11434"
# Fast chit-chat model by default; switch to smart (qwen2.5:7b) for tools or "smart mode".
OLLAMA_MODEL = "qwen2.5:3b"
OLLAMA_SMART_MODEL = "qwen2.5:7b"
OLLAMA_DOLPHIN_MODEL = "dolphin-uncensored:latest"
GEMINI_MODEL = "gemini-2.5-flash"
SELF_CODER_BACKUP_DIR = "/tmp/auronix_self_coder_backup"
WHISPER_MODEL = "mlx-community/whisper-large-v3-turbo"
WHISPER_LANGUAGE = "en"
PIPER_VOICE = "en_US-lessac-medium"
KOKORO_VOICE = "af_sky"
SAMPLE_RATE = 16000

AURONIX_HOME = Path.home() / ".auronix"
AURONIX_HOME.mkdir(exist_ok=True)
DB_PATH = AURONIX_HOME / "auronix.db"

MAX_AUDIO_SECONDS = 10
SILENCE_RMS_THRESHOLD = 0.012
SILENCE_CHUNKS_TO_STOP = 25

_PRIMARY_EXPORT_DIR = Path.home() / "Auronix" / "export"
_NESTED_EXPORT_DIR = Path.home() / "Auronix" / "Auronix" / "export"
_WAKE_EXPORT_DIR = (
    _PRIMARY_EXPORT_DIR if (_PRIMARY_EXPORT_DIR / "wake.onnx").exists() else _NESTED_EXPORT_DIR
)
WAKE_ONNX_PATH = str(_WAKE_EXPORT_DIR / "wake.onnx")
WAKE_JSON_PATH = str(_WAKE_EXPORT_DIR / "wake.json")
WAKE_CONFIG_PATH = str(AURONIX_HOME / "config.json")
WAKE_SAMPLES_DIR = str(AURONIX_HOME / "wake_samples")


def _load_wake_threshold(default: float = 0.85) -> float:
    try:
        cfg_file = Path(WAKE_CONFIG_PATH)
        if cfg_file.exists():
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            if "wake_threshold" in data:
                return float(data["wake_threshold"])
    except Exception:
        pass
    return default


WAKE_THRESHOLD = _load_wake_threshold(0.85)

SFX_WAKE = "/System/Library/Sounds/Blow.aiff"
SFX_LISTENING = "/System/Library/Sounds/Tink.aiff"
SFX_SUCCESS = "/System/Library/Sounds/Glass.aiff"
SFX_ERROR = "/System/Library/Sounds/Basso.aiff"
