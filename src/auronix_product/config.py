"""Auronix configuration."""

from pathlib import Path

OLLAMA_URL = "http://localhost:11434"
# Default model. Switch at runtime via voice: "switch to smart"
# to use qwen2.5:14b, "switch to fast" to return to this.
OLLAMA_MODEL = "qwen2.5:7b"
WHISPER_MODEL = "mlx-community/whisper-large-v3-turbo"
WHISPER_LANGUAGE = "en"
PIPER_VOICE = "en_US-lessac-medium"
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
WAKE_THRESHOLD = 0.71
