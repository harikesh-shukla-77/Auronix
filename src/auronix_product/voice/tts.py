"""Text-to-speech with Piper + macOS say fallback."""

from __future__ import annotations
import subprocess
import tempfile
import threading


class TTS:
    def __init__(self, voice: str = "en_US-lessac-medium"):
        self.voice = voice
        self._piper_ok = self._test_piper()
        self._voice_obj = None
        self._lock = threading.Lock()
        self._last_proc = None

    def _test_piper(self) -> bool:
        try:
            import piper  # noqa
            return True
        except ImportError:
            return False

    def preload(self):
        """Warm Piper model so first speak is instant."""
        if not self._piper_ok:
            return
        try:
            import piper
            with self._lock:
                if self._voice_obj is None:
                    self._voice_obj = piper.PiperVoice.load(self.voice)
            print("[tts] piper ready")
        except FileNotFoundError:
            # Piper voice not downloaded. Silent fallback to macOS say.
            self._piper_ok = False
        except Exception:
            self._piper_ok = False

    def speak_async(self, text: str):
        """Non-blocking speak — starts TTS in background thread."""
        if not text.strip():
            return
        # Kill previous audio if still playing (interrupt behavior)
        self._stop_current()
        t = threading.Thread(target=self._speak_blocking, args=(text,), daemon=True)
        t.start()

    def speak(self, text: str):
        """Blocking speak (kept for compatibility)."""
        if not text.strip():
            return
        self._stop_current()
        self._speak_blocking(text)

    def _stop_current(self):
        if self._last_proc is not None:
            try:
                if self._last_proc.poll() is None:
                    self._last_proc.terminate()
            except Exception:
                pass
            self._last_proc = None

    def _speak_blocking(self, text: str):
        if self._piper_ok:
            try:
                self._speak_piper(text)
                return
            except Exception:
                pass
        self._speak_say(text)

    def _speak_piper(self, text: str):
        import piper
        with self._lock:
            if self._voice_obj is None:
                self._voice_obj = piper.PiperVoice.load(self.voice)
            voice = self._voice_obj
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            out_path = f.name
        with open(out_path, "wb") as f:
            voice.synthesize(text, f)
        self._last_proc = subprocess.Popen(["afplay", out_path])

    def _speak_say(self, text: str):
        # Detect script: Devanagari = use Hindi voice
        has_devanagari = any("\u0900" <= c <= "\u097F" for c in text)
        if has_devanagari:
            voice = "Lekha"  # macOS Hindi voice
        else:
            voice = "Samantha"  # natural female English, handles Hinglish ok
        self._last_proc = subprocess.Popen(["say", "-v", voice, text])

