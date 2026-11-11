"""Text-to-speech with optional ElevenLabs J.A.R.V.I.S. API, dynamic Kokoro tone/pitch, and macOS say fallback."""

from __future__ import annotations
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time
import numpy as np


DEFAULT_ELEVENLABS_VOICE_ID = "onwK4e9ZLuTAKqWW03F9"  # Daniel (authoritative J.A.R.V.I.S.-like register)
DEFAULT_ELEVENLABS_MODEL_ID = "eleven_turbo_v2_5"

_URGENT_TONE_RE = re.compile(
    r"\b(?:boss|battery is low|starts in \d+ minutes|urgent|warning|alert|error|failed|"
    r"critical|blocked|rejected|emergency|immediately)\b",
    re.IGNORECASE,
)
_FOCUSED_TONE_RE = re.compile(
    r"\b(?:researching|patch|verified|summary|calendar|schedule|reminder|indexed|briefing)\b",
    re.IGNORECASE,
)
_CASUAL_TONE_RE = re.compile(
    r"\b(?:good morning|good evening|good afternoon|nice to meet|welcome|joke|"
    r"you're welcome|happy to|glad to|how are you|hey there|hi there)\b",
    re.IGNORECASE,
)


def _get_env_or_dotenv(key: str) -> str:
    """Resolve an API key from process env first, falling back to repo .env without mutating environ."""
    direct = os.environ.get(key, "").strip()
    if direct:
        return direct
    for candidate in (
        Path(__file__).resolve().parents[3] / ".env",
        Path.cwd() / ".env",
    ):
        if candidate.exists():
            try:
                for raw_line in candidate.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k.strip() == key:
                        return v.strip().strip("'\"")
            except Exception:
                pass
    return ""


def analyze_voice_tone(text: str, context: str | None = None) -> dict:
    """Choose dynamic speed, pitch shift (semitones), and ElevenLabs settings for response context."""
    hint = (context or "").strip().lower()
    low = text.lower()
    if hint in ("urgent", "alert") or _URGENT_TONE_RE.search(low):
        return {
            "tone": "urgent",
            "speed": 1.24,
            "pitch_semitones": 0.6,
            "stability": 0.72,
            "similarity_boost": 0.80,
            "style": 0.35,
            "say_rate": 205,
        }
    if hint in ("focused", "briefing", "technical") or _FOCUSED_TONE_RE.search(low):
        return {
            "tone": "focused",
            "speed": 1.12,
            "pitch_semitones": -0.35,
            "stability": 0.65,
            "similarity_boost": 0.78,
            "style": 0.25,
            "say_rate": 182,
        }
    if hint in ("casual", "warm") or _CASUAL_TONE_RE.search(low):
        return {
            "tone": "casual",
            "speed": 1.06,
            "pitch_semitones": 0.25,
            "stability": 0.45,
            "similarity_boost": 0.75,
            "style": 0.45,
            "say_rate": 175,
        }
    return {
        "tone": "neutral",
        "speed": 1.15,
        "pitch_semitones": 0.0,
        "stability": 0.55,
        "similarity_boost": 0.75,
        "style": 0.20,
        "say_rate": 185,
    }


def _apply_pitch_shift(audio: np.ndarray, semitones: float) -> np.ndarray:
    """Resample 1D float audio to apply subtle semitone pitch modulation when non-zero."""
    if abs(semitones) < 1e-3 or len(audio) < 16:
        return audio
    factor = 2.0 ** (semitones / 12.0)
    target_len = max(16, int(round(len(audio) / factor)))
    src_idx = np.linspace(0, len(audio) - 1, target_len, dtype=np.float32)
    shifted = np.interp(src_idx, np.arange(len(audio), dtype=np.float32), np.asarray(audio, dtype=np.float32))
    return shifted.astype(np.float32)


class TTS:
    def __init__(self, voice: str = "af_sky", elevenlabs_voice_id: str | None = None):
        self.voice = "af_sky" if not voice or voice == "en_US-lessac-medium" else voice
        self.elevenlabs_voice_id = elevenlabs_voice_id or _get_env_or_dotenv("ELEVENLABS_VOICE_ID") or DEFAULT_ELEVENLABS_VOICE_ID
        self._pipeline = None
        self._lock = threading.Lock()
        self._last_proc = None
        self._stop_requested = False
        self.last_spoken_text = ""
        self.last_tone: dict = analyze_voice_tone("")
        self.last_provider: str = "kokoro"

    def preload(self):
        """Warm Kokoro pipeline so first speak is fast."""
        try:
            from kokoro import KPipeline
            with self._lock:
                if self._pipeline is None:
                    self._pipeline = KPipeline(lang_code="a")
            print("[tts] kokoro ready")
        except Exception as e:
            print(f"[tts] kokoro unavailable: {e}")

    def speak_async(self, text: str, tone_context: str | None = None):
        """Non-blocking speak — starts TTS in background thread."""
        if not text.strip():
            return
        # Kill previous audio if still playing (interrupt behavior)
        self.stop()
        self._stop_requested = False
        self.last_spoken_text = text.strip()
        t = threading.Thread(target=self._speak_blocking, args=(text, tone_context), daemon=True)
        t.start()

    def speak(self, text: str, tone_context: str | None = None):
        """Blocking speak (kept for compatibility) with 250ms echo decay cooldown."""
        if not text.strip():
            return
        self.stop()
        self._stop_requested = False
        self.last_spoken_text = text.strip()
        self._speak_blocking(text, tone_context=tone_context)
        time.sleep(0.25)

    def _speak_and_wait(self, text: str, tone_context: str | None = None) -> None:
        """Speak one sentence and wait for audio playback before starting the next."""
        if not text.strip() or self._stop_requested:
            return
        self._speak_blocking(text, tone_context=tone_context)

    def speak_stream(self, text_generator, wait: bool = False) -> str:
        """Speak sentences on a worker thread as chunks arrive from a text generator."""
        self.stop()
        self._stop_requested = False
        sentence_q: queue.Queue[str | None] = queue.Queue()

        def _worker():
            while not self._stop_requested:
                item = sentence_q.get()
                if item is None or self._stop_requested:
                    break
                try:
                    self._speak_and_wait(item)
                except Exception as e:
                    print(f"[tts] stream error: {e}")

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()

        full_parts: list[str] = []
        buffer = ""
        try:
            for chunk in text_generator:
                if self._stop_requested:
                    break
                if not chunk:
                    continue
                full_parts.append(chunk)
                buffer += chunk
                parts = re.split(r"(?<=[.!?])\s+", buffer)
                if len(parts) > 1:
                    for sentence in parts[:-1]:
                        cleaned = sentence.strip()
                        if cleaned:
                            sentence_q.put(cleaned)
                    buffer = parts[-1]
        finally:
            tail = buffer.strip()
            if tail and not self._stop_requested:
                sentence_q.put(tail)
            sentence_q.put(None)

        full_text = "".join(full_parts).strip()
        if full_text:
            self.last_spoken_text = full_text
        if wait:
            try:
                worker.join(timeout=30.0)
            finally:
                try:
                    import sounddevice as sd
                    sd.stop()
                except Exception:
                    pass
        return full_text

    def stop(self) -> None:
        """Immediately halt any active TTS playback (subprocess or sounddevice stream)."""
        self._stop_requested = True
        if self._last_proc is not None:
            try:
                if self._last_proc.poll() is None:
                    self._last_proc.terminate()
            except Exception:
                pass
            self._last_proc = None
        try:
            import sounddevice as sd
            sd.stop()
        except Exception:
            pass
        subprocess.run(["killall", "afplay"], stderr=subprocess.DEVNULL)
        subprocess.run(["killall", "say"], stderr=subprocess.DEVNULL)

    def _stop_current(self):
        self.stop()

    def _speak_blocking(self, text: str, tone_context: str | None = None):
        if self._stop_requested:
            return
        if text.strip():
            self.last_spoken_text = text.strip()
        profile = analyze_voice_tone(text, context=tone_context)
        self.last_tone = profile

        elevenlabs_key = _get_env_or_dotenv("ELEVENLABS_API_KEY")
        has_devanagari = any("\u0900" <= c <= "\u097F" for c in text)
        if elevenlabs_key:
            try:
                self._speak_elevenlabs(text, elevenlabs_key, profile)
                self.last_provider = "elevenlabs"
                return
            except Exception as e:
                print(f"[tts] elevenlabs fail, falling back to kokoro/say: {e}")

        if not has_devanagari:
            try:
                self._speak_kokoro(text, profile=profile)
                self.last_provider = "kokoro"
                return
            except Exception as e:
                print(f"[tts] kokoro fail, fallback to say: {e}")
        self.last_provider = "say"
        self._speak_say(text, profile=profile)

    def _speak_elevenlabs(self, text: str, api_key: str, profile: dict | None = None) -> None:
        """Stream synthesized PCM/MP3 J.A.R.V.I.S. speech via ElevenLabs REST API."""
        import httpx
        import sounddevice as sd

        prof = profile or analyze_voice_tone(text)
        voice_id = _get_env_or_dotenv("ELEVENLABS_VOICE_ID") or self.elevenlabs_voice_id or DEFAULT_ELEVENLABS_VOICE_ID
        url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
        payload = {
            "text": text,
            "model_id": DEFAULT_ELEVENLABS_MODEL_ID,
            "voice_settings": {
                "stability": prof["stability"],
                "similarity_boost": prof["similarity_boost"],
                "style": prof["style"],
                "use_speaker_boost": True,
                "speed": min(1.2, max(0.8, prof["speed"])),
            },
        }
        headers = {
            "xi-api-key": api_key,
            "Accept": "audio/mpeg",
            "Content-Type": "application/json",
        }
        resp = httpx.post(
            url,
            params={"output_format": "pcm_24000"},
            json=payload,
            headers=headers,
            timeout=20.0,
        )
        resp.raise_for_status()
        if self._stop_requested:
            return
        content_type = resp.headers.get("content-type", "").lower()
        raw = resp.content
        if "mpeg" in content_type or raw[:3] == b"ID3":
            with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            try:
                self._last_proc = subprocess.Popen(["afplay", tmp_path])
                self._last_proc.wait()
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
            return

        pcm = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
        sd.stop()
        try:
            sd.play(pcm, samplerate=24000)
            sd.wait()
        finally:
            sd.stop()

    def _speak_kokoro(self, text: str, profile: dict | None = None):
        import sounddevice as sd
        from kokoro import KPipeline

        prof = profile or analyze_voice_tone(text)
        with self._lock:
            if self._pipeline is None:
                self._pipeline = KPipeline(lang_code="a")
            pipeline = self._pipeline

        t0 = time.perf_counter()
        first_chunk = True
        sd.stop()
        try:
            for _, _, audio in pipeline(text, voice=self.voice, speed=prof["speed"]):
                if self._stop_requested:
                    break
                if first_chunk:
                    print(f"[timing] tts_first_audio: {(time.perf_counter() - t0) * 1000:.0f}ms")
                    first_chunk = False
                modulated = _apply_pitch_shift(audio, prof["pitch_semitones"])
                sd.play(modulated, samplerate=24000)
                sd.wait()
        finally:
            sd.stop()

    def _speak_say(self, text: str, profile: dict | None = None):
        if self._stop_requested:
            return
        t0 = time.perf_counter()
        # Detect script: Devanagari = use Hindi voice
        has_devanagari = any("\u0900" <= c <= "\u097F" for c in text)
        if has_devanagari:
            voice = "Lekha"  # macOS Hindi voice
        else:
            voice = "Samantha"  # natural female English, handles Hinglish ok
        prof = profile or analyze_voice_tone(text)
        cmd = ["say", "-v", voice]
        if prof.get("tone") != "neutral":
            cmd.extend(["-r", str(prof["say_rate"])])
        cmd.append(text)
        self._last_proc = subprocess.Popen(cmd)
        print(f"[timing] tts_first_audio: {(time.perf_counter() - t0) * 1000:.0f}ms")
        self._last_proc.wait()

