"""STT with mlx-whisper + corrections + no false rejections."""

from __future__ import annotations
import re
import tempfile
import wave
import numpy as np
from .. import config

HALLUCINATIONS = {
    "thanks for watching", "thank you for watching", "please subscribe",
    "you", "bye", "[music]", "(music)", "[applause]", "the end",
    "subscribe", "like and subscribe", "thank you very much",
    "subtitles by", "amara.org", "thanks for watching!",
    "thank you", "thank you.", "thanks", "thanks.",
    "thank you so much", "much appreciated",
}

DOMAIN_PROMPT = (
    "Auronix assistant. Commands in English, Hindi, Hinglish. "
    "Examples: what is the time, time kya hai, what is the weather in Delhi, "
    "mausam kaisa hai, open Chrome, close Chrome, switch to dolphin, "
    "my name is Harikesh, what is my name, how are you, battery status, "
    "open spotify, close safari, find my file, khol do, band karo."
)

# Common Whisper mishearings → corrections
CORRECTIONS = {
    "queen": "qwen",
    "quean": "qwen",
    "quen": "qwen",
    "quinn": "qwen",
    "dolfin": "dolphin",
    "dolfn": "dolphin",
    "dolpin": "dolphin",
    "lama": "llama",
    "lamaa": "llama",
    "llamma": "llama",
    "mausum": "mausam",
    "mausom": "mausam",
    "wheather": "weather",
    "wether": "weather",
    "wheater": "weather",
    "crome": "chrome",
    "crhome": "chrome",
    "chorme": "chrome",
}

SPLIT_RE = re.compile(r"[,\n]")


def _filter_repeats(text: str) -> str:
    parts = [p.strip().rstrip(".!?") for p in SPLIT_RE.split(text) if p.strip()]
    if not parts:
        return ""
    counts: dict[str, int] = {}
    for p in parts:
        k = p.lower()
        counts[k] = counts.get(k, 0) + 1
    if max(counts.values()) > 2:
        return ""
    if len(parts) > 5 and len(counts) <= 2:
        return ""
    return text.strip()


def _apply_corrections(text: str) -> str:
    """Fix common Whisper mishearings."""
    words = text.split()
    corrected = []
    for w in words:
        lower = w.lower().strip(".,!?")
        if lower in CORRECTIONS:
            suffix = w[len(lower):] if len(w) > len(lower) else ""
            corrected.append(CORRECTIONS[lower] + suffix)
        else:
            corrected.append(w)
    return " ".join(corrected)


class STT:
    def __init__(self):
        self.model_name = "mlx-community/whisper-large-v3-mlx"
        self._ready = False

    def preload(self):
        if self._ready:
            return
        try:
            import mlx_whisper
            print(f"[stt] warming {self.model_name}...")
            silence = np.zeros(16000, dtype=np.float32)
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                with wave.open(f.name, "wb") as wf:
                    wf.setnchannels(1)
                    wf.setsampwidth(2)
                    wf.setframerate(16000)
                    wf.writeframes((silence * 32767).astype(np.int16).tobytes())
                mlx_whisper.transcribe(
                    f.name, path_or_hf_repo=self.model_name, verbose=False
                )
            self._ready = True
            print("[stt] ready")
        except Exception as e:
            print(f"[stt] warmup failed: {e}")

    def record(self, max_seconds: float = 12.0) -> np.ndarray:
        import pyaudio
        pa = pyaudio.PyAudio()
        stream = pa.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=config.SAMPLE_RATE,
            input=True,
            frames_per_buffer=1600,
        )
        frames = [stream.read(1600, exception_on_overflow=False) for _ in range(5)]
        total = 5
        speech_detected = False
        silent = 0
        try:
            while total < int(max_seconds * 10):
                chunk = stream.read(1600, exception_on_overflow=False)
                frames.append(chunk)
                total += 1
                a = np.frombuffer(chunk, dtype=np.int16).astype(np.float32) / 32768.0
                rms = float(np.sqrt((a ** 2).mean()))
                if rms > 0.008:
                    speech_detected = True
                    silent = 0
                elif speech_detected:
                    silent += 1
                    if silent >= 15:  # 2.5s silence
                        break
        finally:
            stream.stop_stream()
            stream.close()
            pa.terminate()
        if not speech_detected:
            return np.array([], dtype=np.float32)
        return (
            np.frombuffer(b"".join(frames), dtype=np.int16).astype(np.float32)
            / 32768.0
        )

    def _normalize(self, audio: np.ndarray) -> np.ndarray:
        rms = float(np.sqrt((audio ** 2).mean()))
        if rms < 0.001:
            return audio
        active = np.where(np.abs(audio) > rms * 0.4)[0]
        if len(active) > 0:
            audio = audio[
                max(0, active[0] - 3200) : min(len(audio), active[-1] + 3200)
            ]
        peak = float(np.abs(audio).max())
        if peak > 0.01:
            audio = audio * (0.5 / peak)
        return audio

    def transcribe(self, audio: np.ndarray) -> str:
        if len(audio) < 4800:
            return ""
        audio = self._normalize(audio)
        import mlx_whisper

        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            with wave.open(f.name, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(16000)
                wf.writeframes(
                    (np.clip(audio, -1, 1) * 32767).astype(np.int16).tobytes()
                )
            path = f.name

        # First try: auto language
        try:
            result = mlx_whisper.transcribe(
                path,
                path_or_hf_repo=self.model_name,
                initial_prompt=DOMAIN_PROMPT,
                condition_on_previous_text=False,
                temperature=0.0,
                no_speech_threshold=0.6,
                verbose=False,
            )
        except Exception as e:
            print(f"[stt] transcribe error: {e}")
            return ""

        text = result.get("text", "").strip()
        detected = result.get("language", "?")

        # RETRY LOGIC — if detected language is wrong, retry with target
        if text and detected in ("ur", "ar", "fa", "ps", "sd"):
            # Hindi speakers often detected as Urdu/Arabic
            try:
                result2 = mlx_whisper.transcribe(
                    path, path_or_hf_repo=self.model_name,
                    language="hi",
                    initial_prompt=DOMAIN_PROMPT,
                    condition_on_previous_text=False,
                    temperature=0.0,
                    no_speech_threshold=0.6,
                    verbose=False,
                )
                text2 = result2.get("text", "").strip()
                if text2 and len(text2.split()) >= len(text.split()) * 0.7:
                    text = text2
                    detected = "hi"
            except Exception:
                pass
        elif text and detected in ("pt", "es", "fr", "it", "ca", "ro"):
            # English speakers often detected as Romance languages on silence
            if len(text.split()) < 5:
                try:
                    result2 = mlx_whisper.transcribe(
                        path, path_or_hf_repo=self.model_name,
                        language="en",
                        initial_prompt=DOMAIN_PROMPT,
                        condition_on_previous_text=False,
                        temperature=0.0,
                        no_speech_threshold=0.6,
                        verbose=False,
                    )
                    text2 = result2.get("text", "").strip()
                    if text2 and len(text2.split()) >= len(text.split()) * 0.7:
                        text = text2
                        detected = "en"
                except Exception:
                    pass

        # Filter hallucinations
        if not text or text.lower().strip(".,!?") in HALLUCINATIONS:
            print(f"[stt] filtered: {text!r} (lang={detected})")
            return ""

        text = _filter_repeats(text)
        if not text or len(text) > 250:
            return ""

        text = _apply_corrections(text)
        print(f"[stt] heard (lang={detected}): {text!r}")
        return text

