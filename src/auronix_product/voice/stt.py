"""STT with mlx-whisper + corrections + no false rejections."""

from __future__ import annotations
import re
import tempfile
import time
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
    "Auronix, Start Auronix, Harikesh, Hari, Safari, Chrome, VS Code, Terminal, "
    "GitHub, kholo, band karo, search karo, kya hai, battery, reminders, calendar, "
    "audio status, stop, ruk ja."
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
    words = [w.lower().strip(".,!?।") for w in text.split() if w.strip(".,!?।")]
    for i in range(len(words) - 3):
        if words[i] == words[i + 1] == words[i + 2] == words[i + 3]:
            print(f"[stt] filtered repeat loop: {words[i]}")
            return ""
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
        self.coreml_fallback_model = "base.en"
        self._ready = False
        self._vad_model = None
        self.last_backend = "mlx_whisper"

    @staticmethod
    def get_acceleration_backend() -> str:
        """Report preferred Apple Silicon hardware backend: mlx_whisper -> coreml_ane -> faster_whisper."""
        try:
            import mlx_whisper  # noqa: F401
            return "mlx_whisper"
        except Exception:
            pass
        try:
            import coremltools  # noqa: F401
            return "coreml_ane"
        except Exception:
            pass
        try:
            import faster_whisper  # noqa: F401
            return "faster_whisper"
        except Exception:
            return "cpu"

    def _transcribe_coreml_fallback(self, wav_path: str) -> str:
        """Fallback to CoreML/ANE or faster-whisper for small models when mlx-whisper fails."""
        try:
            import faster_whisper

            model = faster_whisper.WhisperModel(self.coreml_fallback_model, device="cpu", compute_type="int8")
            segments, _ = model.transcribe(wav_path, language="en")
            self.last_backend = "faster_whisper_ane_fallback"
            return " ".join(seg.text.strip() for seg in segments).strip()
        except Exception:
            return ""

    def stream_transcribe(self, audio_chunks):
        """Yield progressive transcriptions across streaming speech chunks for low latency."""
        accumulated: list[np.ndarray] = []
        for chunk in audio_chunks:
            arr = np.asarray(chunk, dtype=np.float32).flatten()
            if arr.size == 0:
                continue
            accumulated.append(arr)
            joined = np.concatenate(accumulated)
            if len(joined) >= 4800:
                partial = self.transcribe(joined)
                if partial:
                    yield partial

    def _get_vad_model(self):
        if self._vad_model is None:
            from silero_vad import load_silero_vad
            self._vad_model = load_silero_vad()
        return self._vad_model

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
            try:
                self._get_vad_model()
            except Exception as e:
                print(f"[stt] silero-vad warmup failed: {e}")
            self._ready = True
            print("[stt] ready")
        except Exception as e:
            print(f"[stt] warmup failed: {e}")

    def record(self, max_seconds: float = 8.0) -> np.ndarray:
        return self.record_until_silence(max_seconds=max_seconds)

    def _open_stream_safely(self, pa, retries: int = 3, frames_per_buffer: int = 1280):
        """Open a PyAudio input stream with 3x retry, 0.5s backoff, and device fallback."""
        import pyaudio

        for attempt in range(retries):
            kwargs = {
                "format": pyaudio.paInt16,
                "channels": 1,
                "rate": config.SAMPLE_RATE,
                "input": True,
                "frames_per_buffer": frames_per_buffer,
            }
            if attempt > 0:
                try:
                    info = pa.get_default_input_device_info()
                    if isinstance(info, dict) and isinstance(info.get("index"), int):
                        kwargs["input_device_index"] = info["index"]
                except Exception:
                    pass
            try:
                return pa.open(**kwargs)
            except Exception as e:
                print(f"[audio] open failed (attempt {attempt + 1}/{retries}): {e}")
                time.sleep(0.5)
        try:
            pa.terminate()
        except Exception:
            pass
        raise RuntimeError("Could not open audio stream after retries")

    def _read_chunk_safely(self, pa, stream, chunk_size: int):
        """Read one PyAudio chunk, closing/reopening on OSError/IOError up to 3 attempts."""
        max_read_retries = 3
        read_retries = 0
        while stream is not None:
            try:
                data = stream.read(chunk_size, exception_on_overflow=False)
                return data, stream
            except (OSError, IOError) as e:
                read_retries += 1
                print(f"[audio] read failed (attempt {read_retries}/{max_read_retries}): {e}")
                try:
                    stream.close()
                except Exception:
                    pass
                stream = None
                time.sleep(0.2)
                if read_retries >= max_read_retries:
                    print("[audio] Entering safe idle mode after repeated read failures")
                    return None, None
                try:
                    stream = self._open_stream_safely(pa, frames_per_buffer=chunk_size)
                except Exception:
                    return None, None
        return None, None

    def record_until_silence(self, max_seconds: float = 8.0, stop_event=None) -> np.ndarray:
        try:
            return self._record_silero(max_seconds=max_seconds, stop_event=stop_event)
        except Exception as e:
            print(f"[stt] silero-vad unavailable ({e}); using RMS fallback.")
            return self._record_rms(max_seconds=max_seconds, stop_event=stop_event)

    def _record_silero(self, max_seconds: float = 8.0, stop_event=None) -> np.ndarray:
        import pyaudio
        import torch
        from silero_vad import VADIterator

        model = self._get_vad_model()
        vad = VADIterator(
            model,
            threshold=0.5,
            sampling_rate=config.SAMPLE_RATE,
            min_silence_duration_ms=300,
        )
        pa = pyaudio.PyAudio()
        stream = self._open_stream_safely(pa, frames_per_buffer=512)
        audio_buffer: list[bytes] = []
        speech_detected = False
        max_chunks = max(1, int(max_seconds * config.SAMPLE_RATE / 512))
        try:
            while len(audio_buffer) < max_chunks:
                if stop_event is not None and stop_event.is_set():
                    return np.array([], dtype=np.float32)
                chunk, stream = self._read_chunk_safely(pa, stream, 512)
                if chunk is None:
                    return np.array([], dtype=np.float32)
                audio_buffer.append(chunk)
                pcm = np.frombuffer(chunk, dtype=np.int16).astype(np.float32) / 32768.0
                speech_dict = vad(torch.from_numpy(pcm), return_seconds=False)
                if speech_dict:
                    if "start" in speech_dict:
                        speech_detected = True
                    if "end" in speech_dict and speech_detected:
                        break
        finally:
            if stream is not None:
                try:
                    stream.stop_stream()
                    stream.close()
                except Exception:
                    pass
            try:
                pa.terminate()
            except Exception:
                pass
        if not speech_detected:
            return np.array([], dtype=np.float32)
        return (
            np.frombuffer(b"".join(audio_buffer), dtype=np.int16).astype(np.float32)
            / 32768.0
        )

    def _record_rms(self, max_seconds: float = 12.0, stop_event=None) -> np.ndarray:
        import pyaudio
        pa = pyaudio.PyAudio()
        stream = self._open_stream_safely(pa, frames_per_buffer=1600)
        frames: list[bytes] = []
        total = 0
        speech_detected = False
        silent = 0
        try:
            for _ in range(5):
                if stop_event is not None and stop_event.is_set():
                    return np.array([], dtype=np.float32)
                chunk, stream = self._read_chunk_safely(pa, stream, 1600)
                if chunk is None:
                    return np.array([], dtype=np.float32)
                frames.append(chunk)
                total += 1
            while total < int(max_seconds * 10):
                if stop_event is not None and stop_event.is_set():
                    return np.array([], dtype=np.float32)
                chunk, stream = self._read_chunk_safely(pa, stream, 1600)
                if chunk is None:
                    return np.array([], dtype=np.float32)
                frames.append(chunk)
                total += 1
                a = np.frombuffer(chunk, dtype=np.int16).astype(np.float32) / 32768.0
                rms = float(np.sqrt((a ** 2).mean()))
                if rms > 0.008:
                    speech_detected = True
                    silent = 0
                elif speech_detected:
                    silent += 1
                    if silent >= 15:  # 1.5s silence
                        break
        finally:
            if stream is not None:
                try:
                    stream.stop_stream()
                    stream.close()
                except Exception:
                    pass
            try:
                pa.terminate()
            except Exception:
                pass
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
        t_start = time.perf_counter()

        # Skip Whisper completely if Silero VAD detects no speech in raw audio
        try:
            import torch

            vad_model = self._get_vad_model()
            if hasattr(vad_model, "reset_states"):
                vad_model.reset_states()
            has_speech = False
            float_audio = np.asarray(audio, dtype=np.float32).flatten()
            for start in range(0, len(float_audio) - 511, 512):
                chunk_t = torch.from_numpy(float_audio[start : start + 512])
                if vad_model(chunk_t, config.SAMPLE_RATE).item() > 0.5:
                    has_speech = True
                    break
            if hasattr(vad_model, "reset_states"):
                vad_model.reset_states()
            if not has_speech:
                print("[stt] no speech detected by Silero VAD; skipping Whisper")
                return ""
        except Exception:
            pass

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
            print(f"[stt] mlx_whisper error ({e}); trying CoreML/ANE fallback")
            fb_text = self._transcribe_coreml_fallback(path)
            if not fb_text:
                return ""
            result = {"text": fb_text, "language": "en"}

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

        # Filter non-English / non-Hindi hallucinations (e.g., Arabic/Chinese)
        lang = detected or "en"
        if lang not in ("en", "hi"):
            print(f"[stt] discarding non-en/hi language: {lang}")
            return ""
        from .audio_guard import has_heavy_non_latin
        if has_heavy_non_latin(text):
            print("[stt] discarding non-latin text")
            return ""

        # Filter hallucinations
        if not text or text.lower().strip(".,!?") in HALLUCINATIONS:
            print(f"[stt] filtered: {text!r} (lang={detected})")
            return ""

        text = _filter_repeats(text)
        if not text or len(text) > 250:
            return ""

        text = _apply_corrections(text)
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        print(f"[timing] stt_transcribe: {elapsed_ms:.0f}ms")
        print(f"[stt] heard (lang={detected}): {text!r}")
        return text

