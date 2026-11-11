"""Text-to-speech with Kokoro + macOS say fallback."""

from __future__ import annotations
import os
import queue
import re
import subprocess
import tempfile
import threading
import time


class TTS:
    def __init__(self, voice: str = "af_sky"):
        self.voice = "af_sky" if not voice or voice == "en_US-lessac-medium" else voice
        self._pipeline = None
        self._lock = threading.Lock()
        self._last_proc = None
        self._stop_requested = False
        self.last_spoken_text = ""

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

    def speak_async(self, text: str):
        """Non-blocking speak — starts TTS in background thread."""
        if not text.strip():
            return
        # Kill previous audio if still playing (interrupt behavior)
        self.stop()
        self._stop_requested = False
        self.last_spoken_text = text.strip()
        t = threading.Thread(target=self._speak_blocking, args=(text,), daemon=True)
        t.start()

    def speak(self, text: str):
        """Blocking speak (kept for compatibility) with 250ms echo decay cooldown."""
        if not text.strip():
            return
        self.stop()
        self._stop_requested = False
        self.last_spoken_text = text.strip()
        self._speak_blocking(text)
        time.sleep(0.25)

    def _speak_and_wait(self, text: str) -> None:
        """Speak one sentence and wait for audio playback before starting the next."""
        if not text.strip() or self._stop_requested:
            return
        self._speak_blocking(text)

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

    def _speak_blocking(self, text: str):
        if self._stop_requested:
            return
        if text.strip():
            self.last_spoken_text = text.strip()
        has_devanagari = any("\u0900" <= c <= "\u097F" for c in text)
        if not has_devanagari:
            try:
                self._speak_kokoro(text)
                return
            except Exception as e:
                print(f"[tts] kokoro fail, fallback to say: {e}")
        self._speak_say(text)

    def _speak_kokoro(self, text: str):
        import sounddevice as sd
        from kokoro import KPipeline

        with self._lock:
            if self._pipeline is None:
                self._pipeline = KPipeline(lang_code="a")
            pipeline = self._pipeline

        t0 = time.perf_counter()
        first_chunk = True
        sd.stop()
        try:
            for _, _, audio in pipeline(text, voice=self.voice, speed=1.15):
                if self._stop_requested:
                    break
                if first_chunk:
                    print(f"[timing] tts_first_audio: {(time.perf_counter() - t0) * 1000:.0f}ms")
                    first_chunk = False
                sd.play(audio, samplerate=24000)
                sd.wait()
        finally:
            sd.stop()

    def _speak_say(self, text: str):
        if self._stop_requested:
            return
        t0 = time.perf_counter()
        # Detect script: Devanagari = use Hindi voice
        has_devanagari = any("\u0900" <= c <= "\u097F" for c in text)
        if has_devanagari:
            voice = "Lekha"  # macOS Hindi voice
        else:
            voice = "Samantha"  # natural female English, handles Hinglish ok
        self._last_proc = subprocess.Popen(["say", "-v", voice, text])
        print(f"[timing] tts_first_audio: {(time.perf_counter() - t0) * 1000:.0f}ms")
        self._last_proc.wait()

