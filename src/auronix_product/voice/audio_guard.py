"""Audio guard: barge-in detection, echo/hallucination filtering, and resilient stream."""

from __future__ import annotations

import difflib
import re
import time

BARGE_IN_TRIGGERS = {
    "stop",
    "ruk ja",
    "ruk jao",
    "band karo",
    "quiet",
    "cancel",
    "chup",
}

HALLUCINATION_PHRASES = {
    "thank you for watching",
    "thanks for watching",
    "thanks for watching!",
    "please subscribe",
    "subscribe",
    "like and subscribe",
    "subtitles by",
    "amara.org",
    "thank you",
    "thank you.",
    "thank you very much",
    "thank you so much",
    "much appreciated",
    "thanks",
    "thanks.",
    "you",
    "the",
    "[music]",
    "(music)",
    "[applause]",
    "the end",
    "bye",
}

_BARGE_IN_PATTERN = re.compile(
    r"^(?:(?:okay|ok|hey|please|auronix)[,\s]+)*"
    r"(stop|ruk ja|ruk jao|band karo|quiet|cancel|chup)"
    r"(?:[,\s]+(?:please|now|karo))*$"
)


def is_barge_in_command(text: str) -> bool:
    """Return True when the utterance is a direct barge-in / stop command."""
    if not text:
        return False
    cleaned = text.lower().strip().rstrip(".!?, ")
    if cleaned in BARGE_IN_TRIGGERS:
        return True
    return bool(_BARGE_IN_PATTERN.fullmatch(cleaned))


def has_heavy_non_latin(text: str) -> bool:
    """Return True when >30% of characters are non-ASCII outside Devanagari/degree symbol."""
    if not text:
        return False
    bad = sum(
        1
        for c in text
        if ord(c) > 127 and not ("\u0900" <= c <= "\u097F") and c not in ("°",)
    )
    return (bad / len(text)) > 0.3


def should_discard_transcript(text: str, last_tts_text: str = "") -> bool:
    """Return True if transcript is empty/tiny, non-latin garbage, hallucination, or TTS echo."""
    if not text or len(text.strip()) < 2:
        return True
    if has_heavy_non_latin(text):
        return True
    stripped_punct = text.strip().strip(".!?,। \t\n")
    if len(stripped_punct) < 2:
        return True
    norm = stripped_punct.lower()
    if norm in HALLUCINATION_PHRASES or text.strip().lower() in HALLUCINATION_PHRASES:
        return True
    if last_tts_text and last_tts_text.strip():
        ratio = difflib.SequenceMatcher(
            None,
            norm,
            last_tts_text.strip().lower().rstrip(".!?, "),
        ).ratio()
        if ratio > 0.65:
            return True
    return False


class ResilientAudioStream:
    """PyAudio input wrapper with PaMacCore -50 recovery and device status reporting."""

    def __init__(self, rate: int = 16000, chunk: int = 1280):
        self.rate = rate
        self.chunk = chunk
        self.device_name = "Default Input"
        self.native_rate = rate
        self._pa = None
        self._stream = None
        self._open_stream()

    def _open_stream(self) -> None:
        import pyaudio

        if self._pa is None:
            self._pa = pyaudio.PyAudio()
        try:
            info = self._pa.get_default_input_device_info()
            if isinstance(info, dict):
                if info.get("name"):
                    self.device_name = str(info["name"])
                if info.get("defaultSampleRate"):
                    self.native_rate = int(float(info["defaultSampleRate"]))
        except Exception:
            pass
        self._stream = self._pa.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=self.rate,
            input=True,
            frames_per_buffer=self.chunk,
        )

    def _reopen_stream(self) -> None:
        if self._stream is not None:
            try:
                self._stream.stop_stream()
            except Exception:
                pass
            try:
                self._stream.close()
            except Exception:
                pass
            self._stream = None
        if self._pa is not None:
            try:
                self._pa.terminate()
            except Exception:
                pass
            self._pa = None
        self._open_stream()

    def read_chunk(self) -> bytes:
        """Read one chunk, retrying up to 3 times on CoreAudio -50 errors."""
        last_err: Exception | None = None
        for attempt in range(4):
            try:
                if self._stream is None:
                    self._open_stream()
                return self._stream.read(self.chunk, exception_on_overflow=False)
            except Exception as e:
                err_str = str(e)
                is_coreaudio_50 = (
                    "-50" in err_str
                    or getattr(e, "errno", None) == -50
                    or "pamaccore" in err_str.lower()
                )
                if not is_coreaudio_50 or attempt >= 3:
                    raise
                last_err = e
                time.sleep(0.25)
                self._reopen_stream()
        raise last_err  # pragma: no cover

    def get_audio_status_report(self) -> str:
        """Return a spoken description of active microphone device and sample rate."""
        khz = f"{(self.native_rate or self.rate) / 1000:g}"
        return f"Microphone is active. Input device is {self.device_name}. Sample rate is {khz} kilohertz."

    def close(self) -> None:
        """Cleanly close the PyAudio stream and terminate PyAudio."""
        if self._stream is not None:
            try:
                self._stream.stop_stream()
            except Exception:
                pass
            try:
                self._stream.close()
            except Exception:
                pass
            self._stream = None
        if self._pa is not None:
            try:
                self._pa.terminate()
            except Exception:
                pass
            self._pa = None


def get_audio_status_report() -> str:
    """Query default microphone device and sample rate safely."""
    stream = None
    try:
        stream = ResilientAudioStream()
        return stream.get_audio_status_report()
    except Exception as e:
        return f"Microphone status unavailable: {e}"
    finally:
        if stream is not None:
            stream.close()
