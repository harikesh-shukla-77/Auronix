"""Wake-word detection (Heed ONNX) with Cmd+Shift+A hotkey fallback."""

from __future__ import annotations
import json
import math
import threading
import time
from pathlib import Path

try:
    from pynput import keyboard
    _OK = True
except ImportError:
    _OK = False

HOTKEY_DISPLAY = "Cmd+Shift+A"


class Hotkey:
    def __init__(self):
        self._event = threading.Event()
        self._mods: set[str] = set()

    def _on_press(self, key):
        try:
            if key in (keyboard.Key.cmd_l, keyboard.Key.cmd_r):
                self._mods.add("cmd")
            elif key in (keyboard.Key.shift_l, keyboard.Key.shift_r):
                self._mods.add("shift")
            elif hasattr(key, "char") and key.char and key.char.lower() == "a":
                if "cmd" in self._mods and "shift" in self._mods:
                    self._event.set()
                    return False
        except AttributeError:
            pass

    def _on_release(self, key):
        if key in (keyboard.Key.cmd_l, keyboard.Key.cmd_r):
            self._mods.discard("cmd")
        elif key in (keyboard.Key.shift_l, keyboard.Key.shift_r):
            self._mods.discard("shift")

    def wait(self) -> bool:
        if not _OK:
            raise RuntimeError("pynput not installed")
        self._event.clear()
        self._mods = set()
        listener = keyboard.Listener(on_press=self._on_press, on_release=self._on_release)
        listener.start()
        try:
            fired = self._event.wait()
        except KeyboardInterrupt:
            return False
        finally:
            listener.stop()
        return fired


class WakeWordDetector:
    """Always-on streaming wake word detector backed by a Heed ONNX export."""

    def __init__(
        self,
        model_path: str,
        config_path: str,
        threshold: float | None = None,
    ):
        import numpy as np
        import onnxruntime as ort
        import torch
        from heed.audio import StreamingHighpass
        from heed.gate import EnergyGate

        meta = json.loads(Path(config_path).read_text(encoding="utf-8"))
        self.phrase = str(meta.get("phrase", "Auronix"))
        self.sample_rate = int(meta.get("sample_rate", 16000))
        self.window_samples = int(meta.get("audio_window_samples", self.sample_rate))
        self.chunk_samples = max(1, int(self.sample_rate * 0.1))
        self.threshold = float(meta.get("threshold", 0.71) if threshold is None else threshold)

        trigger_cfg = meta.get("trigger", {})
        self.consecutive_frames = int(trigger_cfg.get("consecutive_frames", 2))
        self.refractory_seconds = float(trigger_cfg.get("refractory_seconds", 0.7))

        hpf_cfg = next(
            (op for op in meta.get("preprocessing", []) if op.get("op") == "highpass_filter"),
            {},
        )
        norm_cfg = next(
            (op for op in meta.get("preprocessing", []) if op.get("op") == "peak_normalize"),
            {},
        )
        self._target_dbfs = float(norm_cfg.get("target_dbfs", -3.0))

        gate_cfg = meta.get("energy_gate", {})
        self._hpf = StreamingHighpass(
            cutoff_hz=float(hpf_cfg.get("cutoff_hz", 100.0)),
            sample_rate=self.sample_rate,
            order=int(hpf_cfg.get("order", 8)),
            apply_mains_notch=bool(hpf_cfg.get("mains_notch_hz", [50.0, 60.0])),
        )
        self._gate = EnergyGate(
            energy_dbfs=float(gate_cfg.get("rms_threshold_dbfs", -55.0)),
            voice_band_min=float(gate_cfg.get("voice_band_min_fraction", 0.15)),
            sample_rate=self.sample_rate,
            band_lo_hz=float(gate_cfg.get("voice_band_lo_hz", 100.0)),
            band_hi_hz=float(gate_cfg.get("voice_band_hi_hz", 7000.0)),
        )

        self.session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self._np = np
        self._torch = torch
        self._buffer = torch.zeros(self.window_samples, dtype=torch.float32)
        self._above = 0
        self._last_trigger_time = -1e9

    def reset(self) -> None:
        """Clear rolling buffer and filter state between wake cycles."""
        self._buffer.zero_()
        self._hpf.reset()
        self._above = 0

    def process_chunk(self, audio_chunk, now: float | None = None) -> bool:
        """Process one float32 audio chunk and return True when the wake word triggers."""
        from heed.audio import log_mel, peak_normalize

        if self.session is None:
            return False
        if now is None:
            now = time.monotonic()

        chunk = self._np.asarray(audio_chunk, dtype=self._np.float32).flatten()
        if chunk.size == 0:
            return False

        filt_new = self._hpf(self._torch.from_numpy(chunk))
        n = filt_new.numel()
        if n >= self.window_samples:
            self._buffer = filt_new[-self.window_samples:].clone()
        else:
            self._buffer = self._torch.cat([self._buffer[n:], filt_new])

        passed, _ = self._gate(self._buffer)
        if not passed:
            self._above = 0
            return False

        normalized = peak_normalize(self._buffer, target_dbfs=self._target_dbfs)
        mel = log_mel(normalized, apply_cmn=True).numpy().astype(self._np.float32)
        raw_out = self.session.run(None, {self.input_name: mel})[0]
        logit = float(self._np.asarray(raw_out).flatten()[0])
        prob = 1.0 / (1.0 + math.exp(-max(-50.0, min(50.0, logit))))

        if prob > self.threshold:
            self._above += 1
        else:
            self._above = 0

        if (
            self._above >= self.consecutive_frames
            and (now - self._last_trigger_time) > self.refractory_seconds
        ):
            self._last_trigger_time = now
            self._above = 0
            return True
        return False

    def wait_for_wake(self) -> bool:
        import pyaudio

        self.reset()
        p = pyaudio.PyAudio()
        stream = p.open(
            rate=self.sample_rate,
            channels=1,
            format=pyaudio.paInt16,
            input=True,
            frames_per_buffer=self.chunk_samples,
        )
        print(f"Listening for wake word '{self.phrase}'...")
        try:
            while True:
                pcm = stream.read(self.chunk_samples, exception_on_overflow=False)
                audio = self._np.frombuffer(pcm, dtype=self._np.int16).astype(self._np.float32) / 32768.0
                if self.process_chunk(audio):
                    return True
        except KeyboardInterrupt:
            return False
        finally:
            stream.stop_stream()
            stream.close()
            p.terminate()

    def close(self) -> None:
        self.session = None

