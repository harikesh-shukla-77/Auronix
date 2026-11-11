"""Local screen-capture and visual understanding skill powered by mss + Pillow + minicpm-v."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

from PIL import Image

from .. import config
from ..brain.client import LLM
from ..core.logger import get_logger

DEFAULT_SCREENSHOT_PATH = "/tmp/auronix_screen.png"
DEFAULT_VISION_MODEL = config.OLLAMA_VISION_MODEL


class VisionSkill:
    """Captures the active display via mss and analyzes it with Ollama minicpm-v:latest."""

    def __init__(
        self,
        llm: LLM | None = None,
        model: str = DEFAULT_VISION_MODEL,
        screenshot_path: str | Path = DEFAULT_SCREENSHOT_PATH,
        max_dimension: int = 1280,
        logger=None,
    ):
        self.llm = llm or LLM()
        self.model = model
        self.screenshot_path = Path(screenshot_path)
        self.max_dimension = max_dimension
        self.logger = logger or get_logger("auronix.vision")

    def capture_screen(self, output_path: str | Path | None = None) -> str:
        """Capture the primary screen via mss and save a resized PNG to /tmp/auronix_screen.png."""
        dest = Path(output_path or self.screenshot_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            import mss

            with mss.mss() as sct:
                monitor = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                shot = sct.grab(monitor)
                img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
                img.thumbnail((self.max_dimension, self.max_dimension), Image.Resampling.LANCZOS)
                img.save(dest, format="PNG")
            self.logger.info(f"Captured screen via mss to {dest} ({img.size[0]}x{img.size[1]})")
            return str(dest)
        except Exception as mss_err:
            self.logger.warn(f"mss capture failed ({mss_err}); falling back to macOS screencapture")
            screencapture_bin = shutil.which("screencapture") or "/usr/sbin/screencapture"
            subprocess.run([screencapture_bin, "-x", str(dest)], check=True, timeout=10)
            try:
                with Image.open(dest) as img:
                    img.thumbnail((self.max_dimension, self.max_dimension), Image.Resampling.LANCZOS)
                    img.save(dest, format="PNG")
            except Exception:
                pass
            return str(dest)

    def analyze_screen(
        self,
        prompt: str = "Describe what is on this screen.",
        *,
        image_path: str | Path | None = None,
        cleanup: bool = False,
    ) -> str:
        """Capture screen (unless image_path is given) and query minicpm-v:latest."""
        path: Path | None = Path(image_path) if image_path else None
        try:
            if path is None:
                path = Path(self.capture_screen())
            self.logger.info(f"Analyzing screen with {self.model}: {prompt[:80]!r}")
            reply = self.llm.vision_chat(prompt, str(path), model=self.model)
            return reply
        except Exception as exc:
            self.logger.error(f"Vision analysis failed: {exc}")
            return f"Screen analysis failed: {exc}"
        finally:
            if cleanup and image_path is None and path is not None and path.exists():
                try:
                    path.unlink()
                except Exception:
                    pass


def capture_screen(output_path: str | Path = DEFAULT_SCREENSHOT_PATH) -> str:
    """Capture screen via mss and save PNG to /tmp/auronix_screen.png."""
    return VisionSkill().capture_screen(output_path=output_path)


def analyze_screen(prompt: str = "Describe what is on this screen.", model: str = DEFAULT_VISION_MODEL) -> str:
    """Capture current screen and analyze it with Ollama minicpm-v:latest."""
    return VisionSkill(model=model).analyze_screen(prompt)

