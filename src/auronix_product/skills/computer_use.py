"""Stage 12 Computer Use skill: Vision-guided UI localization + gated pyautogui execution."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from PIL import Image

from ..actions import handlers
from ..brain.client import LLM
from ..core.logger import get_logger
from .vision import VisionSkill


def _parse_coordinates_json(raw: str) -> dict[str, Any]:
    """Extract {'x': int, 'y': int, 'found': bool} from minicpm-v response."""
    cleaned = raw.strip()
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    candidates = [m.group(0)] if m else [cleaned]
    for cand in candidates:
        try:
            data = json.loads(cand)
            if isinstance(data, dict) and "x" in data and "y" in data:
                return {
                    "x": int(round(float(data["x"]))),
                    "y": int(round(float(data["y"]))),
                    "found": bool(data.get("found", True)),
                }
        except Exception:
            pass
    # Regex fallback: e.g. "(420, 315)" or "x=420, y=315"
    xy_match = re.search(r"x\s*[:=]\s*(\d+(?:\.\d+)?)\D+y\s*[:=]\s*(\d+(?:\.\d+)?)", cleaned, re.IGNORECASE)
    if not xy_match:
        xy_match = re.search(r"\((\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\)", cleaned)
    if xy_match:
        return {
            "x": int(round(float(xy_match.group(1)))),
            "y": int(round(float(xy_match.group(2)))),
            "found": True,
        }
    return {"found": False, "x": 0, "y": 0}


class ComputerUseSkill:
    """Orchestrates vision-grounded click, type, and drag-and-drop with mandatory confirmation."""

    def __init__(
        self,
        *,
        llm: LLM | None = None,
        vision_skill: VisionSkill | None = None,
        logger=None,
    ) -> None:
        self.llm = llm or LLM()
        self.vision_skill = vision_skill or VisionSkill(llm=self.llm)
        self.logger = logger or get_logger("auronix.computer_use")

    def locate_on_screen(self, description: str, image_path: str | Path | None = None) -> dict[str, Any]:
        """Capture the screen, ask minicpm-v for target coordinates, and scale to desktop points."""
        import pyautogui

        img_path = Path(image_path) if image_path else Path(self.vision_skill.capture_screen())
        with Image.open(img_path) as im:
            img_w, img_h = im.size
        screen_w, screen_h = pyautogui.size()

        prompt = (
            f"Locate the UI element or target matching: '{description}'. "
            f"The image resolution is {img_w}x{img_h} pixels. "
            'Return ONLY valid JSON: {"found": true, "x": <pixel_x>, "y": <pixel_y>}.'
        )
        raw = self.vision_skill.analyze_screen(prompt, image_path=img_path)
        coords = _parse_coordinates_json(raw)
        if not coords.get("found"):
            return {"found": False, "x": 0, "y": 0, "raw": raw}

        scaled_x = int(round((coords["x"] / max(1, img_w)) * screen_w))
        scaled_y = int(round((coords["y"] / max(1, img_h)) * screen_h))
        scaled_x = max(0, min(int(screen_w) - 1, scaled_x))
        scaled_y = max(0, min(int(screen_h) - 1, scaled_y))
        return {"found": True, "x": scaled_x, "y": scaled_y, "raw_x": coords["x"], "raw_y": coords["y"]}

    def click(self, text_description: str, *, confirmed: bool = False) -> str:
        """Click the UI element matching text_description (requires explicit confirmation)."""
        if not confirmed:
            return f"Are you sure you want me to click '{text_description}'? Say 'Yes' to confirm."
        return handlers.click_on_screen(
            text_description,
            llm=self.llm,
            vision_skill=self.vision_skill,
        )

    def type_into_active(self, text: str, *, confirmed: bool = False) -> str:
        """Type text into the focused window (requires explicit confirmation)."""
        if not confirmed:
            return f"Are you sure you want me to type into the active window? Say 'Yes' to confirm."
        return handlers.type_text(text)

    def drag_drop(self, from_desc: str, to_desc: str, *, confirmed: bool = False) -> str:
        """Drag from one UI target to another (requires explicit confirmation)."""
        if not confirmed:
            return f"Are you sure you want me to drag '{from_desc}' to '{to_desc}'? Say 'Yes' to confirm."
        return handlers.drag_and_drop(
            from_desc,
            to_desc,
            llm=self.llm,
            vision_skill=self.vision_skill,
        )

