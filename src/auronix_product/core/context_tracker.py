"""Short-term conversation context tracker for follow-up command resolution."""

from __future__ import annotations

from collections import deque
import re

BROWSER_APPS = {
    "safari",
    "chrome",
    "google chrome",
    "arc",
    "firefox",
    "brave",
    "edge",
    "microsoft edge",
}


class ConversationContext:
    """Tracks recent turns and active app/url/response entities for follow-up intents."""

    def __init__(self, max_turns: int = 10):
        self.turns: deque[dict] = deque(maxlen=max_turns)
        self.last_app: str | None = None
        self.last_url: str | None = None
        self.last_response: str = ""
        self.last_items = None

    def record_turn(
        self,
        user_text: str,
        assistant_text: str,
        app: str | None = None,
        url: str | None = None,
        items=None,
    ) -> None:
        """Record a user/assistant exchange and update active context pointers."""
        self.turns.append(
            {
                "user": user_text,
                "assistant": assistant_text,
                "app": app,
                "url": url,
                "items": items,
            }
        )
        if assistant_text:
            self.last_response = assistant_text
        if app:
            self.last_app = app
        if url:
            self.last_url = url
        if items is not None:
            self.last_items = items

    def resolve_followup(self, text: str) -> dict | None:
        """Resolve anaphoric or contextual follow-up utterances into structured intents."""
        if not text:
            return None
        lower = text.lower().strip().rstrip(".!?, ")

        if lower in (
            "wahi app dobara kholo",
            "wahi app kholo",
            "open it again",
            "open that again",
            "open that app again",
            "reopen it",
        ):
            if self.last_app:
                return {"intent": "open_app", "app": self.last_app}
            return None

        if lower in (
            "read previous one",
            "read the previous one",
            "repeat that",
            "say that again",
            "phir se bolo",
            "dobara bolo",
        ):
            if self.last_response:
                return {"intent": "read_last_response", "text": self.last_response}
            return None

        if lower in ("copy last response", "copy the last response", "copy that response"):
            if self.last_response:
                return {"intent": "copy_last_response", "text": self.last_response}
            return None

        if self.last_app and self.last_app.lower() in BROWSER_APPS:
            m = re.match(r"^(?:search(?:\s+for)?|khojo)\s+(.+)$", lower)
            if m:
                query = m.group(1).strip()
                if query:
                    return {
                        "intent": "browser_search_in_app",
                        "app": self.last_app,
                        "query": query,
                    }

        return None

