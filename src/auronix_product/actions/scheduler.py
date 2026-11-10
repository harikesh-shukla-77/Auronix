"""Background scheduler for reminders."""
import threading
import time
from ..core.memory import Memory
from ..voice.tts import TTS
from .. import config

class ReminderScheduler:
    def __init__(self, memory: Memory, tts: TTS):
        self.memory = memory
        self.tts = tts
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                due = self.memory.get_due_reminders()
                for item in due:
                    msg = f"Reminder: {item['task']}"
                    print(f"\n[REMINDER FIRED] {msg}\n")
                    self.tts.speak_async(msg)
            except Exception as e:
                print(f"[scheduler error] {e}")
            # Check every 10 seconds
            self._stop_event.wait(10.0)

