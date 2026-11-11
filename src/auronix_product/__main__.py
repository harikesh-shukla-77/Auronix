import os
import warnings

os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import subprocess
import sys
from .core.agent import Agent


def warn_if_daemon_running(argv: list[str] | None = None) -> bool:
    """Warn terminal users if the LaunchAgent daemon (or another instance) is already running."""
    args = argv if argv is not None else sys.argv[1:]
    if "--background" in args or "PYTEST_CURRENT_TEST" in os.environ:
        return False

    daemon_pids: list[int] = []
    try:
        lc = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in lc.stdout.splitlines():
            if "com.auronix.assistant" in line:
                parts = line.split()
                if parts and parts[0].isdigit() and int(parts[0]) not in (os.getpid(), os.getppid()):
                    daemon_pids.append(int(parts[0]))
    except Exception:
        pass

    if not daemon_pids:
        try:
            pg = subprocess.run(
                ["pgrep", "-f", "auronix_product"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for tok in pg.stdout.split():
                if tok.isdigit() and int(tok) not in (os.getpid(), os.getppid()):
                    daemon_pids.append(int(tok))
        except Exception:
            pass

    if daemon_pids:
        pids_str = ", ".join(str(p) for p in daemon_pids)
        print(
            f"\n⚠️  WARNING: Auronix background daemon is already running (PID: {pids_str}).\n"
            "   Running a manual terminal instance concurrently will conflict on the microphone.\n"
            "   To run manually in terminal cleanly, unload the LaunchAgent first:\n"
            "     launchctl unload ~/Library/LaunchAgents/com.auronix.assistant.plist\n"
        )
        return True
    return False


def main():
    warn_if_daemon_running()
    text_mode = "--text" in sys.argv
    Agent().run(text_mode=text_mode)


if __name__ == "__main__":
    main()
