"""Stage 12 tests: 24/7 Lid-Closed PowerManager, streaming TTS/STT/Wake, Computer Use gates, DreamEngine, & benchmark."""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
import numpy as np
from PIL import Image

import auronix_product.api.server as server_mod
import auronix_product.core.agent as agent_mod
from auronix_product.core.memory import Memory
from auronix_product.core.power_manager import PowerManager
from auronix_product.skills.dream_engine import DreamEngine
from auronix_product.skills.self_coder import SelfCoder


def test_stage12_power_manager_toggles_and_dashboard_api(tmp_path, monkeypatch):
    calls: list[list[str]] = []
    popens: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    class _FakeProc:
        def __init__(self, cmd):
            popens.append(list(cmd))
            self.terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True

    pm = PowerManager(runner=fake_run, popen_fn=lambda cmd, **_kw: _FakeProc(cmd))
    res_on = pm.enable_lid_closed_mode()
    assert res_on["ok"] is True and res_on["enabled"] is True
    assert "drains battery" in res_on["warning"].lower()
    assert "osascript" in calls[0][0]
    assert calls[0][1:] == ["-e", 'do shell script "pmset -a disablesleep 1" with administrator privileges']
    assert "caffeinate" in popens[0][0] and "-i" in popens[0] and "-m" in popens[0]

    # Cancelling macOS password prompt fails closed and returns clear error
    denied_pm = PowerManager(
        runner=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="execution error: User canceled. (-128)"),
        popen_fn=lambda cmd, **_kw: _FakeProc(cmd),
    )
    res_denied = denied_pm.enable_lid_closed_mode()
    assert res_denied["ok"] is False and res_denied["needs_sudo"] is True
    assert "password was cancelled" in res_denied["error"].lower()
    assert "password was cancelled" in res_denied["message"].lower()
    assert denied_pm.lid_closed_enabled is False

    res_off = pm.disable_lid_closed_mode()
    assert res_off["ok"] is True and res_off["enabled"] is False
    assert "osascript" in calls[-1][0]
    assert calls[-1][1:] == ["-e", 'do shell script "pmset -a disablesleep 0" with administrator privileges']

    # Dashboard API + HTML check
    mem = Memory(db_path=tmp_path / "power_api.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.power_manager = pm
    monkeypatch.setattr(server_mod, "_probe_ollama", lambda _u: (True, ["qwen2.5:3b"]))
    client = TestClient(server_mod.create_app(agent=agent))

    assert "Always-On (Lid Closed)" in client.get("/").text
    assert client.post("/api/power/toggle", json={"enabled": True}).json()["enabled"] is True
    assert client.post("/api/power/toggle", json={"enabled": False}).json()["enabled"] is False

    # API error propagation when osascript fails/cancels
    agent.power_manager = denied_pm
    err_resp = client.post("/api/power/toggle", json={"enabled": True}).json()
    assert err_resp["ok"] is False
    assert "password was cancelled" in err_resp["error"].lower()
    assert "password was cancelled" in err_resp["message"].lower()


def test_stage12_streaming_tts_chunking_stt_backend_and_wake_gate(monkeypatch):
    from auronix_product.voice.stt import STT
    from auronix_product.voice.tts import TTS
    from auronix_product.voice.wake import OpenWakeWordGate

    tts = TTS()
    spoken_segments: list[str] = []
    monkeypatch.setattr(tts, "_speak_and_wait", lambda seg: spoken_segments.append(seg))

    def _token_gen():
        yield "Checking your Mac status right now, "
        yield "everything looks healthy. "
        yield "Let me know if you need more details."

    full = tts.speak_stream(_token_gen(), wait=True, early_clause_flush=True)
    assert "Checking your Mac status right now," in tts.streamed_sentences[0]
    assert len(tts.streamed_sentences) >= 2
    assert len(spoken_segments) == len(tts.streamed_sentences)
    assert tts.last_first_audio_ms >= 0.0
    assert full.startswith("Checking your Mac")

    # Hardware backend reporting (mlx_whisper active in env)
    assert STT().get_acceleration_backend() in ("mlx_whisper", "coreml_ane", "faster_whisper", "cpu")

    # OpenWakeWord energy gate suppresses near-silent noise before scoring
    gate = OpenWakeWordGate(energy_dbfs=-50.0, threshold=0.5)
    quiet = np.zeros(1600, dtype=np.float32) + 1e-4
    loud = np.ones(1600, dtype=np.float32) * 0.25
    assert gate.passes_energy_gate(quiet) is False
    assert gate.passes_energy_gate(loud) is True


def test_stage12_computer_use_scaled_click_and_confirmation_gate(tmp_path, monkeypatch):
    import pyautogui
    import auronix_product.core.agent as agent_mod

    img_file = tmp_path / "ui_screen.png"
    Image.new("RGB", (1000, 500), (10, 10, 10)).save(img_file)

    clicks: list[tuple[int, int]] = []
    typed: list[str] = []
    monkeypatch.setattr(pyautogui, "size", lambda: (2000, 1000))
    monkeypatch.setattr(pyautogui, "click", lambda x, y: clicks.append((x, y)))
    monkeypatch.setattr(pyautogui, "write", lambda txt, interval=0.02: typed.append(txt))

    mem = Memory(db_path=tmp_path / "cu.db")
    monkeypatch.setattr(agent_mod, "Memory", lambda: mem)
    agent = agent_mod.Agent()
    agent.vision_skill.capture_screen = MagicMock(return_value=str(img_file))
    agent.vision_skill.analyze_screen = MagicMock(return_value='{"found": true, "x": 250, "y": 125}')

    # Mandatory confirmation gate: click does NOT fire on first request
    confirm_prompt = agent._process("Auronix, click the submit button")
    assert "are you sure" in confirm_prompt.lower()
    assert clicks == []

    # Saying "Yes" executes scaled Vision -> pyautogui.click (250/1000*2000 = 500, 125/500*1000 = 250)
    exec_resp = agent._process("Yes")
    assert "Clicked" in exec_resp
    assert clicks == [(500, 250)]

    # Type security gate
    type_prompt = agent._process("type Hello Jarvis")
    assert "are you sure" in type_prompt.lower()
    assert typed == []
    assert "Typed" in agent._process("Yes")
    assert typed == ["Hello Jarvis"]


def test_stage12_dream_engine_sandbox_simulation_and_benchmark_script(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    import httpx

    _bench_path = Path("/Users/harikeshshukla/Auronix/scripts/benchmark_local_models.py")
    _bench_spec = importlib.util.spec_from_file_location("benchmark_local_models", str(_bench_path))
    _bench_mod = importlib.util.module_from_spec(_bench_spec)
    _bench_spec.loader.exec_module(_bench_mod)
    benchmark_model = _bench_mod.benchmark_model

    # Build real temp repo with failing baseline & passing counterfactual in DreamEngine sandbox
    src_dir = tmp_path / "src" / "auronix_product" / "actions"
    test_dir = tmp_path / "tests"
    src_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)

    target = src_dir / "calc.py"
    target.write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (test_dir / "test_calc.py").write_text(
        "from pathlib import Path\n"
        "import importlib.util\n"
        "_TARGET = Path(__file__).resolve().parents[1] / 'src' / 'auronix_product' / 'actions' / 'calc.py'\n"
        "_SPEC = importlib.util.spec_from_file_location('tmp_calc', str(_TARGET))\n"
        "_MOD = importlib.util.module_from_spec(_SPEC)\n"
        "_SPEC.loader.exec_module(_MOD)\n"
        "def test_add():\n"
        "    assert _MOD.add(2, 3) == 5\n",
        encoding="utf-8",
    )

    mem = Memory(db_path=tmp_path / "dream.db")
    mem.save_coding_outcome("calc.add bug", "Rejected patch for wrong sign", approved=False)

    fake_llm = MagicMock()
    fake_llm.chat.return_value = {
        "content": json.dumps(
            {
                "file": "src/auronix_product/actions/calc.py",
                "old_code": "return a - b",
                "new_code": "return a + b",
                "counterfactual": "What if add() summed operands instead of subtracting?",
                "heuristic": "Verify arithmetic operator semantics before proposing patches.",
            }
        )
    }
    coder = SelfCoder(repo_root=tmp_path, llm=fake_llm, memory=mem, backup_dir=tmp_path / "bak")
    dream = DreamEngine(
        memory=mem,
        self_coder=coder,
        repo_root=tmp_path,
        journal_path=tmp_path / "dream_journal.jsonl",
    )

    res = dream.run_dream_cycle(test_cmd=[sys.executable, "-m", "pytest", "tests/", "-q"])
    assert res["status"] == "consolidated"
    assert res["dreamed"] is True
    assert "Dream Journal" in res["journal_message"]
    assert len(mem.search_memory("Dream Journal")) >= 1
    assert "Verify arithmetic operator semantics" in coder.learned_heuristics[0]
    # Real workspace file was NOT mutated by sandbox simulation
    assert "return a - b" in target.read_text(encoding="utf-8")

    # Benchmark script calculation check
    fake_post = MagicMock(
        return_value=MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"eval_count": 100, "eval_duration": 2_000_000_000, "response": "ok"}),
        )
    )
    monkeypatch.setattr(httpx, "post", fake_post)
    b = benchmark_model("qwen2.5:3b", runs=1)
    assert b["ok"] is True and b["avg_tokens_per_sec"] == 50.0

