const API_BASE =
  window.location.origin && window.location.origin.startsWith("http")
    ? window.location.origin
    : "http://localhost:8000";
const CHAT_ENDPOINT = "http://localhost:8000/api/chat";
const EFFECTIVE_CHAT_URL =
  window.location.hostname === "localhost" && window.location.port === "8000"
    ? CHAT_ENDPOINT
    : `${API_BASE}/api/chat`;

const chatLogEl = document.getElementById("chat-log");
const commandFormEl = document.getElementById("command-form");
const commandInputEl = document.getElementById("command-input");
const sendBtnEl = document.getElementById("send-btn");
const arcReactorEl = document.getElementById("arc-reactor");
const reactorSubstateEl = document.getElementById("reactor-substate");
const coreStateTextEl = document.getElementById("core-state-text");

const statusGeminiEl = document.getElementById("status-gemini");
const statusOllamaEl = document.getElementById("status-ollama");
const statusDolphinEl = document.getElementById("status-dolphin");
const statusDbEl = document.getElementById("status-db");
const statusWsEl = document.getElementById("status-ws");

const metricCpuEl = document.getElementById("metric-cpu");
const metricRamEl = document.getElementById("metric-ram");
const metricBatEl = document.getElementById("metric-bat");
const metricDbSizeEl = document.getElementById("metric-db-size");

const memoryListEl = document.getElementById("memory-list");
const memoryCountEl = document.getElementById("memory-count");
const toggleTtsBtnEl = document.getElementById("toggle-tts-btn");
const toggleDaemonBtnEl = document.getElementById("toggle-daemon-btn");
const micInputBtnEl = document.getElementById("mic-input-btn");

let browserTtsEnabled = false;
let voiceDaemonActive = false;
let wsConn = null;

function setCoreState(state, label) {
  arcReactorEl.classList.remove("state-idle", "state-thinking", "state-speaking", "state-error");
  arcReactorEl.classList.add(`state-${state}`);
  reactorSubstateEl.textContent = (label || state).toUpperCase();
  coreStateTextEl.textContent = `AURONIX CORE: ${(label || state).toUpperCase()}`;
}

function appendMessage(role, text, metaExtra = "") {
  const wrap = document.createElement("div");
  wrap.className = `msg msg-${role}`;

  const meta = document.createElement("div");
  meta.className = "msg-meta";
  const nowStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  meta.textContent = `${role === "user" ? "HARIKESH" : "AURONIX"} • ${nowStr}${metaExtra ? ` • ${metaExtra}` : ""}`;

  const bubble = document.createElement("div");
  bubble.className = "msg-bubble";
  bubble.textContent = text;

  wrap.appendChild(meta);
  wrap.appendChild(bubble);
  chatLogEl.appendChild(wrap);
  chatLogEl.scrollTop = chatLogEl.scrollHeight;
}

function speakText(text) {
  if (!browserTtsEnabled || !("speechSynthesis" in window) || !text) return;
  try {
    window.speechSynthesis.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    utter.rate = 1.03;
    window.speechSynthesis.speak(utter);
  } catch {
    // Ignore speech synthesis errors on headless/unsupported browsers
  }
}

function setBadge(el, text, kind) {
  el.textContent = text;
  el.className = `badge badge-${kind}`;
}

async function fetchStatus() {
  try {
    const resp = await fetch(`${API_BASE}/api/status`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    const geminiActive = Boolean(data.models?.gemini?.active);
    setBadge(
      statusGeminiEl,
      geminiActive ? "ACTIVE" : "STANDBY (NO KEY)",
      geminiActive ? "ok" : "warn"
    );

    const ollamaActive = Boolean(data.models?.ollama?.active);
    const installed = data.models?.ollama?.installed || [];
    setBadge(statusOllamaEl, ollamaActive ? "ACTIVE" : "OFFLINE", ollamaActive ? "ok" : "err");

    const hasDolphin = installed.some((m) => m.includes("dolphin"));
    setBadge(statusDolphinEl, hasDolphin ? "ACTIVE" : ollamaActive ? "READY" : "OFFLINE", hasDolphin ? "ok" : "muted");

    const dbConn = Boolean(data.memory?.connected);
    setBadge(statusDbEl, dbConn ? "CONNECTED" : "DISCONNECTED", dbConn ? "ok" : "err");

    const sys = data.system || {};
    metricCpuEl.textContent = sys.cpu_percent != null ? `${sys.cpu_percent}%` : "--%";
    metricRamEl.textContent = sys.memory_percent != null ? `${sys.memory_percent}%` : "--%";
    metricBatEl.textContent = sys.battery_percent != null ? `${sys.battery_percent}%` : "AC";

    const bytes = Number(data.memory?.db_size_bytes || 0);
    metricDbSizeEl.textContent = `${(bytes / 1024).toFixed(1)} KB`;

    voiceDaemonActive = Boolean(data.voice?.daemon_active);
    toggleDaemonBtnEl.textContent = `🎙️ Mic Daemon: ${voiceDaemonActive ? "ON" : "OFF"}`;
    toggleDaemonBtnEl.classList.toggle("active", voiceDaemonActive);
  } catch (err) {
    setBadge(statusOllamaEl, "UNREACHABLE", "err");
    setBadge(statusDbEl, "UNKNOWN", "warn");
  }
}

async function fetchMemory() {
  try {
    const resp = await fetch(`${API_BASE}/api/memory?limit=10`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const items = data.items || [];
    memoryCountEl.textContent = String(data.count || 0);

    memoryListEl.innerHTML = "";
    if (!items.length) {
      memoryListEl.innerHTML = '<div class="memory-empty">No memories saved in SQLite yet.</div>';
      return;
    }

    for (const item of items) {
      const card = document.createElement("div");
      card.className = "memory-card";

      const top = document.createElement("div");
      top.className = "memory-card-top";
      const kindSpan = document.createElement("span");
      kindSpan.textContent = (item.kind || "memory").toUpperCase();
      const provSpan = document.createElement("span");
      provSpan.textContent = (item.provenance || "").toUpperCase();
      top.appendChild(kindSpan);
      top.appendChild(provSpan);

      const title = document.createElement("div");
      title.className = "memory-card-title";
      title.textContent = item.title || "Untitled";

      const body = document.createElement("div");
      body.className = "memory-card-body";
      body.textContent = item.content || "";

      card.appendChild(top);
      card.appendChild(title);
      card.appendChild(body);
      memoryListEl.appendChild(card);
    }
  } catch {
    memoryListEl.innerHTML = '<div class="memory-empty">Failed to load SQLite memories.</div>';
  }
}

async function sendCommand(text) {
  const clean = (text || "").trim();
  if (!clean) return;

  appendMessage("user", clean);
  commandInputEl.value = "";
  sendBtnEl.disabled = true;
  setCoreState("thinking", "THINKING");

  try {
    const resp = await fetch(EFFECTIVE_CHAT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: clean }),
    });
    if (!resp.ok) {
      throw new Error(`Server returned HTTP ${resp.status}`);
    }
    const data = await resp.json();
    const replyText = data.response || "Done.";
    const engineTag = data.gemini_active ? "GEMINI / ROUTER" : data.model || "OLLAMA";

    setCoreState("speaking", "RESPONDING");
    appendMessage("assistant", replyText, engineTag);
    speakText(replyText);

    await Promise.all([fetchStatus(), fetchMemory()]);
    setTimeout(() => setCoreState("idle", "READY"), 1200);
  } catch (err) {
    setCoreState("error", "ERROR");
    appendMessage("assistant", `Command error: ${err.message}`, "ERROR");
    setTimeout(() => setCoreState("idle", "READY"), 2000);
  } finally {
    sendBtnEl.disabled = false;
    commandInputEl.focus();
  }
}

function connectWebSocket() {
  const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsHost = window.location.host || "localhost:8000";
  try {
    wsConn = new WebSocket(`${wsProto}//${wsHost}/ws/voice`);
    wsConn.onopen = () => setBadge(statusWsEl, "CONNECTED", "ok");
    wsConn.onclose = () => {
      setBadge(statusWsEl, "RECONNECTING", "warn");
      setTimeout(connectWebSocket, 4000);
    };
    wsConn.onerror = () => setBadge(statusWsEl, "ERROR", "err");
    wsConn.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.event === "state" && msg.state) {
          setCoreState(msg.state, msg.state.toUpperCase());
        }
      } catch {
        // Ignore malformed WS telemetry
      }
    };
  } catch {
    setBadge(statusWsEl, "UNAVAILABLE", "muted");
  }
}

commandFormEl.addEventListener("submit", (e) => {
  e.preventDefault();
  sendCommand(commandInputEl.value);
});

document.querySelectorAll(".chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    const cmd = btn.getAttribute("data-cmd");
    if (cmd) sendCommand(cmd);
  });
});

document.getElementById("refresh-status-btn").addEventListener("click", fetchStatus);
document.getElementById("refresh-memory-btn").addEventListener("click", fetchMemory);

toggleTtsBtnEl.addEventListener("click", () => {
  browserTtsEnabled = !browserTtsEnabled;
  toggleTtsBtnEl.textContent = `🔊 Voice Output: ${browserTtsEnabled ? "ON" : "OFF"}`;
  toggleTtsBtnEl.classList.toggle("active", browserTtsEnabled);
});

toggleDaemonBtnEl.addEventListener("click", async () => {
  try {
    const resp = await fetch(`${API_BASE}/api/voice/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !voiceDaemonActive }),
    });
    const data = await resp.json();
    voiceDaemonActive = Boolean(data.daemon_active);
    toggleDaemonBtnEl.textContent = `🎙️ Mic Daemon: ${voiceDaemonActive ? "ON" : "OFF"}`;
    toggleDaemonBtnEl.classList.toggle("active", voiceDaemonActive);
    appendMessage("assistant", data.message || "Voice daemon state updated.", "VOICE");
  } catch (err) {
    appendMessage("assistant", `Voice toggle failed: ${err.message}`, "ERROR");
  }
});

micInputBtnEl.addEventListener("click", () => {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRec) {
    appendMessage("assistant", "Browser speech recognition unavailable here; type your command or toggle Mic Daemon.", "INFO");
    return;
  }
  const rec = new SpeechRec();
  rec.lang = "en-IN";
  rec.interimResults = false;
  micInputBtnEl.classList.add("recording");
  setCoreState("speaking", "LISTENING");
  rec.onresult = (event) => {
    const transcript = event.results?.[0]?.[0]?.transcript || "";
    if (transcript.trim()) sendCommand(transcript);
  };
  rec.onerror = () => setCoreState("idle", "READY");
  rec.onend = () => {
    micInputBtnEl.classList.remove("recording");
    setCoreState("idle", "READY");
  };
  rec.start();
});

fetchStatus();
fetchMemory();
connectWebSocket();
setInterval(() => {
  fetchStatus();
  fetchMemory();
}, 15000);
