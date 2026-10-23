// Pocket Packet Sniffer dashboard logic with Auth & Error Handling.

const POLL_INTERVAL_MS = 2000;

const STATUS_LABELS = {
  idle: "Idle",
  capturing: "Capturing",
  stopped: "Stopped",
  error: "Error",
};

const el = (id) => document.getElementById(id);

let currentUser = null;

// --- Auth Handling (Issue #14) ---

async function checkAuth() {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    if (data.authenticated && data.user) {
      currentUser = data.user;
      el("user-info").innerHTML = `Logged in: <strong>${currentUser.username}</strong> (${currentUser.role})`;
      el("auth-btn").textContent = "Logout";
      el("login-modal").style.display = "none";
    } else {
      currentUser = null;
      el("user-info").textContent = "Not authenticated";
      el("auth-btn").textContent = "Login";
    }
  } catch (err) {
    el("user-info").textContent = "Auth offline";
  }
}

el("auth-btn").addEventListener("click", async () => {
  if (currentUser) {
    // Logout
    await fetch("/api/auth/logout", { method: "POST" });
    await checkAuth();
  } else {
    // Toggle Login Dialog
    const modal = el("login-modal");
    modal.style.display = modal.style.display === "none" ? "grid" : "none";
  }
});

el("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = el("login-username").value.trim();
  const password = el("login-password").value;
  const errorEl = el("login-error");

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || "Authentication failed");
    }
    errorEl.style.display = "none";
    el("login-password").value = "";
    await checkAuth();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = "block";
  }
});

// --- Capture & Status Rendering ---

function render(data) {
  el("interface-name").textContent = data.interface.name;
  el("interface-type").textContent = data.interface.type;

  const status = data.capture.status;
  const badge = el("status-badge");
  badge.textContent = STATUS_LABELS[status] || "Unknown";
  badge.className = "badge badge-" + (STATUS_LABELS[status] ? status : "unknown");

  el("status-note").textContent = data.capture.started_at
    ? "Started: " + new Date(data.capture.started_at).toLocaleString()
    : "No capture in progress";
  el("start-button").disabled = status === "capturing";
  el("stop-button").disabled = status !== "capturing";
}

async function refresh() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error("HTTP " + res.status);
    render(await res.json());
    el("error-banner").hidden = true;
  } catch (err) {
    el("error-banner").hidden = false;
  }
}

function filters() {
  const params = new URLSearchParams();
  ["search", "protocol", "source", "destination"].forEach((field) => {
    const value = el(field + "-filter").value.trim();
    if (value) params.set(field, value);
  });
  return params;
}

function renderPackets(packets) {
  el("packet-count").textContent = `${packets.length} packet${packets.length === 1 ? "" : "s"}`;
  el("packet-list").innerHTML = packets.length
    ? packets.map((packet) => `<tr><td>${new Date(packet.timestamp).toLocaleTimeString()}</td><td><strong>${packet.protocol}</strong></td><td>${packet.source}</td><td>${packet.destination}</td><td>${packet.length} B</td><td>${packet.info}</td></tr>`).join("")
    : '<tr><td colspan="6">No packets match the current filters.</td></tr>';
}

async function refreshPackets() {
  const errEl = el("filter-error");
  try {
    const res = await fetch("/api/packets?" + filters());
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load packets");
    renderPackets(data.packets);
    errEl.style.display = "none";
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = "block";
    el("packet-list").innerHTML = '<tr><td colspan="6">Unable to load captured traffic.</td></tr>';
  }
}

async function changeCapture(action) {
  const message = el("capture-error");
  try {
    const res = await fetch("/api/capture/" + action, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Capture request failed");
    render(data);
    message.style.display = "none";
  } catch (err) {
    message.textContent = err.message;
    message.style.display = "block";
  }
}

el("start-button").addEventListener("click", () => changeCapture("start"));
el("stop-button").addEventListener("click", () => changeCapture("stop"));
el("filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  refreshPackets();
});
el("clear-filters").addEventListener("click", () => {
  el("filter-form").reset();
  el("filter-error").style.display = "none";
  refreshPackets();
});

// Initial boot
checkAuth();
refresh();
refreshPackets();
setInterval(refresh, POLL_INTERVAL_MS);
