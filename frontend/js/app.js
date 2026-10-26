// Pocket Packet Sniffer dashboard logic with Auth, Traffic Stats & Error Handling.

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

// --- Interface Detection & Selection (Issue #4, FR-02) ---

let availableInterfaces = [];

async function loadInterfaces() {
  const errEl = el("interface-error");
  try {
    const res = await fetch("/api/interfaces");
    if (!res.ok) throw new Error("Failed to load interfaces");
    const raw = data.interfaces || {};
    availableInterfaces = Array.isArray(raw) ? raw : Object.values(raw);

    const select = el("interface-select");
    select.innerHTML = availableInterfaces
      .map((iface) => `<option value="${iface.name}" ${iface.selected ? "selected" : ""}>${iface.name} (${iface.type})</option>`)
      .join("");

    updateInterfaceDetails(data.selected);
    if (errEl) errEl.style.display = "none";
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message;
      errEl.style.display = "block";
    }
  }
}

function updateInterfaceDetails(ifaceName) {
  const iface = availableInterfaces.find((i) => i.name === ifaceName);
  if (!iface) return;
  el("interface-name").textContent = iface.name;
  el("interface-type").textContent = iface.type;
  const extra = iface.details ? `Details: ${iface.details}` : (iface.speed ? `Speed: ${iface.speed}` : "");
  el("interface-details").textContent = extra;
}

async function selectInterface(ifaceName) {
  const errEl = el("interface-error");
  try {
    const res = await fetch("/api/interfaces/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: ifaceName })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to switch interface");
    updateInterfaceDetails(ifaceName);
    if (errEl) errEl.style.display = "none";
  } catch (err) {
    if (errEl) {
      errEl.textContent = err.message;
      errEl.style.display = "block";
    }
    // Revert select dropdown to actual active interface
    refresh();
  }
}

// --- Capture & Status Rendering ---

function render(data) {
  el("interface-name").textContent = data.interface.name;
  el("interface-type").textContent = data.interface.type;

  const select = el("interface-select");
  if (select && select.value !== data.interface.name) {
    select.value = data.interface.name;
  }
  updateInterfaceDetails(data.interface.name);

  const status = data.capture.status;
  const badge = el("status-badge");
  badge.textContent = STATUS_LABELS[status] || "Unknown";
  badge.className = "badge badge-" + (STATUS_LABELS[status] ? status : "unknown");

  el("status-note").textContent = data.capture.started_at
    ? "Started: " + new Date(data.capture.started_at).toLocaleString()
    : "No capture in progress";
  el("start-button").disabled = status === "capturing";
  el("stop-button").disabled = status !== "capturing";
  if (select) select.disabled = status === "capturing";
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

// --- Traffic Statistics Rendering (Issue #7, FR-05, FR-6) ---

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return bytes + " B";
  const kb = bytes / 1024;
  if (kb < 1024) return kb.toFixed(1) + " KB";
  return (kb / 1024).toFixed(1) + " MB";
}

async function refreshStats() {
  try {
    const res = await fetch("/api/capture/stats");
    if (!res.ok) return;
    const stats = await res.json();

    if (el("stat-total-packets")) el("stat-total-packets").textContent = stats.total_packets;
    if (el("stat-total-bytes")) el("stat-total-bytes").textContent = formatBytes(stats.total_bytes);
    if (el("stat-rate")) el("stat-rate").textContent = `${stats.packets_per_second} /s`;
    if (el("stat-duration")) el("stat-duration").textContent = `${stats.capture_duration_seconds}s`;

    // Render protocol distribution
    const protoBox = el("protocol-distribution");
    if (protoBox) {
      const protos = Object.entries(stats.protocol_distribution || {});
      if (protos.length === 0) {
        protoBox.innerHTML = '<span class="card-note">No traffic yet</span>';
      } else {
        protoBox.innerHTML = protos
          .map(([proto, count]) => {
            const pct = stats.total_packets > 0 ? Math.round((count / stats.total_packets) * 100) : 0;
            return `<span class="proto-pill"><strong>${proto}</strong> <span class="proto-pill-count">${count} (${pct}%)</span></span>`;
          })
          .join("");
      }
    }

    // Render top talkers
    const talkersBox = el("top-talkers-list");
    if (talkersBox) {
      const talkers = stats.top_talkers || [];
      if (talkers.length === 0) {
        talkersBox.innerHTML = '<span class="card-note">No active hosts yet</span>';
      } else {
        talkersBox.innerHTML = talkers
          .map((t) => `<div class="talker-row"><span class="talker-ip">${t.ip}</span><span class="talker-stat">${t.packets} pkts (${formatBytes(t.bytes)})</span></div>`)
          .join("");
      }
    }
  } catch (err) {
    // Non-blocking for dashboard
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
    refreshStats();
  } catch (err) {
    message.textContent = err.message;
    message.style.display = "block";
  }
}

el("interface-select").addEventListener("change", (e) => {
  selectInterface(e.target.value);
});

el("start-button").addEventListener("click", () => changeCapture("start"));
el("stop-button").addEventListener("click", () => changeCapture("stop"));
el("filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  refreshPackets();
  refreshStats();
});
el("clear-filters").addEventListener("click", () => {
  el("filter-form").reset();
  el("filter-error").style.display = "none";
  refreshPackets();
  refreshStats();
});

// Initial boot
checkAuth();
loadInterfaces();
refresh();
refreshPackets();
refreshStats();
setInterval(() => {
  refresh();
  refreshStats();
}, POLL_INTERVAL_MS);
