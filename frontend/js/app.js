// Pocket Packet Sniffer dashboard logic.
// Fetches status from the backend and updates the header cards.
// Polls every 2 seconds, matching the refresh bound in SRS FR-6.

const POLL_INTERVAL_MS = 2000;

const STATUS_LABELS = {
  idle: "Idle",
  capturing: "Capturing",
  stopped: "Stopped",
  error: "Error",
};

const el = (id) => document.getElementById(id);

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

refresh();
setInterval(refresh, POLL_INTERVAL_MS);

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

function renderSessions(sessions) {
  el("history-empty").hidden = sessions.length > 0;
  el("history-table-wrap").hidden = sessions.length === 0;
  el("session-list").innerHTML = sessions.map((session) => {
    const protocols = Object.entries(session.analysis.protocol_counts)
      .map(([protocol, count]) => `${protocol}: ${count}`).join(", ") || "Pending";
    return `<tr><td>${session.id}</td><td>${new Date(session.started_at).toLocaleString()}</td><td>${session.ended_at ? new Date(session.ended_at).toLocaleString() : "In progress"}</td><td>${session.packet_count}</td><td>${protocols} (${session.analysis.total_bytes} B)</td></tr>`;
  }).join("");
}

async function refreshSessions() {
  try {
    const res = await fetch("/api/sessions");
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderSessions((await res.json()).sessions);
    el("history-error").hidden = true;
  } catch (err) {
    el("history-error").hidden = false;
  }
}

async function refreshPackets() {
  try {
    const res = await fetch("/api/packets?" + filters());
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderPackets((await res.json()).packets);
  } catch (err) {
    el("packet-list").innerHTML = '<tr><td colspan="6">Unable to load captured traffic.</td></tr>';
  }
}

async function changeCapture(action) {
  const message = el("capture-message");
  try {
    const res = await fetch("/api/capture/" + action, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Capture request failed");
    render(data);
    message.hidden = true;
  } catch (err) {
    message.textContent = err.message;
    message.hidden = false;
  }
}

el("start-button").addEventListener("click", () => changeCapture("start"));
el("stop-button").addEventListener("click", async () => {
  await changeCapture("stop");
  refreshSessions();
});
el("filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  refreshPackets();
});
el("clear-filters").addEventListener("click", () => {
  el("filter-form").reset();
  refreshPackets();
});
refreshPackets();
refreshSessions();
