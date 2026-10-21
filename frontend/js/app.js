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
el("stop-button").addEventListener("click", () => changeCapture("stop"));
el("filter-form").addEventListener("submit", (event) => {
  event.preventDefault();
  refreshPackets();
});
el("clear-filters").addEventListener("click", () => {
  el("filter-form").reset();
  refreshPackets();
});
refreshPackets();
