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
