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
    const data = await res.json();
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

function renderSessions(sessions) {
  el("history-empty").hidden = sessions.length > 0;
  el("history-table-wrap").hidden = sessions.length === 0;
  el("session-list").innerHTML = sessions.map((session) => {
    const protocols = Object.entries(session.analysis.protocol_counts || {})
      .map(([protocol, count]) => `${protocol}: ${count}`).join(", ") || "Pending";
    return `<tr>
      <td><strong>${session.id}</strong></td>
      <td>${new Date(session.started_at).toLocaleString()}</td>
      <td>${session.ended_at ? new Date(session.ended_at).toLocaleString() : "In progress"}</td>
      <td>${session.packet_count}</td>
      <td>${protocols} (${session.analysis.total_bytes || 0} B)</td>
      <td style="white-space: nowrap;">
        <a href="/api/sessions/${session.id}/export?format=pcap" class="export-link" download title="Download PCAP">PCAP</a> |
        <a href="/api/sessions/${session.id}/report" class="export-link" target="_blank" title="View Report">Report</a> |
        <a href="/api/sessions/${session.id}/export?format=json" class="export-link" download title="Download JSON">JSON</a>
      </td>
    </tr>`;
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
el("stop-button").addEventListener("click", async () => {
  await changeCapture("stop");
  refreshSessions();
});
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

// --- Alerts & Analysis Observations (Issue #11, FR-08) ---

let currentAlertSeverity = "";

async function refreshAlerts() {
  const alertList = el("alert-list");
  const countEl = el("alert-count");
  if (!alertList) return;

  try {
    const url = currentAlertSeverity
      ? `/api/alerts?severity=${encodeURIComponent(currentAlertSeverity)}`
      : "/api/alerts";
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    const alerts = data.alerts || [];

    if (countEl) countEl.textContent = `${alerts.length} alert${alerts.length === 1 ? "" : "s"}`;

    if (alerts.length === 0) {
      alertList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--muted); padding: 1rem;">No security alerts detected. Traffic nominal.</td></tr>';
      return;
    }

    alertList.innerHTML = alerts
      .map((a) => {
        const sev = (a.severity || "INFO").toUpperCase();
        let badgeClass = "badge-info";
        if (sev === "CRITICAL") badgeClass = "badge-critical";
        else if (sev === "WARNING") badgeClass = "badge-warning";

        const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "--:--:--";
        const sourceStr = a.source_ip || "unknown";
        return `<tr>
          <td>${timeStr}</td>
          <td><span class="${badgeClass}">${sev}</span></td>
          <td><strong>${a.alert_type}</strong></td>
          <td><code>${sourceStr}</code></td>
          <td style="white-space: normal; max-width: 280px;">${a.details || ""}</td>
        </tr>`;
      })
      .join("");
  } catch (err) {
    // Non-blocking
  }
}

document.querySelectorAll(".alert-chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".alert-chip").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentAlertSeverity = btn.getAttribute("data-severity") || "";
    refreshAlerts();
  });
});

// --- Performance & Resource Telemetry (Issue #15, NFR-01, NFR-07) ---

async function refreshPerformance() {
  try {
    const res = await fetch("/api/system/performance");
    if (!res.ok) return;
    const data = await res.json();

    const latency = data.dashboard_response_time_ms;
    if (latency && el("stat-latency")) {
      el("stat-latency").textContent = `${latency.mean} ms`;
    }
    if (latency && el("stat-p95")) {
      el("stat-p95").textContent = `${latency.p95} ms`;
    }

    const cpu = data.cpu_usage;
    if (cpu && el("stat-cpu")) {
      el("stat-cpu").textContent = `${cpu.process_cpu_time_sec}s`;
    }

    const mem = data.memory_usage;
    if (mem && el("stat-memory")) {
      el("stat-memory").textContent = `${mem.rss_mb} MB`;
    }
  } catch (err) {
    // Non-blocking
  }
}


// --- Zeek Network Analysis (Issue #9, FR-5, FR-10) ---

let currentZeekLogType = "all";

async function refreshZeek() {
  const logList = el("zeek-log-list");
  if (!logList) return;

  try {
    const statsRes = await fetch("/api/zeek/stats");
    if (statsRes.ok) {
      const statsData = await statsRes.json();
      const zSum = statsData.zeek_summary || {};
      if (el("zeek-stat-conn")) el("zeek-stat-conn").textContent = zSum.total_connections || 0;
      if (el("zeek-stat-dns")) el("zeek-stat-dns").textContent = zSum.dns_transactions || 0;
      if (el("zeek-stat-weird")) el("zeek-stat-weird").textContent = zSum.weird_events || 0;
      if (el("zeek-stat-notice")) el("zeek-stat-notice").textContent = zSum.security_notices || 0;
    }

    const url = currentZeekLogType && currentZeekLogType !== "all"
      ? `/api/zeek/logs?type=${encodeURIComponent(currentZeekLogType)}`
      : "/api/zeek/logs";
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      logList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--muted); padding: 1rem;">No Zeek log entries matching selected filter.</td></tr>';
      return;
    }

    logList.innerHTML = logs
      .map((entry) => {
        const type = (entry.log_type || currentZeekLogType || "conn").toUpperCase();
        let badgeClass = "badge-info";
        if (type === "WEIRD") badgeClass = "badge-warning";
        else if (type === "NOTICE") badgeClass = "badge-critical";

        const timeStr = entry.ts ? new Date(entry.ts).toLocaleTimeString() : "--:--:--";
        const uidStr = entry.uid || entry.trans_id || "-";

        let endpointStr = "-";
        let detailStr = "-";

        if (entry.log_type === "conn" || (!entry.log_type && entry["id.orig_h"])) {
          endpointStr = `${entry["id.orig_h"]}:${entry["id.orig_p"]} &rarr; ${entry["id.resp_h"]}:${entry["id.resp_p"]} (${entry.service || "-"})`;
          detailStr = `State: ${entry.conn_state || "-"} | Orig: ${entry.orig_bytes || 0}B, Resp: ${entry.resp_bytes || 0}B`;
        } else if (entry.log_type === "dns" || entry.query) {
          endpointStr = `${entry["id.orig_h"]} &rarr; ${entry["id.resp_h"]}`;
          detailStr = `Query: ${entry.query} (${entry.qtype_name || "A"}) | RCode: ${entry.rcode_name || "NOERROR"}`;
        } else if (entry.log_type === "weird" || entry.name) {
          endpointStr = `Peer: ${entry.peer || "-"}`;
          detailStr = `Weird: <strong>${entry.name}</strong> (${entry.addl || ""})`;
        } else if (entry.log_type === "notice" || entry.note) {
          endpointStr = `${entry.src || "-"} &rarr; ${entry.dst || "-"}`;
          detailStr = `<strong>${entry.note}</strong>: ${entry.msg || ""}`;
        }

        return `<tr>
          <td><span class="${badgeClass}">${type}</span></td>
          <td>${timeStr}</td>
          <td><code>${uidStr}</code></td>
          <td>${endpointStr}</td>
          <td style="white-space: normal; max-width: 320px;">${detailStr}</td>
        </tr>`;
      })
      .join("");
  } catch (err) {
    // Non-blocking
  }
}

document.querySelectorAll(".zeek-chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".zeek-chip").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentZeekLogType = btn.getAttribute("data-logtype") || "all";
    refreshZeek();
  });
});

// Initial boot
checkAuth();
loadInterfaces();
refresh();
refreshPackets();
refreshSessions();
refreshStats();
refreshAlerts();
refreshPerformance();
refreshZeek();

setInterval(() => {
  refresh();
  refreshStats();
  refreshSessions();
  refreshAlerts();
  refreshPerformance();
  refreshZeek();
}, POLL_INTERVAL_MS);
