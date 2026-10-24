"use strict";

const REFRESH_MS = parseInt(
  document.querySelector('meta[name="idsfw-refresh-ms"]')?.content || "2000",
  10
);

const COLORS = {
  accent: "#38bdf8",
  accent2: "#22d3ee",
  danger: "#f87171",
  warn: "#fbbf24",
  ok: "#34d399",
  grid: "#1f2c3a",
  text: "#8b9bab",
};

/* ------------------------------------------------------------------ utils */
const nf = new Intl.NumberFormat();

function fmtNum(value) {
  if (value === null || value === undefined) return "–";
  return nf.format(Math.round(value));
}

function fmtBytes(value) {
  if (!value && value !== 0) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let num = Number(value);
  while (num >= 1024 && idx < units.length - 1) {
    num /= 1024;
    idx += 1;
  }
  return `${num.toFixed(num >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function fmtTime(epochSeconds) {
  if (!epochSeconds) return "–";
  const d = new Date(epochSeconds * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function fmtDurationMicros(micros) {
  if (!micros) return "0 ms";
  if (micros < 1000) return `${Math.round(micros)} µs`;
  if (micros < 1_000_000) return `${(micros / 1000).toFixed(1)} ms`;
  return `${(micros / 1_000_000).toFixed(2)} s`;
}

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${s % 60}s`;
}

function fmtExpiry(epochSeconds) {
  if (!epochSeconds) return "permanent";
  const remaining = epochSeconds - Date.now() / 1000;
  if (remaining <= 0) return "expired";
  if (remaining < 60) return `${Math.round(remaining)} s`;
  if (remaining < 3600) return `${Math.round(remaining / 60)} min`;
  return `${(remaining / 3600).toFixed(1)} h`;
}

function protoName(proto) {
  if (proto === 6) return "TCP";
  if (proto === 17) return "UDP";
  return String(proto);
}

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function toast(message, isError) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.toggle("error", Boolean(isError));
  el.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { el.hidden = true; }, 4000);
}

async function api(path, options) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || payload.message || response.statusText);
  return payload;
}

/* ----------------------------------------------------------------- charts */
function prepareCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 300;
  const height = canvas.clientHeight || 180;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width, height };
}

function drawChart(canvas, series, labels, { yFormat = fmtNum } = {}) {
  const { ctx, width, height } = prepareCanvas(canvas);
  const pad = { top: 12, right: 8, bottom: 20, left: 46 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  ctx.clearRect(0, 0, width, height);

  const maxValue = Math.max(1, ...series.flatMap((s) => s.values));
  const count = labels.length || 1;

  // grid + y labels
  ctx.strokeStyle = COLORS.grid;
  ctx.fillStyle = COLORS.text;
  ctx.font = "10px ui-monospace, monospace";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = pad.top + (plotH * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(pad.left + plotW, y);
    ctx.stroke();
    const value = maxValue * (1 - i / 4);
    ctx.fillText(yFormat(value), 4, y + 3);
  }

  // x labels (first / middle / last timestamp)
  if (labels.length) {
    const stamps = [labels[0], labels[Math.floor(labels.length / 2)], labels[labels.length - 1]];
    stamps.forEach((stamp, index) => {
      const x = pad.left + (plotW * (index * (count - 1))) / Math.max(1, count - 1) / 2 + (index === 1 ? 0 : 0);
      const xPos = index === 0 ? pad.left : index === 1 ? pad.left + plotW / 2 : pad.left + plotW;
      ctx.fillText(fmtTime(stamp), Math.min(xPos, width - pad.right - 34), height - 6);
    });
  }

  const stepX = plotW / Math.max(1, count - 1);
  series.forEach((serie) => {
    if (!serie.values.length) return;
    ctx.beginPath();
    serie.values.forEach((value, index) => {
      const x = pad.left + stepX * index;
      const y = pad.top + plotH - (value / maxValue) * plotH;
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    if (serie.fill) {
      const lastIndex = serie.values.length - 1;
      ctx.lineTo(pad.left + stepX * lastIndex, pad.top + plotH);
      ctx.lineTo(pad.left, pad.top + plotH);
      ctx.closePath();
      ctx.fillStyle = serie.fill;
      ctx.fill();
      ctx.beginPath();
      serie.values.forEach((value, index) => {
        const x = pad.left + stepX * index;
        const y = pad.top + plotH - (value / maxValue) * plotH;
        if (index === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
    }
    ctx.strokeStyle = serie.color;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  });
}

/* -------------------------------------------------------------- rendering */
function renderSparkline(svgId, values) {
  const svg = document.getElementById(svgId);
  if (!svg) return;
  const path = svg.querySelector("path");
  if (!path) return;
  if (!values || !values.length) {
    path.setAttribute("d", "M 1 31 L 119 31");
    return;
  }
  const max = Math.max(1, ...values);
  const min = 0;
  const range = max - min || 1;
  const width = 120;
  const height = 32;
  const padY = 4;
  const stepX = (width - 2) / Math.max(1, values.length - 1);
  const d = values.map((val, idx) => {
    const x = 1 + idx * stepX;
    const y = height - padY - ((val - min) / range) * (height - 2 * padY);
    return `${idx === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(" ");
  path.setAttribute("d", d);
}

function renderHealth(summary) {
  const stats = summary.stats || {};
  const model = summary.model || {};
  const alerts = summary.alerts || {};
  let score = 100;
  let statusText = "● healthy";
  let isErr = false;

  if (model.backend === "mock") {
    score -= 25;
    statusText = "▲ mock model";
  }
  if (stats.dropped_packets > 0) {
    score -= Math.min(20, Math.ceil(stats.dropped_packets / 10));
  }
  if (stats.parse_errors > 0) {
    score -= Math.min(15, stats.parse_errors);
  }
  if ((alerts.window || 0) > 0) {
    score = Math.max(30, score - Math.min(50, (alerts.window || 0) * 10));
    statusText = `! ${alerts.window} threats active`;
    isErr = true;
  }
  score = Math.max(10, Math.min(100, score));

  const ringEl = document.getElementById("health-ring-val");
  if (ringEl) {
    const level = score >= 80 ? "protected" : (score >= 50 ? "warning" : "critical");
    ringEl.innerHTML = `<strong>${score}%</strong><small>${level}</small>`;
  }
  const badgeEl = document.getElementById("health-status-check");
  if (badgeEl) {
    badgeEl.textContent = statusText;
    badgeEl.style.color = isErr ? "var(--rose)" : (score < 80 ? "var(--amber)" : "var(--emerald)");
  }
}

function renderSummary(summary) {
  const stats = summary.stats || {};
  const model = summary.model || {};
  const firewall = summary.firewall || {};
  const flowsDb = summary.flows || {};

  const totalFlows = (stats.flows_total || 0) || ((flowsDb.BENIGN || 0) + (flowsDb.ATTACK || 0));
  const totalAttacks = (stats.attacks_total || 0) || (flowsDb.ATTACK || 0);
  const totalBenign = (stats.verdicts?.BENIGN || 0) || (flowsDb.BENIGN || 0);

  document.getElementById("kpi-flows").textContent = fmtNum(totalFlows);
  document.getElementById("kpi-flows-sub").textContent =
    `${fmtNum(totalAttacks)} attacks · ${fmtNum(totalBenign)} benign`;
  document.getElementById("kpi-attacks").textContent = fmtNum(totalAttacks);
  document.getElementById("kpi-attacks-sub").textContent =
    `last 5 min: ${fmtNum(summary.alerts?.window || 0)}`;
  document.getElementById("kpi-blocked").textContent = fmtNum((firewall.blocked || []).length);
  document.getElementById("kpi-blocked-sub").textContent = firewall.available
    ? `nftables table ${firewall.table}`
    : "nftables unavailable";
  document.getElementById("kpi-pps").textContent = fmtNum(stats.packets_per_s);
  document.getElementById("kpi-pps-sub").textContent = `${fmtNum(stats.packets_total)} total`;
  document.getElementById("kpi-bps").textContent = `${fmtBytes(stats.bytes_per_s)}/s`;
  document.getElementById("kpi-bps-sub").textContent = `${fmtBytes(stats.bytes_total)} total`;
  const kpiActive = document.getElementById("kpi-active");
  if (kpiActive) kpiActive.textContent = fmtNum(stats.active_flows);
  const kpiActiveSub = document.getElementById("kpi-active-sub");
  if (kpiActiveSub) kpiActiveSub.textContent = `${fmtNum(stats.dropped_packets)} dropped`;

  renderHealth(summary);

  document.getElementById("chip-iface").textContent = `iface: ${summary.interface?.capture_interface || "–"}`;
  document.getElementById("chip-model").textContent =
    `model: ${model.backend || "–"} · ${model.features || 0}f · thr ${model.threshold ?? "–"}`;
  document.getElementById("chip-uptime").textContent = `up: ${fmtUptime(stats.uptime_s)}`;

  const statusDot = document.getElementById("status-dot");
  statusDot.classList.toggle("err", model.backend === "mock");
  statusDot.classList.remove("ok");
  if (model.backend !== "mock") statusDot.classList.add("ok");
  document.getElementById("status-text").textContent =
    model.backend === "mock" ? "MOCK MODEL" : `${summary.source} capture`;

  const advertise = summary.interface?.advertise_ip;
  const port = summary.interface?.port || 80;
  const suffix = port === 80 ? "" : `:${port}`;
  document.getElementById("banner-ips").innerHTML = advertise
    ? `reachable at <a href="http://${esc(advertise)}${suffix}/">${esc(advertise)}${suffix}</a>`
    : "no address detected";

  document.querySelectorAll(".mode-switch button").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === firewall.mode);
  });

  const info = [
    ["model dir", model.dir],
    ["model file", model.model_file],
    ["backend", model.backend],
    ["features", model.features],
    ["threshold", model.threshold],
    ["rows scored", fmtNum(model.rows_scored)],
    ["attacks", fmtNum(model.attacks)],
    ["firewall mode", firewall.mode],
    ["auto-block", `${firewall.threshold} attacks → ${firewall.ttl_s}s`],
    ["allowlist", (firewall.allowlist || []).join(", ")],
    ["protocols", Object.entries(stats.protocols || {}).map(([k, v]) => `${protoName(Number(k))}:${v}`).join("  ")],
    ["parse errors", fmtNum(stats.parse_errors)],
  ];
  document.getElementById("system-info").innerHTML = info
    .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`)
    .join("");

  document.getElementById("footer-iface").textContent = summary.interface?.capture_interface || "–";
  const fwStatus = firewall.available
    ? `${firewall.mode} · ${firewall.table}`
    : "unavailable (no nft)";
  const footerFw = document.getElementById("footer-fw");
  if (footerFw) footerFw.textContent = fwStatus;
  const footerFwBottom = document.getElementById("footer-fw-bottom");
  if (footerFwBottom) footerFwBottom.textContent = fwStatus;
}

function renderTimeseries(data) {
  const labels = data.labels || [];
  const bytesPerSec = (data.bytes || []).map((v) => v);
  drawChart(
    document.getElementById("chart-traffic"),
    [
      { values: bytesPerSec, color: COLORS.accent, fill: "rgba(56,189,248,0.14)" },
    ],
    labels,
    { yFormat: (v) => fmtBytes(v) }
  );
  const peak = Math.max(0, ...bytesPerSec);
  document.getElementById("chart-traffic-peak").textContent = `peak ${fmtBytes(peak)}/s`;

  drawChart(
    document.getElementById("chart-flows"),
    [
      { values: data.flows || [], color: COLORS.ok },
      { values: data.attacks || [], color: COLORS.danger },
    ],
    labels
  );
  const peakFlows = Math.max(0, ...(data.flows || []));
  const peakAttacks = Math.max(0, ...(data.attacks || []));
  document.getElementById("chart-flows-peak").textContent =
    `peak ${peakFlows} flows/s · ${peakAttacks} attacks/s`;

  renderSparkline("sparkline-pps", data.packets || []);
  renderSparkline("sparkline-bps", data.bytes || []);
  renderSparkline("sparkline-flows", data.flows || []);
  renderSparkline("sparkline-attacks", data.attacks || []);
}

function blockButton(ip) {
  return `<button class="action" data-block="${esc(ip)}" title="Block ${esc(ip)}">block</button>`;
}

function renderAlerts(data, blocks) {
  const body = document.querySelector("#table-alerts tbody");
  const blockedSet = new Set((blocks || []).map((b) => b.ip));
  const alerts = data.alerts || [];
  document.getElementById("alerts-count").textContent = `${alerts.length} recent`;
  if (!alerts.length) {
    body.innerHTML = `<tr><td colspan="7" class="muted">No detections yet.</td></tr>`;
    return;
  }
  body.innerHTML = alerts
    .map((alert) => `
      <tr>
        <td>${fmtTime(alert.ts)}</td>
        <td>${esc(alert.src_ip)}</td>
        <td>${esc(alert.dst_ip)}:${alert.dst_port ?? "–"} <span class="muted">${protoName(alert.proto)}</span></td>
        <td>${esc(alert.reason?.includes("blocked") || alert.action === "blocked" ? "auto" : "")}</td>
        <td class="num">${Number(alert.score ?? 0).toFixed(3)}</td>
        <td><span class="badge ${alert.action === "blocked" ? "blocked" : "attack"}">${esc(alert.action)}</span></td>
        <td>${blockedSet.has(alert.src_ip) ? "" : blockButton(alert.src_ip)}</td>
      </tr>`)
    .join("");
}

function renderBlocks(data) {
  const body = document.querySelector("#table-blocks tbody");
  const blocks = data.blocks || [];
  document.getElementById("blocks-count").textContent = data.available
    ? `${blocks.length} blocked`
    : "nftables unavailable";
  renderSparkline("sparkline-blocked", blocks.map((_, i) => i + 1));
  if (!blocks.length) {
    body.innerHTML = `<tr><td colspan="4" class="muted">No addresses blocked.</td></tr>`;
    return;
  }
  body.innerHTML = blocks
    .map((block) => `
      <tr>
        <td>${esc(block.ip)}</td>
        <td>${esc(block.source)}</td>
        <td>${fmtExpiry(block.expires_ts)}</td>
        <td><button class="action undo" data-unblock="${esc(block.ip)}">unblock</button></td>
      </tr>`)
    .join("");
}

function renderFlows(data, blocks) {
  const body = document.querySelector("#table-flows tbody");
  const blockedSet = new Set((blocks || []).map((b) => b.ip));
  const flows = data.flows || [];
  document.getElementById("flows-count").textContent = `${flows.length} latest`;
  if (!flows.length) {
    body.innerHTML = `<tr><td colspan="10" class="muted">Waiting for traffic…</td></tr>`;
    return;
  }
  body.innerHTML = flows
    .map((flow) => `
      <tr>
        <td>${fmtTime(flow.ts)}</td>
        <td>${esc(flow.src_ip)}:${flow.src_port ?? ""}</td>
        <td>${esc(flow.dst_ip)}:${flow.dst_port ?? ""}</td>
        <td>${esc(flow.service)} <span class="muted">${protoName(flow.proto)}</span></td>
        <td>${fmtDurationMicros(flow.duration_us)}</td>
        <td>${fmtNum(flow.fwd_pkts)} / ${fmtNum(flow.bwd_pkts)}</td>
        <td>${fmtBytes((flow.fwd_bytes || 0) + (flow.bwd_bytes || 0))}</td>
        <td class="num">${Number(flow.score ?? 0).toFixed(3)}</td>
        <td><span class="badge ${flow.verdict === "ATTACK" ? "attack" : "benign"}">${esc(flow.verdict)}</span></td>
        <td>${flow.verdict === "ATTACK" && !blockedSet.has(flow.src_ip) ? blockButton(flow.src_ip) : ""}</td>
      </tr>`)
    .join("");
}

function renderBars(containerId, rows, { label, value, danger = false, format = fmtNum }) {
  const container = document.getElementById(containerId);
  if (!rows.length) {
    container.innerHTML = `<p class="muted">No data in the selected window.</p>`;
    return;
  }
  const max = Math.max(...rows.map(value)) || 1;
  container.innerHTML = rows
    .map((row) => {
      const amount = value(row) || 0;
      const width = Math.max(2, (amount / max) * 100);
      return `<div class="bar-row">
        <span class="label" title="${esc(label(row))}">${esc(label(row))}</span>
        <span class="bar-track"><span class="bar-fill${danger ? " danger" : ""}" style="width:${width}%"></span></span>
        <span class="value">${esc(format(amount))}</span>
      </div>`;
    })
    .join("");
}

function renderClients(data) {
  const body = document.querySelector("#table-clients tbody");
  if (!body) return;
  const clients = data.clients || [];
  const countEl = document.getElementById("clients-count");
  if (countEl) countEl.textContent = `(${clients.length} device${clients.length === 1 ? "" : "s"})`;
  const apEl = document.getElementById("clients-ap");
  if (apEl) apEl.textContent = `interface: ${data.ap_interface || "ap0"}`;

  if (!clients.length) {
    body.innerHTML = `<tr><td colspan="4" class="muted">No devices currently connected to hotspot.</td></tr>`;
    return;
  }
  body.innerHTML = clients
    .map(
      (c) => `
      <tr>
        <td><strong>${esc(c.ip)}</strong></td>
        <td><code>${esc(c.mac || "-")}</code></td>
        <td>${esc(c.hostname || "unknown")}</td>
        <td><span class="badge benign">${esc(c.source)}</span></td>
      </tr>`
    )
    .join("");
}

function renderAnalytics(data) {
  renderBars("top-talkers", data.top_talkers || [], {
    label: (row) => row.src_ip,
    value: (row) => row.bytes,
    format: fmtBytes,
  });
  renderBars("top-attackers", data.top_attackers || [], {
    label: (row) => row.src_ip,
    value: (row) => row.attacks,
    danger: true,
  });
  renderBars("top-ports", data.destination_ports || [], {
    label: (row) => `${row.dst_port} (${row.attacks} atk)`,
    value: (row) => row.flows,
  });
}

/* ------------------------------------------------------------------ events */
document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const blockIp = target.dataset?.block;
  const unblockIp = target.dataset?.unblock;

  if (blockIp) {
    try {
      const result = await api("/api/blocks", {
        method: "POST",
        body: JSON.stringify({ ip: blockIp }),
      });
      toast(result.ok ? `Blocked ${blockIp}` : `Failed: ${result.message}`, !result.ok);
      await refresh();
    } catch (error) {
      toast(`Failed to block ${blockIp}: ${error.message}`, true);
    }
  }

  if (unblockIp) {
    try {
      const result = await api(`/api/blocks/${encodeURIComponent(unblockIp)}`, { method: "DELETE" });
      toast(result.ok ? `Unblocked ${unblockIp}` : `Failed: ${result.message}`, !result.ok);
      await refresh();
    } catch (error) {
      toast(`Failed to unblock ${unblockIp}: ${error.message}`, true);
    }
  }

  const mode = target.dataset?.mode;
  if (mode) {
    try {
      const result = await api("/api/mode", { method: "POST", body: JSON.stringify({ mode }) });
      toast(`Firewall mode: ${result.mode}`);
      await refresh();
    } catch (error) {
      toast(`Failed to switch mode: ${error.message}`, true);
    }
  }
});

/* ----------------------------------------------------------------- polling */
let failures = 0;

async function refresh() {
  try {
    const [summary, timeseries, flows, alerts, blocks, analytics, clients] = await Promise.all([
      api("/api/summary"),
      api("/api/timeseries?points=120"),
      api("/api/flows?limit=60"),
      api("/api/alerts?limit=40"),
      api("/api/blocks"),
      api("/api/analytics?window=300"),
      api("/api/clients"),
    ]);
    renderSummary(summary);
    renderTimeseries(timeseries);
    renderFlows(flows, blocks.blocks);
    renderAlerts(alerts, blocks.blocks);
    renderBlocks(blocks);
    renderAnalytics(analytics);
    renderClients(clients);
    document.getElementById("footer-refresh").textContent = `updated ${new Date().toLocaleTimeString()}`;
    failures = 0;
  } catch (error) {
    failures += 1;
    document.getElementById("status-dot").classList.remove("ok");
    document.getElementById("status-dot").classList.add("err");
    document.getElementById("status-text").textContent = `connection lost (${failures})`;
  }
}

window.addEventListener("resize", () => refresh());
refresh();
setInterval(refresh, REFRESH_MS);
