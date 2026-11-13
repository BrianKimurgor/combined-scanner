"use strict";

const root = document.getElementById("app");
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CATEGORIES = ["dependency", "code", "secret", "pii", "iac", "duplication", "complexity", "license"];
const TOOLS = ["osv", "semgrep", "gitleaks", "trivy", "jscpd", "lizard", "checkov", "presidio", "trufflehog"];
const PAGE = 50;

let timer = null;      // auto-refresh for scans that are still running
let ticker = null;     // one-second clock for elapsed times on the live progress page
let renderToken = 0;   // a slow response must not draw over a newer page
const watched = new Set(); // scans seen running in this tab: show their finish screen before the report

// ---------------------------------------------------------------- helpers

// Build elements only through textContent / setAttribute: scanned code is untrusted text.
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "text") el.textContent = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "value") el.value = value;
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, value);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const kid of kids) if (kid) el.append(kid);
  return el;
}
function svgText(x, y, text, anchor = "middle") {
  const el = svg("text", { x, y, "text-anchor": anchor });
  el.textContent = text;
  return el;
}

// Stroke icons in the style of Lucide, drawn from path data only.
const ICONS = {
  logo: ["M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z", "m9 12 2 2 4-4"],
  history: ["M3 12a9 9 0 1 0 3-6.7", "M3 4v5h5", "M12 7v5l3 2"],
  plus: ["M12 5v14", "M5 12h14"],
  trend: ["M3 17l6-6 4 4 8-8", "M15 7h6v6"],
  policy: ["M9 11l3 3 8-8", "M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9"],
  sun: ["M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", "M12 2v2", "M12 20v2", "M4.9 4.9l1.4 1.4", "M17.7 17.7l1.4 1.4", "M2 12h2", "M20 12h2", "M4.9 19.1l1.4-1.4", "M17.7 6.3l1.4-1.4"],
  moon: ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
  upload: ["M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3", "M17 8l-5-5-5 5", "M12 3v12"],
  download: ["M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3", "M7 10l5 5 5-5", "M12 15V3"],
  git: ["M6 3v12", "M15 6a3 3 0 1 0 6 0 3 3 0 1 0-6 0", "M3 18a3 3 0 1 0 6 0 3 3 0 1 0-6 0", "M18 9a9 9 0 0 1-9 9"],
  check: ["M20 6L9 17l-5-5"],
  x: ["M18 6L6 18", "M6 6l12 12"],
  alert: ["M12 9v4", "M12 17h.01", "M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"],
  file: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6", "M8 13h8", "M8 17h5"],
  external: ["M15 3h6v6", "M10 14L21 3", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
  bookmark: ["M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"],
  eye: ["M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"],
  inbox: ["M22 12h-6l-2 3h-4l-2-3H2", "M5.5 5.1L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"],
  pointer: ["M3 3l7 17 2.5-7.5L20 10z"],
  key: ["M15 7a4 4 0 1 1-3.5 6L3 21v-3l8.5-8.5A4 4 0 0 1 15 7z"],
  clock: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 6v6l4 2"],
  minus: ["M5 12h14"],
  arrowRight: ["M5 12h14", "M13 5l7 7-7 7"],
};

function icon(name, cls = "") {
  const el = svg("svg", { class: `icon ${cls}`.trim(), viewBox: "0 0 24 24", "aria-hidden": "true" });
  for (const d of ICONS[name] || []) el.append(svg("path", { d }));
  return el;
}

function describeError(body, status) {
  const detail = body && body.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return `request failed (${status})`;
}

class AuthError extends Error {}

async function api(path, options = {}) {
  const headers = { "X-Requested-With": "scanner-ui", ...(options.headers || {}) };
  let body = options.body;
  if (body && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body,
    credentials: "same-origin",
  });
  if (response.status === 401 && !options.noAuthRedirect) {
    window.location.hash = "#/login";
    throw new AuthError("sign in required");
  }
  if (response.status === 204) return null;
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) throw new Error(describeError(data, response.status));
  return data;
}

function query(params) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== "" && value !== null && value !== undefined) qs.set(key, value);
  }
  const text = qs.toString();
  return text ? `?${text}` : "";
}

function when(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

function shortSource(scan) {
  const source = scan.source || "";
  return source.length > 60 ? `${source.slice(0, 57)}...` : source;
}

function scoreClass(percent) {
  if (percent === null || percent === undefined) return "muted";
  return percent >= 80 ? "good" : percent >= 50 ? "warn" : "bad";
}

function percentText(score) {
  return score && score.percent !== null && score.percent !== undefined
    ? `${Math.round(score.percent)}%`
    : "n/a";
}

function sevPill(severity) {
  return h("span", { class: `pill ${severity}`, text: severity });
}

function statusPill(status) {
  return h("span", { class: `pill ${status}`, text: status });
}

function errorBanner(message) {
  return h("div", { class: "banner error", role: "alert" }, icon("alert", "sm"), h("span", { text: message }));
}

function emptyState(iconName, title, hint, action) {
  return h(
    "div",
    { class: "empty" },
    h("div", { class: "badge" }, icon(iconName)),
    h("b", { text: title }),
    h("span", { text: hint }),
    action || null,
  );
}

function pageHead(title, sub, ...actions) {
  return h(
    "div",
    { class: "page-head" },
    h("div", {}, h("h1", { text: title }), sub ? h("div", { class: "sub", text: sub }) : null),
    actions.length ? h("div", { class: "actions" }, ...actions) : null,
  );
}

function clearTimer() {
  if (timer) clearTimeout(timer);
  if (ticker) clearInterval(ticker);
  timer = null;
  ticker = null;
}

function whereText(finding) {
  if (!finding.file) return finding.package ? `${finding.package} ${finding.version || ""}`.trim() : "";
  const range =
    finding.line_start && finding.line_end && finding.line_end !== finding.line_start
      ? `${finding.line_start}-${finding.line_end}`
      : finding.line_start || "";
  return range ? `${finding.file}:${range}` : finding.file;
}

// ---------------------------------------------------------------- theme

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

function isDark() {
  const current = document.documentElement.getAttribute("data-theme");
  return current === "dark" || (current === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
}

function toggleTheme() {
  const next = isDark() ? "light" : "dark";
  localStorage.setItem("scanner-theme", next);
  applyTheme(next);
  route();
}

applyTheme(localStorage.getItem("scanner-theme") || "auto");

// ---------------------------------------------------------------- shell

function shell(active, ...content) {
  const link = (href, label, key, iconName) =>
    h("a", { href, class: active === key ? "active" : "" }, icon(iconName), h("span", { text: label }));
  return h(
    "div",
    { class: "app" },
    h(
      "aside",
      { class: "sidebar" },
      h(
        "div",
        { class: "brand" },
        h("div", { class: "logo" }, icon("logo")),
        h("div", {}, h("div", { class: "name", text: "Code Scanner" }), h("div", { class: "tag-line", text: "Security and quality gate" })),
      ),
      h(
        "nav",
        { class: "nav" },
        link("#/", "Scans", "history", "history"),
        link("#/new", "New scan", "new", "plus"),
        link("#/trends", "Trends", "trends", "trend"),
        link("#/policy", "Suppressions", "policy", "policy"),
      ),
      h("div", { class: "spacer" }),
      h(
        "div",
        { class: "foot" },
        h("button", { onclick: toggleTheme, title: "Switch light or dark" }, icon(isDark() ? "sun" : "moon"), h("span", { text: isDark() ? "Light mode" : "Dark mode" })),
        h("button", { onclick: logout }, icon("logout"), h("span", { text: "Sign out" })),
      ),
    ),
    h("main", { class: "content" }, h("div", { class: "page" }, ...content)),
  );
}

function show(node) {
  root.replaceChildren(node);
}

async function logout() {
  try {
    await api("/ui/session", { method: "DELETE" });
  } catch (_) {
    /* already signed out */
  }
  location_hash("#/login");
}

function location_hash(hash) {
  if (window.location.hash === hash) route();
  else window.location.hash = hash;
}

// ---------------------------------------------------------------- login

function loginView() {
  const input = h("input", { type: "password", id: "key", autocomplete: "current-password", required: true, placeholder: "cs_..." });
  const message = h("div");
  const form = h(
    "form",
    {
      onsubmit: async (event) => {
        event.preventDefault();
        message.replaceChildren();
        try {
          await api("/ui/session", {
            method: "POST",
            body: { api_key: input.value },
            noAuthRedirect: true,
          });
          input.value = "";
          location_hash("#/");
        } catch (error) {
          message.replaceChildren(errorBanner(error.message));
        }
      },
    },
    h("label", { for: "key", text: "API key" }),
    input,
    h("p", { class: "muted" }, "Create one with ", h("code", { text: "scanner admin create-key NAME" })),
    message,
    h("button", { class: "primary", type: "submit" }, icon("key", "sm"), "Sign in"),
  );
  show(
    h(
      "div",
      { class: "auth" },
      h(
        "div",
        { class: "auth-card" },
        h("div", { class: "logo" }, icon("logo")),
        h("h1", { text: "Code Scanner" }),
        h("p", { class: "muted", text: "Eight open-source scanners, one report, one quality gate." }),
        form,
      ),
    ),
  );
  input.focus();
}

// ---------------------------------------------------------------- history

function healthBar(score) {
  const percent = score && score.percent;
  if (percent === null || percent === undefined) return h("span", { class: "muted", text: "n/a" });
  const fill = h("span", { class: "fill" });
  fill.style.display = "block";
  fill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  return h("span", { class: `mini-bar ${scoreClass(percent)}` }, h("span", { text: `${Math.round(percent)}%` }), h("span", { class: "track" }, fill));
}

async function historyView(token, page = 0) {
  const status = new URLSearchParams(window.location.hash.split("?")[1] || "").get("status") || "";
  const data = await api(`/scans${query({ status, limit: 25, offset: page * 25 })}`);
  if (token !== renderToken) return;
  const filter = h(
    "select",
    {
      onchange: (event) =>
        location_hash(event.target.value ? `#/?status=${event.target.value}` : "#/"),
      "aria-label": "Filter by status",
    },
    h("option", { value: "", text: "All statuses" }),
    ["queued", "running", "done", "failed"].map((s) =>
      h("option", { value: s, text: s, selected: s === status }),
    ),
  );
  const rows = data.items.map((scan) =>
    h(
      "tr",
      { class: "click", onclick: () => location_hash(`#/scan/${scan.id}`) },
      h("td", {}, h("div", { class: "title mono", text: shortSource(scan) }), h("div", { class: "path", text: when(scan.created_at) })),
      h("td", {}, h("span", { class: "tag", text: scan.base ? `diff vs ${scan.base}` : "full scan" })),
      h("td", {}, statusPill(scan.status)),
      h("td", {}, scan.gate ? h("span", { class: `pill ${scan.gate.passed ? "passed" : "failed"}`, text: scan.gate.passed ? "passed" : "failed" }) : ""),
      h("td", {}, healthBar(scan.score)),
      h("td", { text: scan.counted_count ?? "" }),
    ),
  );
  const pages = Math.max(1, Math.ceil(data.total / 25));
  const newButton = h("a", { class: "btn primary", href: "#/new" }, icon("plus", "sm"), "New scan");
  show(
    shell(
      "history",
      pageHead("Scans", `${data.total} ${data.total === 1 ? "scan" : "scans"} so far`, filter, newButton),
      h(
        "div",
        { class: "panel flush" },
        data.items.length
          ? [
              h(
                "table",
                {},
                h("thead", {}, h("tr", {}, ["Source", "Mode", "Status", "Gate", "Health", "Findings"].map((t) => h("th", { text: t })))),
                h("tbody", {}, rows),
              ),
              h(
                "div",
                { class: "pager" },
                h("button", { class: "small", disabled: page === 0, onclick: () => { clearTimer(); historyView(++renderToken, page - 1).catch(handleError); }, text: "Newer" }),
                h("span", { class: "muted", text: `Page ${page + 1} of ${pages}` }),
                h("button", { class: "small", disabled: page + 1 >= pages, onclick: () => { clearTimer(); historyView(++renderToken, page + 1).catch(handleError); }, text: "Older" }),
              ),
            ]
          : emptyState("inbox", "No scans yet", "Upload a zip or point at a git repository to get your first report.", h("a", { class: "btn primary", href: "#/new" }, icon("plus", "sm"), "Start a scan")),
      ),
    ),
  );
  if (data.items.some((s) => s.status === "queued" || s.status === "running")) {
    timer = setTimeout(() => historyView(token, page).catch(handleError), 3000);
  }
}

// ---------------------------------------------------------------- new scan

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function newScanView(token) {
  const baselines = await api("/baselines");
  if (token !== renderToken) return;
  const message = h("div");
  let mode = "zip";
  const file = h("input", { type: "file", accept: ".zip,application/zip", id: "file" });
  const dropTitle = h("span", { class: "big", text: "Drop a .zip here or click to browse" });
  const drop = h(
    "label",
    { class: "drop", for: "file" },
    icon("upload"),
    dropTitle,
    h("span", { text: "Scanned in an isolated container, then deleted." }),
    file,
  );
  function showFile() {
    if (file.files.length) {
      drop.classList.add("has-file");
      dropTitle.textContent = `${file.files[0].name} (${formatBytes(file.files[0].size)})`;
    } else {
      drop.classList.remove("has-file");
      dropTitle.textContent = "Drop a .zip here or click to browse";
    }
  }
  file.addEventListener("change", showFile);
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    if (event.dataTransfer && event.dataTransfer.files.length) {
      file.files = event.dataTransfer.files;
      showFile();
    }
  });

  const url = h("input", { type: "text", id: "url", placeholder: "https://github.com/owner/repo.git" });
  const ref = h("input", { type: "text", id: "ref", value: "HEAD" });
  const base = h("input", { type: "text", id: "base", placeholder: "main (optional)" });
  const baseline = h(
    "select",
    { id: "baseline" },
    h("option", { value: "", text: "None" }),
    baselines.map((b) => h("option", { value: String(b.id), text: `${b.name} (${b.size} findings)` })),
  );
  const zipBox = h("div", {}, drop);
  const gitBox = h(
    "div",
    { class: "hidden" },
    h("label", { for: "url", text: "Repository URL" }),
    url,
    h("div", { class: "row" },
      h("div", {}, h("label", { for: "ref", text: "Revision to scan" }), ref),
      h("div", {}, h("label", { for: "base", text: "Compare against (diff scan)" }), base),
    ),
    h("p", { class: "muted", text: "With a base revision, only findings new in the scanned revision count." }),
  );
  const zipButton = h("button", { type: "button", class: "on", onclick: () => setMode("zip") }, icon("upload", "sm"), "Upload zip");
  const gitButton = h("button", { type: "button", onclick: () => setMode("git") }, icon("git", "sm"), "Git repository");
  function setMode(next) {
    mode = next;
    zipButton.classList.toggle("on", mode === "zip");
    gitButton.classList.toggle("on", mode === "git");
    zipBox.classList.toggle("hidden", mode !== "zip");
    gitBox.classList.toggle("hidden", mode !== "git");
  }
  const submit = h("button", { class: "primary", type: "submit" }, icon("pointer", "sm"), "Start scan");
  const form = h(
    "form",
    {
      onsubmit: async (event) => {
        event.preventDefault();
        message.replaceChildren();
        submit.disabled = true;
        try {
          let created;
          if (mode === "zip") {
            if (!file.files.length) throw new Error("choose a zip archive");
            const data = new FormData();
            data.append("file", file.files[0]);
            if (baseline.value) data.append("baseline_id", baseline.value);
            created = await api("/scans", { method: "POST", body: data });
          } else {
            const body = { git_url: url.value.trim(), ref: ref.value.trim() || "HEAD" };
            if (base.value.trim()) body.base = base.value.trim();
            if (baseline.value) body.baseline_id = Number(baseline.value);
            created = await api("/scans", { method: "POST", body });
          }
          location_hash(`#/scan/${created.scan_id}`);
        } catch (error) {
          if (error instanceof AuthError) throw error;
          message.replaceChildren(errorBanner(error.message));
          submit.disabled = false;
        }
      },
    },
    h("div", { class: "seg-toggle" }, zipButton, gitButton),
    h("div", { class: "row" }),
    zipBox,
    gitBox,
    h("label", { for: "baseline", text: "Baseline (findings already accepted)" }),
    baseline,
    h("div", { class: "form-actions" }, message, submit),
  );
  show(
    shell(
      "new",
      pageHead("New scan", "Runs eight scanners in a locked-down container and merges the results."),
      h("div", { class: "panel form-narrow" }, form),
    ),
  );
}

// ---------------------------------------------------------------- scan detail

const filters = { severity: "", category: "", tool: "", isNew: "", suppressed: "false", page: 0 };

function categoryLabel(key) {
  const special = { pii: "PII", iac: "IaC" };
  return special[key] || key.charAt(0).toUpperCase() + key.slice(1);
}

function barChart(counts, order) {
  const shown = order.filter((k) => (counts[k] || 0) > 0).sort((a, b) => (counts[b] || 0) - (counts[a] || 0));
  if (!shown.length) return h("p", { class: "muted", text: "Nothing to show." });
  const max = Math.max(1, ...shown.map((k) => counts[k]));
  return h(
    "div",
    { class: "bars" },
    shown.map((key) => {
      const fill = h("div", { class: "bar-fill" });
      fill.style.width = `${(counts[key] / max) * 100}%`;
      return h(
        "div",
        { class: "bar-row" },
        h("span", { class: "bar-label", text: categoryLabel(key) }),
        h("div", { class: "bar-track" }, fill),
        h("span", { class: "bar-count", text: counts[key] }),
      );
    }),
  );
}

function severityStack(counts) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] || 0), 0);
  if (!total) {
    return h("div", { class: "empty" }, h("div", { class: "badge" }, icon("check")), h("b", { text: "Clean" }), h("span", { text: "No findings are counting against this scan." }));
  }
  const stack = h("div", { class: "stack" });
  for (const s of SEVERITIES) {
    if (!counts[s]) continue;
    const seg = h("div", { class: `seg ${s}`, title: `${counts[s]} ${s}` });
    seg.style.flexGrow = String(counts[s]);
    stack.append(seg);
  }
  const legend = h(
    "div",
    { class: "legend" },
    SEVERITIES.map((s) => h("div", { class: "item" }, h("span", { class: "name" }, h("i", { class: s }), s), h("b", { text: counts[s] || 0 }))),
  );
  return h("div", {}, stack, legend);
}

function scoreRing(score) {
  const percent = score && score.percent !== null && score.percent !== undefined ? score.percent : null;
  const r = 54;
  const circumference = 2 * Math.PI * r;
  const value = svg("circle", { class: "value", cx: 66, cy: 66, r, "stroke-dasharray": circumference.toFixed(2), "stroke-dashoffset": circumference.toFixed(2) });
  const ring = h(
    "div",
    { class: `ring ${scoreClass(percent)}` },
    svg("svg", { viewBox: "0 0 132 132", role: "img", "aria-label": `Health ${percentText(score)}` }, svg("circle", { class: "track", cx: 66, cy: 66, r }), value),
    h("div", { class: "label" }, h("b", { text: percentText(score) }), h("span", { text: "health" })),
  );
  if (percent !== null) {
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        value.style.strokeDashoffset = (circumference * (1 - Math.max(0, Math.min(100, percent)) / 100)).toFixed(2);
      }),
    );
  }
  return ring;
}

function durationText(scan) {
  if (!scan.started_at || !scan.finished_at) return "n/a";
  const seconds = Math.max(0, Math.round((new Date(scan.finished_at) - new Date(scan.started_at)) / 1000));
  return seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
}

function stat(label, big, sub, cls = "") {
  return h("div", { class: "stat" }, h("div", { class: "label", text: label }), h("div", { class: `big ${cls}`.trim(), text: big }), sub ? h("div", { class: "muted", text: sub }) : null);
}

function heroSection(scan) {
  const gate = scan.gate;
  const passed = gate && gate.passed;
  const badge = gate
    ? h("div", { class: `gate-badge ${passed ? "pass" : "fail"}` }, icon(passed ? "check" : "x", "sm"), passed ? "Quality gate passed" : "Quality gate failed")
    : null;
  return h(
    "div",
    { class: "hero" },
    h(
      "div",
      { class: "panel score-card" },
      scoreRing(scan.score),
      h(
        "div",
        { class: "score-meta" },
        badge,
        scan.score ? h("div", { class: "muted", text: `${scan.score.scanners_ok} of ${scan.score.scanners_total} scanners ran` }) : null,
      ),
    ),
    h(
      "div",
      { class: "stats" },
      stat("Findings that count", String(scan.counted_count ?? 0), `${scan.suppressed_count || 0} suppressed`),
      scan.diff ? stat(`Diff ${scan.diff.base}...${scan.diff.head}`, `${scan.diff.new_count} new`, `${scan.diff.existing_count} existing, ${scan.diff.fixed_count} fixed`) : null,
      scan.baseline ? stat("Against baseline", `${scan.baseline.new_count} new`, `${scan.baseline.existing_count} accepted`) : null,
      stat("Duration", durationText(scan), scan.finished_at ? when(scan.finished_at) : null),
      scan.metrics && scan.metrics.duplication_percent !== undefined
        ? stat("Duplication", `${scan.metrics.duplication_percent.toFixed(1)}%`, "of source lines")
        : null,
    ),
  );
}

function toolsTable(scan) {
  return h(
    "table",
    {},
    h("thead", {}, h("tr", {}, ["Scanner", "Status", "Findings", "Seconds", "Note"].map((t) => h("th", { text: t })))),
    h(
      "tbody",
      {},
      scan.tools.map((t) =>
        h(
          "tr",
          {},
          h("td", { class: "title", text: t.tool }),
          h("td", {}, statusPill(t.status)),
          h("td", { text: t.finding_count }),
          h("td", { text: t.duration_seconds.toFixed(1) }),
          h("td", { class: "muted", text: t.message }),
        ),
      ),
    ),
  );
}

function snippetView(finding) {
  const s = finding.snippet;
  if (!s) {
    return h("p", {
      class: "muted",
      text:
        finding.category === "secret" || finding.category === "pii"
          ? "Source lines are not shown for secrets or personal data."
          : "No source lines available.",
    });
  }
  return h(
    "pre",
    { class: "snippet" },
    s.lines.map((line, index) => {
      const number = s.start_line + index;
      const hit = number >= s.highlight_start && number <= s.highlight_end;
      return h(
        "div",
        { class: hit ? "line hl" : "line" },
        h("span", { class: "no", text: number }),
        h("span", { class: "src", text: line || " " }),
      );
    }),
  );
}

function fact(name, value) {
  return value === null || value === undefined || value === "" ? [] : [h("dt", { text: name }), h("dd", { text: value })];
}

async function suppressionFor(scan, finding) {
  const all = await api("/suppressions");
  return all.find((s) => s.scope === scan.scope && s.fingerprint === finding.fingerprint) || null;
}

function detailPlaceholder() {
  return h("div", { class: "panel detail" }, emptyState("pointer", "Select a finding", "Its source lines, rule and fix appear here."));
}

function detailPanel(scan, finding, reload) {
  const msg = h("div");
  const parts = [
    h("div", { class: "row" }, sevPill(finding.severity), h("span", { class: "tag", text: finding.category }), finding.is_new === true ? h("span", { class: "tag", text: "new" }) : null),
    h("h2", { text: finding.title }),
    h(
      "dl",
      { class: "facts" },
      fact("Where", whereText(finding)),
      fact("Found by", (finding.sources || [finding.tool]).join(", ")),
      fact("Rule", finding.rule_id),
      fact("Package", finding.package ? `${finding.package} ${finding.version || ""}`.trim() : ""),
      fact("Fixed in", finding.fixed_version),
      fact("Fingerprint", finding.fingerprint),
    ),
    finding.message ? h("p", { text: finding.message }) : null,
    snippetView(finding),
  ];
  const slot = h("div");
  parts.push(slot, msg);
  if (finding.suppressed) {
    slot.append(
      h("div", { class: "banner" }, icon("alert", "sm"), h("span", { text: `Suppressed until ${finding.suppressed.expires}: ${finding.suppressed.reason}` })),
    );
    const remove = h("button", {
      class: "danger",
      text: "Remove suppression",
      onclick: async () => {
        remove.disabled = true;
        try {
          const found = await suppressionFor(scan, finding);
          if (!found) throw new Error("suppression not found");
          await api(`/suppressions/${found.id}`, { method: "DELETE" });
          await reload();
        } catch (error) {
          if (error instanceof AuthError) throw error;
          msg.replaceChildren(errorBanner(error.message));
          remove.disabled = false;
        }
      },
    });
    slot.append(remove);
  } else if (finding.fingerprint) {
    const reason = h("input", { type: "text", maxlength: "500", required: true, size: 40, placeholder: "Why is this acceptable?", "aria-label": "Reason" });
    const expiry = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    const maxDate = new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10);
    const expires = h("input", { type: "date", value: expiry, max: maxDate, min: new Date(Date.now() + 86400000).toISOString().slice(0, 10), required: true, "aria-label": "Review by" });
    slot.append(
      h("h2", { text: "Suppress this finding" }),
      h(
        "form",
        {
          onsubmit: async (event) => {
            event.preventDefault();
            try {
              await api("/suppressions", {
                method: "POST",
                body: { scan_id: scan.id, fingerprint: finding.fingerprint, reason: reason.value, expires: expires.value },
              });
              await reload();
            } catch (error) {
              if (error instanceof AuthError) throw error;
              msg.replaceChildren(errorBanner(error.message));
            }
          },
        },
        h("div", { class: "row" }, reason, h("label", { class: "inline", text: "Review by " }, expires), h("button", { type: "submit", text: "Suppress" })),
        h("p", { class: "muted", text: "It stays listed, stops counting toward the gate, and is shown again after the review date." }),
      ),
    );
  }
  return h("div", { class: "panel detail" }, ...parts);
}

function filterBar(scan, refresh) {
  const select = (label, key, options) =>
    h(
      "label",
      { class: "inline" },
      label,
      h(
        "select",
        {
          onchange: (event) => {
            filters[key] = event.target.value;
            filters.page = 0;
            refresh();
          },
        },
        options.map(([value, text]) => h("option", { value, text, selected: filters[key] === value })),
      ),
    );
  return h(
    "div",
    { class: "row" },
    select("Severity", "severity", [["", "All"], ...SEVERITIES.map((s) => [s, s])]),
    select("Category", "category", [["", "All"], ...CATEGORIES.map((s) => [s, s])]),
    select("Scanner", "tool", [["", "All"], ...TOOLS.map((s) => [s, s])]),
    scan.base || scan.baseline_id
      ? select("Origin", "isNew", [["", "All"], ["true", "New only"], ["false", "Existing only"]])
      : null,
    select("Suppressed", "suppressed", [["false", "Hide"], ["true", "Only"], ["", "Show all"]]),
  );
}

// ---------------------------------------------------------------- live progress

const TOOL_INFO = {
  osv: ["OSV-Scanner", "Dependency vulnerabilities"],
  semgrep: ["Semgrep", "Bugs and security patterns"],
  gitleaks: ["Gitleaks", "Secrets"],
  trivy: ["Trivy", "Vulnerabilities, secrets, IaC"],
  jscpd: ["jscpd", "Duplicated code"],
  lizard: ["Lizard", "Complexity"],
  checkov: ["Checkov", "IaC and Docker"],
  presidio: ["Presidio", "Personal data"],
  trufflehog: ["TruffleHog", "Verified secrets"],
};

const FINAL_STATES = new Set(["ok", "failed", "timeout", "skipped"]);

function secondsText(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}

// Live progress per scanner; once the scan is done, the stored per-tool results are authoritative.
function toolEntries(scan) {
  const entries = (scan.progress || []).map((p) => ({ ...p }));
  const byName = new Map(entries.map((e) => [e.tool, e]));
  if (scan.status === "done" || scan.status === "failed") {
    for (const t of scan.tools || []) {
      let entry = byName.get(t.tool);
      if (!entry) {
        entry = { tool: t.tool, passes: 1, passes_done: 1, started_at: null };
        byName.set(t.tool, entry);
        entries.push(entry);
      }
      Object.assign(entry, {
        state: t.status,
        passes_done: entry.passes || 1,
        finding_count: t.finding_count,
        duration_seconds: t.duration_seconds,
        message: t.message || "",
      });
    }
  }
  return entries;
}

function toolCard(tool) {
  const [name, what] = TOOL_INFO[tool] || [tool, ""];
  const badge = h("div", { class: "tool-badge" });
  const status = h("span", { class: "tool-status" });
  const fill = h("div", { class: "fill" });
  const bar = h("div", { class: "pbar", role: "progressbar", "aria-label": `${name} progress`, "aria-valuemin": "0", "aria-valuemax": "100" }, fill);
  const meta = h("div", { class: "tool-meta" });
  const note = h("div", { class: "tool-note" });
  const card = h(
    "div",
    { class: "tool-card waiting" },
    h("div", { class: "tool-head" }, badge, h("div", { class: "tool-name" }, h("b", { text: name }), h("span", { text: what })), status),
    bar,
    meta,
    note,
  );
  let last = null;
  function update(entry, now) {
    const state = entry.state || "waiting";
    const passes = entry.passes || 1;
    const done = Math.min(passes, entry.passes_done || 0);
    if (state !== last) {
      card.className = `tool-card ${state}`;
      const iconName = { waiting: "clock", ok: "check", failed: "x", timeout: "x", skipped: "minus" }[state];
      badge.replaceChildren(state === "running" ? h("span", { class: "mini-spin" }) : icon(iconName || "clock", "sm"));
      status.textContent = { waiting: "Waiting", running: "Running", ok: "Complete", failed: "Failed", timeout: "Timed out", skipped: "Skipped" }[state] || state;
      last = state;
    }
    const percent = FINAL_STATES.has(state) ? 100 : Math.round((done / passes) * 100);
    fill.style.width = `${percent}%`;
    bar.setAttribute("aria-valuenow", String(percent));
    let text = "";
    if (state === "running") {
      const elapsed = entry.started_at ? (now - new Date(entry.started_at)) / 1000 : 0;
      text = `${secondsText(elapsed)} elapsed`;
      if (passes > 1) text += ` · ${done ? "head" : "base"} revision (${done + 1} of ${passes})`;
    } else if (FINAL_STATES.has(state)) {
      const parts = [];
      if (state === "ok" && entry.finding_count !== null && entry.finding_count !== undefined) {
        parts.push(`${entry.finding_count} ${entry.finding_count === 1 ? "finding" : "findings"}`);
      }
      if (entry.duration_seconds !== null && entry.duration_seconds !== undefined) parts.push(`${entry.duration_seconds.toFixed(1)}s`);
      text = parts.join(" · ");
    } else {
      text = "Queued to start";
    }
    meta.textContent = text;
    note.textContent = state === "ok" ? "" : entry.message || "";
  }
  return { card, update };
}

// Watch every scanner live; when the scan ends, keep the cards and offer the full report.
function progressPage(token, scanId, first) {
  watched.add(scanId);
  const title = h("h1");
  const sub = h("div", { class: "sub", text: first.source || "" });
  const overallFill = h("div", { class: "fill" });
  const overallBar = h("div", { class: "pbar big", role: "progressbar", "aria-label": "Overall progress", "aria-valuemin": "0", "aria-valuemax": "100" }, overallFill);
  const overallText = h("span", { class: "muted" });
  const overallPct = h("b");
  const grid = h("div", { class: "tool-grid" });
  const notice = h("div");
  const finish = h("div", { class: "finish hidden" });
  const cards = new Map();
  let current = first;

  function draw() {
    const scan = current;
    const now = Date.now();
    const entries = toolEntries(scan);
    const active = scan.status === "queued" || scan.status === "running";
    for (const entry of entries) {
      if (!cards.has(entry.tool)) {
        const made = toolCard(entry.tool);
        cards.set(entry.tool, made);
        grid.append(made.card);
      }
      cards.get(entry.tool).update(entry, now);
    }

    const total = entries.reduce((sum, e) => sum + (e.passes || 1), 0);
    const doneUnits = entries.reduce((sum, e) => sum + (FINAL_STATES.has(e.state) ? e.passes || 1 : Math.min(e.passes || 1, e.passes_done || 0)), 0);
    const finished = entries.filter((e) => FINAL_STATES.has(e.state)).length;
    const percent = scan.status === "done" ? 100 : total ? Math.round((doneUnits / total) * 100) : 0;
    overallFill.style.width = `${percent}%`;
    overallBar.setAttribute("aria-valuenow", String(percent));
    overallBar.classList.toggle("complete", scan.status === "done");
    overallBar.classList.toggle("failed", scan.status === "failed");
    overallPct.textContent = `${percent}%`;
    const elapsed = scan.started_at ? secondsText(((scan.finished_at ? new Date(scan.finished_at) : now) - new Date(scan.started_at)) / 1000) : "";

    if (scan.status === "queued") {
      title.textContent = "Waiting for a worker";
      overallText.textContent = "Queued. Start `scanner worker` if nothing picks this up.";
    } else if (scan.status === "running") {
      title.textContent = "Scanning";
      overallText.textContent = entries.length
        ? `${finished} of ${entries.length} scanners finished${elapsed ? ` · ${elapsed}` : ""}`
        : "Preparing the sandbox...";
    } else if (scan.status === "done") {
      title.textContent = "Scan complete";
      overallText.textContent = `${entries.length} scanners finished${elapsed ? ` in ${elapsed}` : ""}`;
    } else {
      title.textContent = "Scan failed";
      overallText.textContent = elapsed ? `Stopped after ${elapsed}` : "Stopped";
    }

    if (!entries.length && active) {
      if (!grid.querySelector(".ghost")) grid.replaceChildren(...Array.from({ length: 6 }, () => h("div", { class: "tool-card ghost" }, h("div", { class: "skeleton" }), h("div", { class: "skeleton short" }))));
    } else if (entries.length) {
      for (const ghost of grid.querySelectorAll(".ghost")) ghost.remove();
    }

    if (scan.status === "failed") {
      notice.replaceChildren(errorBanner(scan.error || "unknown error"));
    }
    if (scan.status === "done" && finish.classList.contains("hidden")) {
      const gate = scan.gate;
      const failedTools = entries.filter((e) => e.state !== "ok").length;
      finish.replaceChildren(
        h("div", { class: "finish-check" }, icon("check")),
        h("b", { text: "All scanners finished" }),
        h(
          "span",
          { class: "muted" },
          `${scan.counted_count ?? 0} ${scan.counted_count === 1 ? "finding counts" : "findings count"}`,
          failedTools ? ` · ${failedTools} ${failedTools === 1 ? "scanner" : "scanners"} did not run cleanly` : "",
        ),
        gate ? h("span", { class: `pill ${gate.passed ? "passed" : "failed"}`, text: gate.passed ? "Quality gate passed" : "Quality gate failed" }) : null,
        h(
          "button",
          {
            class: "primary",
            onclick: () => {
              watched.delete(scanId);
              route();
            },
          },
          h("span", { text: "View full report" }),
          icon("arrowRight", "sm"),
        ),
      );
      finish.classList.remove("hidden");
    }
  }

  show(
    shell(
      "history",
      h("div", { class: "page-head" }, h("div", {}, title, sub)),
      h("div", { class: "panel overall" }, h("div", { class: "overall-head" }, overallText, overallPct), overallBar),
      notice,
      grid,
      finish,
    ),
  );
  draw();

  async function poll() {
    try {
      const scan = await api(`/scans/${scanId}`);
      if (token !== renderToken) return;
      current = scan;
      draw();
      if (scan.status === "queued" || scan.status === "running") timer = setTimeout(poll, 1500);
      else if (ticker) {
        clearInterval(ticker);
        ticker = null;
      }
    } catch (error) {
      if (token === renderToken) handleError(error);
    }
  }
  if (first.status === "queued" || first.status === "running") {
    timer = setTimeout(poll, 1500);
    ticker = setInterval(() => token === renderToken && draw(), 1000);
  }
}

async function scanView(token, scanId) {
  const scan = await api(`/scans/${scanId}`);
  if (token !== renderToken) return;
  if (scan.status === "queued" || scan.status === "running" || watched.has(scanId)) {
    progressPage(token, scanId, scan);
    return;
  }
  if (scan.status === "failed") {
    show(shell("history", pageHead("Scan failed", scan.source || ""), errorBanner(scan.error || "unknown error")));
    return;
  }
  const state = { selected: null };
  if (filters.scanId !== scanId) {
    Object.assign(filters, { severity: "", category: "", tool: "", isNew: "", suppressed: "false", page: 0, scanId });
  }
  const list = h("div");
  const detail = h("div", { class: "detail-wrap" }, detailPlaceholder());

  async function loadFindings() {
    const data = await api(
      `/scans/${scanId}/findings${query({
        severity: filters.severity,
        category: filters.category,
        tool: filters.tool,
        new: filters.isNew,
        suppressed: filters.suppressed,
        limit: PAGE,
        offset: filters.page * PAGE,
      })}`,
    );
    if (token !== renderToken) return;
    const pages = Math.max(1, Math.ceil(data.total / PAGE));
    const rows = data.items.map((finding) =>
      h(
        "tr",
        {
          class: `click sev-${finding.severity} ${state.selected && state.selected.id === finding.id ? "selected" : ""}`,
          onclick: (event) => {
            state.selected = finding;
            detail.replaceChildren(detailPanel(scan, finding, reload));
            for (const tr of list.querySelectorAll("tr.click")) tr.classList.toggle("selected", tr === event.currentTarget);
          },
        },
        h("td", {}, sevPill(finding.severity)),
        h("td", {}, h("div", { class: "title", text: finding.title }), h("div", { class: "path mono", text: whereText(finding) })),
        h("td", {}, (finding.sources || [finding.tool]).map((t) => h("span", { class: "tag", text: t }))),
      ),
    );
    list.replaceChildren(
      h(
        "div",
        { class: "panel flush" },
        data.items.length
          ? h("table", {}, h("thead", {}, h("tr", {}, ["Severity", "Finding", "Found by"].map((t) => h("th", { text: t })))), h("tbody", {}, rows))
          : emptyState("check", "No findings match", "Try clearing a filter."),
        h(
          "div",
          { class: "pager" },
          h("button", { class: "small", disabled: filters.page === 0, onclick: () => { filters.page -= 1; loadFindings().catch(handleError); }, text: "Previous" }),
          h("span", { class: "muted", text: `${data.total} findings, page ${filters.page + 1} of ${pages}` }),
          h("button", { class: "small", disabled: filters.page + 1 >= pages, onclick: () => { filters.page += 1; loadFindings().catch(handleError); }, text: "Next" }),
        ),
      ),
    );
    if (state.selected) {
      const fresh = data.items.find((f) => f.id === state.selected.id);
      if (fresh) {
        state.selected = fresh;
        detail.replaceChildren(detailPanel(scan, fresh, reload));
      } else {
        state.selected = null;
        detail.replaceChildren(detailPlaceholder());
      }
    }
  }

  const reportBox = h("div");
  const base = `/scans/${scanId}/report`;
  const embedLabel = h("span", { text: "Show report" });
  const embed = h(
    "button",
    {
      onclick: () => {
        if (reportBox.firstChild) {
          reportBox.replaceChildren();
          embedLabel.textContent = "Show report";
        } else {
          reportBox.append(h("iframe", { class: "report", src: `${base}?format=html`, title: "HTML report" }));
          embedLabel.textContent = "Hide report";
        }
      },
    },
    icon("eye", "sm"),
    embedLabel,
  );
  const baselineMsg = h("div");
  const baselineBox = h("div", { class: "hidden panel" });
  const nameInput = h("input", { type: "text", maxlength: "100", required: true, placeholder: "Baseline name", "aria-label": "Baseline name" });
  baselineBox.append(
    h(
      "form",
      {
        onsubmit: async (event) => {
          event.preventDefault();
          try {
            const made = await api(`/scans/${scanId}/baseline`, { method: "POST", body: { name: nameInput.value } });
            baselineMsg.replaceChildren(h("div", { class: "banner ok" }, icon("check", "sm"), h("span", { text: `Baseline "${made.name}" saved with ${made.size} findings. Pick it when starting a scan.` })));
            baselineBox.classList.add("hidden");
          } catch (error) {
            if (error instanceof AuthError) throw error;
            baselineMsg.replaceChildren(errorBanner(error.message));
          }
        },
      },
      h("p", { class: "muted", text: "Accept today's findings so later scans only fail on new ones." }),
      h("div", { class: "row" }, nameInput, h("button", { class: "primary", type: "submit", text: "Save baseline" })),
    ),
  );

  const summary = h("div");
  function drawSummary(s) {
    summary.replaceChildren(
      ...[
        ...s.notices.map((n) => h("div", { class: "banner" }, icon("alert", "sm"), h("span", { text: n }))),
        heroSection(s),
        s.gate && s.gate.reasons.length
          ? h("div", { class: "banner error" }, icon("alert", "sm"), h("div", {}, s.gate.reasons.map((r) => h("div", { text: r }))))
          : null,
        h(
          "div",
          { class: "split" },
          h("div", { class: "panel" }, h("h2", { text: "By severity" }), severityStack(s.by_severity)),
          h("div", { class: "panel" }, h("h2", { text: "By category" }), barChart(s.by_category, CATEGORIES)),
        ),
      ].filter(Boolean),
    );
  }
  drawSummary(scan);
  // A suppression changes the gate and counts, so refresh those along with the list.
  async function reload() {
    drawSummary(await api(`/scans/${scanId}`));
    await loadFindings();
  }

  show(
    shell(
      "history",
      pageHead(
        scan.source || "Scan",
        `${when(scan.finished_at)}${scan.base ? ` · diff against ${scan.base}` : ""}`,
        embed,
        ["md", "json", "sarif"].map((f) => h("a", { class: "btn", href: `${base}?format=${f}` }, icon("download", "sm"), f.toUpperCase())),
        h("a", { class: "btn", href: `${base}?format=html`, target: "_blank", rel: "noopener" }, icon("external", "sm"), "Open HTML"),
        h("button", { onclick: () => baselineBox.classList.toggle("hidden") }, icon("bookmark", "sm"), "Save as baseline"),
      ),
      summary,
      baselineBox,
      baselineMsg,
      reportBox,
      h("div", { class: "section-title" }, h("h2", { text: "Findings" }), filterBar(scan, () => loadFindings().catch(handleError))),
      h("div", { class: "split findings" }, list, detail),
      h("h2", { text: "Scanners" }),
      h("div", { class: "panel flush" }, toolsTable(scan)),
    ),
  );
  await loadFindings();
}

// ---------------------------------------------------------------- trends

function trendChart(points, kind) {
  const W = 720, H = 240, L = 44, R = 14, T = 14, B = 30;
  const values = points.map((p) => (kind === "score" ? p.score_percent : p.counted));
  const max = kind === "score" ? 100 : Math.max(1, ...values.map((v) => v || 0));
  const x = (i) => (points.length === 1 ? (L + W - R) / 2 : L + 24 + (i * (W - L - R - 48)) / (points.length - 1));
  const y = (v) => T + (1 - (v || 0) / max) * (H - T - B);
  const chart = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": kind === "score" ? "Health score over time" : "Findings over time" });
  for (const frac of [0, 0.5, 1]) {
    const gy = T + (1 - frac) * (H - T - B);
    chart.append(svg("line", { class: "grid", x1: L, x2: W - R, y1: gy, y2: gy }), svgText(L - 8, gy + 4, Math.round(max * frac) + (kind === "score" ? "%" : ""), "end"));
  }
  if (kind === "score") {
    const known = points.map((p, i) => ({ p, i })).filter(({ p }) => p.score_percent !== null);
    if (known.length) {
      const line = known.map(({ p, i }, n) => `${n ? "L" : "M"}${x(i)},${y(p.score_percent)}`).join(" ");
      const floor = H - B;
      chart.append(svg("path", { class: "area", d: `${line} L${x(known[known.length - 1].i)},${floor} L${x(known[0].i)},${floor} Z` }), svg("path", { class: "line", d: line }));
    }
  }
  const barWidth = Math.max(4, Math.min(30, (W - L - R) / Math.max(1, points.length) - 4));
  points.forEach((p, i) => {
    const value = kind === "score" ? p.score_percent : p.counted;
    if (value === null || value === undefined) return;
    const open = () => location_hash(`#/scan/${p.scan_id}`);
    const label = `${when(p.at)}: ${kind === "score" ? `${Math.round(value)}%` : `${value} findings`}${p.gate_passed === false ? " (gate failed)" : ""}`;
    const title = svg("title");
    title.textContent = label;
    if (kind === "score") {
      const dot = svg("circle", { class: p.gate_passed === false ? "dot fail" : "dot", cx: x(i), cy: y(value), r: 5 }, title);
      dot.addEventListener("click", open);
      chart.append(dot);
    } else {
      const col = svg("rect", { class: "col", rx: 4, x: x(i) - barWidth / 2, y: y(value), width: barWidth, height: Math.max(2, H - B - y(value)) }, title);
      col.addEventListener("click", open);
      chart.append(col);
    }
  });
  if (points.length) {
    chart.append(svgText(L, H - 8, new Date(points[0].at).toLocaleDateString(), "start"), svgText(W - R, H - 8, new Date(points[points.length - 1].at).toLocaleDateString(), "end"));
  }
  return chart;
}

async function trendsView(token) {
  const sources = await api("/sources");
  if (token !== renderToken) return;
  const wanted = new URLSearchParams(window.location.hash.split("?")[1] || "").get("source") || (sources[0] && sources[0].source) || "";
  const content = [];
  if (!sources.length) {
    content.push(pageHead("Trends", "Health and findings over time"));
    content.push(h("div", { class: "panel" }, emptyState("trend", "Nothing to chart yet", "Finish a scan and its history shows up here.", h("a", { class: "btn primary", href: "#/new" }, icon("plus", "sm"), "Start a scan"))));
  } else {
    const select = h(
      "select",
      { onchange: (event) => location_hash(`#/trends?${new URLSearchParams({ source: event.target.value })}`), "aria-label": "Source" },
      sources.map((s) => h("option", { value: s.source, text: `${s.source} (${s.scans} scans)`, selected: s.source === wanted })),
    );
    content.push(pageHead("Trends", "Health and findings over time", select));
    const trend = await api(`/trends${query({ source: wanted })}`);
    if (token !== renderToken) return;
    if (!trend.points.length) {
      content.push(h("div", { class: "panel" }, emptyState("trend", "No finished scans for this source yet", "")));
    } else {
      content.push(
        h("div", { class: "panel" }, h("h2", { text: "Health score" }), trendChart(trend.points, "score"), h("div", { class: "legend-inline" }, h("span", {}, h("i", {}), "Gate passed"), h("span", {}, h("i", { class: "fail" }), "Gate failed"), h("span", { text: "Click a point to open the scan." }))),
        h("div", { class: "panel" }, h("h2", { text: "Findings that count" }), trendChart(trend.points, "count")),
      );
    }
  }
  show(shell("trends", ...content));
}

// ---------------------------------------------------------------- suppressions and baselines

async function policyView(token) {
  const [suppressions, baselines] = await Promise.all([api("/suppressions"), api("/baselines")]);
  if (token !== renderToken) return;
  const del = (path) => async () => {
    try {
      await api(path, { method: "DELETE" });
      await policyView(++renderToken);
    } catch (error) {
      handleError(error);
    }
  };
  const table = (headers, rows, emptyTitle, emptyHint) =>
    rows.length
      ? h("table", {}, h("thead", {}, h("tr", {}, headers.map((t) => h("th", { text: t })))), h("tbody", {}, rows))
      : emptyState("policy", emptyTitle, emptyHint);
  show(
    shell(
      "policy",
      pageHead("Suppressions and baselines", "Accepted risk, with a review date and a reason"),
      h("div", { class: "section-title" }, h("h2", { text: "Suppressions" })),
      h(
        "div",
        { class: "panel flush" },
        table(
          ["Source", "Fingerprint", "Reason", "Review by", ""],
          suppressions.map((s) =>
            h(
              "tr",
              {},
              h("td", { class: "mono", text: s.scope }),
              h("td", { class: "mono", text: s.fingerprint }),
              h("td", { text: s.reason }),
              h("td", {}, h("span", { class: s.expired ? "pill failed" : "", text: s.expired ? `${s.expires} (expired)` : s.expires })),
              h("td", {}, h("button", { class: "danger small", onclick: del(`/suppressions/${s.id}`), text: "Remove" })),
            ),
          ),
          "No suppressions",
          "Open a finding in a scan to suppress it.",
        ),
      ),
      h("div", { class: "section-title" }, h("h2", { text: "Baselines" })),
      h(
        "div",
        { class: "panel flush" },
        table(
          ["Name", "Source", "Findings", "Created", ""],
          baselines.map((b) =>
            h(
              "tr",
              {},
              h("td", { class: "title", text: b.name }),
              h("td", { class: "mono", text: b.source }),
              h("td", { text: b.size }),
              h("td", { text: when(b.created_at) }),
              h("td", {}, h("button", { class: "danger small", onclick: del(`/baselines/${b.id}`), text: "Delete" })),
            ),
          ),
          "No baselines",
          "Open a scan and choose Save as baseline.",
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------- routing

function handleError(error) {
  if (error instanceof AuthError) {
    if (window.location.hash !== "#/login") window.location.hash = "#/login";
    else loginView();
    return;
  }
  show(shell("", errorBanner(error.message || "something went wrong")));
}

async function route() {
  clearTimer();
  const token = ++renderToken;
  const hash = window.location.hash || "#/";
  const path = hash.split("?")[0];
  try {
    if (path === "#/login") {
      loginView();
    } else if (path === "#/new") {
      await newScanView(token);
    } else if (path === "#/trends") {
      await trendsView(token);
    } else if (path === "#/policy") {
      await policyView(token);
    } else if (path.startsWith("#/scan/")) {
      const id = path.slice("#/scan/".length);
      if (!/^[0-9a-f]{32}$/.test(id)) throw new Error("not a valid scan id");
      await scanView(token, id);
    } else {
      await historyView(token);
    }
  } catch (error) {
    handleError(error);
  }
}

window.addEventListener("hashchange", route);
route();
