/* ============================================================
   SENTINEL — CDR / IPDR Spreadsheet Engine
   Pure-JS, dependency-free. Handles large datasets via row
   virtualization. Features: search, per-column filter (multi-
   select + text), sort, hide/show, freeze, pagination, export,
   charts, and forensic enrichment derived from the reference
   DB structures (cell-id, handset TAC, operator/circle codes).
   ============================================================ */
(() => {
"use strict";

// ---------- tiny helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const debounce = (fn, ms = 180) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
function toast(msg, err = false) { const t = $("#toast"); t.textContent = msg; t.classList.toggle("err", err); t.classList.add("show"); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("show"), 2600); }
function fmtInt(n) { return (n ?? 0).toLocaleString("en-IN"); }
function fmtDur(sec) { sec = +sec || 0; const h = (sec / 3600) | 0, m = ((sec % 3600) / 60) | 0, s = sec % 60; return h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`; }

// ---------- reference maps (from uploaded DB structures) ----------
// Operator / circle codes are illustrative seeds; the server enriches
// against the full SDR / MSC / LRN reference tables on import.
const OPERATOR = { 1: "Airtel", 2: "Vodafone Idea", 3: "Jio", 4: "BSNL", 5: "MTNL" };
const CIRCLE = { 1: "Delhi", 2: "Mumbai", 3: "Maharashtra", 4: "Gujarat", 5: "Karnataka", 6: "Tamil Nadu", 7: "West Bengal", 8: "Chhattisgarh", 9: "Madhya Pradesh", 10: "Uttar Pradesh" };
// IMEI TAC (first 8 digits) -> handset.  Real lookup uses handset db (TAC,Desc).
const TAC = { "35315110": "Apple iPhone", "86891803": "Samsung Galaxy", "35692611": "Xiaomi Redmi", "86234405": "OnePlus", "35404209": "Vivo", "86997404": "Oppo", "35876110": "Realme" };
function handsetFromImei(imei) { if (!imei) return ""; const t = String(imei).replace(/\D/g, "").slice(0, 8); return TAC[t] || ""; }
function operatorName(c) { return OPERATOR[+c] || (c ? `Op-${c}` : ""); }
function circleName(c) { return CIRCLE[+c] || (c ? `Circle-${c}` : ""); }

// ---------- column model per mode ----------
// enriched:true columns are derived, not from the raw file.
const SCHEMAS = {
  cdr: [
    { key: "a", label: "A-Party", aliases: ["calling_number", "a_party", "caller", "msisdn", "number"] },
    { key: "b", label: "B-Party", aliases: ["called_number", "b_party", "callee", "called"] },
    { key: "type", label: "Type", aliases: ["call_type", "type", "direction"] },
    { key: "dt", label: "Date/Time", aliases: ["date_time", "call_date", "start_time", "timestamp", "date", "datetime"] },
    { key: "dur", label: "Duration(s)", aliases: ["duration", "call_duration", "dur"], num: true },
    { key: "imei", label: "IMEI", aliases: ["imei"] },
    { key: "handset", label: "Handset", enriched: true },
    { key: "imsi", label: "IMSI", aliases: ["imsi"] },
    { key: "lac", label: "LAC", aliases: ["lac", "first_lac"] },
    { key: "cid", label: "Cell ID", aliases: ["cid", "cell_id", "cellid", "first_cell_id"] },
    { key: "tower", label: "Tower / Address", enriched: true, aliases: ["tower_address", "address", "site_address"] },
    { key: "operator", label: "Operator", enriched: true, aliases: ["operator"] },
    { key: "circle", label: "Circle", enriched: true, aliases: ["circle"] },
  ],
  ipdr: [
    { key: "sub", label: "Subscriber", aliases: ["msisdn", "subscriber_number", "subscriber", "mobile_number"] },
    { key: "sip", label: "Source IP", aliases: ["source_ip", "src_ip", "private_ip"] },
    { key: "dip", label: "Dest IP", aliases: ["dest_ip", "destination_ip", "server_ip", "public_ip"] },
    { key: "sport", label: "Src Port", aliases: ["source_port", "src_port"] },
    { key: "dport", label: "Dst Port", aliases: ["dest_port", "destination_port"] },
    { key: "proto", label: "Protocol", aliases: ["protocol", "app_protocol", "service_type"] },
    { key: "dt", label: "Start Time", aliases: ["start_time", "date_time", "timestamp", "session_start"] },
    { key: "bytes", label: "Bytes", aliases: ["bytes_transferred", "data_volume", "bytes", "total_bytes"], num: true },
    { key: "imei", label: "IMEI", aliases: ["imei"] },
    { key: "handset", label: "Handset", enriched: true },
    { key: "lac", label: "LAC", aliases: ["lac"] },
    { key: "cid", label: "Cell ID", aliases: ["cid", "cell_id"] },
    { key: "tower", label: "Tower / Address", enriched: true, aliases: ["tower_address", "address"] },
  ],
};

// ---------- date parsing ----------
const DATE_FMTS = [/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/, /^(\d{2})-(\d{2})-(\d{4})[ T](\d{2}):(\d{2})/, /^(\d{2})\/(\d{2})\/(\d{4})[ T](\d{2}):(\d{2})/, /^(\d{4})\/(\d{2})\/(\d{2})[ T](\d{2}):(\d{2})/];
const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
function parseDT(s) {
  if (!s) return null;
  let m = DATE_FMTS[0].exec(s) || DATE_FMTS[3].exec(s);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
  m = DATE_FMTS[1].exec(s) || DATE_FMTS[2].exec(s);
  if (m) return new Date(+m[3], +m[2] - 1, +m[1], +m[4], +m[5]);
  const d = new Date(s); return isNaN(d) ? null : d;
}

// ---------- CSV parser (RFC-4180, streaming-friendly) ----------
function parseCSV(text) {
  const rows = []; let row = [], field = "", i = 0, inQ = false;
  const delim = text.indexOf("\t") > -1 && text.indexOf(",") === -1 ? "\t" : ",";
  while (i < text.length) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else {
      if (c === '"') inQ = true;
      else if (c === delim) { row.push(field); field = ""; }
      else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
      else if (c === "\r") { /* skip */ }
      else field += c;
    }
    i++;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.length && !(r.length === 1 && r[0] === ""));
}

// ---------- application state ----------
const state = {
  mode: "cdr",
  cols: [],          // active column defs (incl. enriched)
  rawHeaders: [],
  rows: [],          // array of objects keyed by col.key
  view: [],          // filtered + sorted indices into rows
  hidden: new Set(),
  frozen: 2,
  sort: { key: null, dir: 0 },   // dir: 1 asc, -1 desc
  filters: {},       // key -> {set:Set|null, text:string}
  search: "",
  page: 1,
  pageSize: 100,
};

// ---------- map raw row -> normalized object using schema aliases ----------
function buildColumns(headers) {
  const norm = headers.map(h => h.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, ""));
  const schema = SCHEMAS[state.mode];
  const cols = [];
  const usedRaw = new Set();
  for (const def of schema) {
    let rawIdx = -1;
    if (def.aliases) for (const a of def.aliases) { const idx = norm.indexOf(a); if (idx > -1) { rawIdx = idx; break; } }
    cols.push({ ...def, rawIdx });
    if (rawIdx > -1) usedRaw.add(rawIdx);
  }
  // append any unmapped raw columns so nothing is lost
  headers.forEach((h, idx) => {
    if (!usedRaw.has(idx) && !cols.some(c => c.rawIdx === idx)) {
      const exists = cols.find(c => c.label.toLowerCase() === h.toLowerCase());
      if (!exists) cols.push({ key: "x_" + idx, label: h || "Col " + (idx + 1), rawIdx: idx, extra: true });
    }
  });
  return cols;
}

function ingest(headers, dataRows) {
  state.rawHeaders = headers;
  state.cols = buildColumns(headers);
  state.hidden = new Set();
  state.sort = { key: null, dir: 0 };
  state.filters = {};
  state.search = "";
  state.page = 1;
  $("#globalSearch").value = "";

  const cols = state.cols;
  state.rows = dataRows.map(r => {
    const o = {};
    for (const c of cols) o[c.key] = c.rawIdx > -1 ? String(r[c.rawIdx] ?? "").trim() : "";
    // enrichment
    if (o.handset !== undefined && !o.handset) o.handset = handsetFromImei(o.imei);
    if (o.operator !== undefined) o.operator = o.operator && !isNaN(o.operator) ? operatorName(o.operator) : o.operator;
    if (o.circle !== undefined) o.circle = o.circle && !isNaN(o.circle) ? circleName(o.circle) : o.circle;
    if (o.tower !== undefined && !o.tower && (o.lac || o.cid)) o.tower = `LAC ${o.lac || "—"} · CID ${o.cid || "—"}`;
    // precompute searchable + datetime
    o.__dt = parseDT(o.dt);
    return o;
  });
  recompute();
  $("#emptyState").style.display = "none";
  $("#sheet").style.display = "";
  $("#insights").style.display = "";
  renderHead();
  updateKPIs();
  renderCharts();
  toast(`Loaded ${fmtInt(state.rows.length)} ${state.mode.toUpperCase()} records`);
}

// ---------- filter + sort pipeline ----------
function passesFilters(o) {
  for (const key in state.filters) {
    const f = state.filters[key];
    const val = String(o[key] ?? "");
    if (f.set && f.set.size && !f.set.has(val)) return false;
    if (f.text && !val.toLowerCase().includes(f.text.toLowerCase())) return false;
  }
  if (state.search) {
    const q = state.search.toLowerCase();
    let hit = false;
    for (const c of state.cols) { if (state.hidden.has(c.key)) continue; if (String(o[c.key] ?? "").toLowerCase().includes(q)) { hit = true; break; } }
    if (!hit) return false;
  }
  return true;
}
function recompute() {
  const out = [];
  for (let i = 0; i < state.rows.length; i++) if (passesFilters(state.rows[i])) out.push(i);
  if (state.sort.key) {
    const k = state.sort.key, dir = state.sort.dir;
    const col = state.cols.find(c => c.key === k);
    const numeric = col && (col.num);
    out.sort((ia, ib) => {
      let a = state.rows[ia][k], b = state.rows[ib][k];
      if (k === "dt") { a = state.rows[ia].__dt?.getTime() || 0; b = state.rows[ib].__dt?.getTime() || 0; }
      else if (numeric) { a = +a || 0; b = +b || 0; }
      else { a = String(a).toLowerCase(); b = String(b).toLowerCase(); }
      return a < b ? -dir : a > b ? dir : 0;
    });
  }
  state.view = out;
  const maxPage = Math.max(1, Math.ceil(state.view.length / (state.pageSize || state.view.length || 1)));
  if (state.page > maxPage) state.page = maxPage;
  renderBody();
  renderPager();
  renderFilterChips();
  updateKPIs();
  $("#matchInfo").textContent = state.view.length === state.rows.length
    ? `${fmtInt(state.rows.length)} rows`
    : `${fmtInt(state.view.length)} of ${fmtInt(state.rows.length)} match`;
  $("#btnClearFilters").style.display = (Object.keys(state.filters).length || state.search) ? "" : "none";
}

// ---------- render: header ----------
function renderHead() {
  const head = $("#sheetHead");
  let fx = 0; // cumulative left offset for frozen
  const ths = [`<th class="rownum frozen" style="left:0"><div class="th-inner" style="cursor:default"><span class="label">#</span></div></th>`];
  let leftAcc = 54;
  const visible = state.cols.filter(c => !state.hidden.has(c.key));
  visible.forEach((c, idx) => {
    const isFrozen = idx < state.frozen;
    const sortMark = state.sort.key === c.key ? (state.sort.dir === 1 ? "▲" : "▼") : "";
    const filtered = state.filters[c.key] ? "filtered" : "";
    const frozenCls = isFrozen ? "frozen" : "";
    const style = isFrozen ? `left:${leftAcc}px` : "";
    ths.push(
      `<th class="${frozenCls}" data-key="${c.key}" style="${style}">
        <div class="th-inner ${filtered}" data-act="sort" data-key="${c.key}">
          <span class="label" title="${esc(c.label)}">${esc(c.label)}${c.enriched ? " ✦" : ""}</span>
          <span class="sort">${sortMark}</span>
          <span class="menu" data-act="menu" data-key="${c.key}">⋮</span>
        </div>
      </th>`);
    if (isFrozen) leftAcc += 160; // approx; refined after layout below
  });
  head.innerHTML = `<tr>${ths.join("")}</tr>`;
  // precise frozen offsets after the row is in DOM
  requestAnimationFrame(applyFreezeOffsets);
}
function applyFreezeOffsets() {
  const headCells = $$("#sheetHead th");
  let left = 0;
  headCells.forEach((th, i) => {
    if (th.classList.contains("frozen")) { th.style.left = left + "px"; }
    left += th.offsetWidth;
    th._left = th.classList.contains("frozen") ? (left - th.offsetWidth) : null;
  });
  // apply same offsets to body frozen cells
  const offsets = headCells.map(th => th.classList.contains("frozen") ? th.style.left : null);
  $$("#sheetBody tr").forEach(tr => {
    [...tr.children].forEach((td, i) => { if (offsets[i] != null) td.style.left = offsets[i]; });
  });
}

// ---------- render: body (paginated window) ----------
function pageBounds() {
  const ps = state.pageSize || state.view.length;
  const start = ps ? (state.page - 1) * ps : 0;
  const end = ps ? Math.min(start + ps, state.view.length) : state.view.length;
  return { start, end };
}
function renderBody() {
  const body = $("#sheetBody");
  const { start, end } = pageBounds();
  const visible = state.cols.filter(c => !state.hidden.has(c.key));
  const q = state.search.toLowerCase();
  const frag = [];
  for (let vi = start; vi < end; vi++) {
    const ri = state.view[vi];
    const o = state.rows[ri];
    const tds = [`<td class="rownum frozen" style="left:0"><span class="cell">${vi + 1}</span></td>`];
    visible.forEach((c, idx) => {
      const isFrozen = idx < state.frozen;
      let v = esc(o[c.key] ?? "");
      if (q && v && v.toLowerCase().includes(q)) {
        const re = new RegExp("(" + q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
        v = v.replace(re, "<span class='hl'>$1</span>");
      }
      tds.push(`<td class="${isFrozen ? "frozen" : ""} ${c.enriched ? "col-enriched" : ""}"><span class="cell">${v}</span></td>`);
    });
    frag.push(`<tr>${tds.join("")}</tr>`);
  }
  body.innerHTML = frag.join("") || `<tr><td colspan="${visible.length + 1}" style="padding:30px;text-align:center;color:var(--muted)">No rows match the current filters.</td></tr>`;
  requestAnimationFrame(applyFreezeOffsets);
}

// ---------- render: pagination ----------
function renderPager() {
  const ps = state.pageSize || state.view.length || 1;
  const pages = Math.max(1, Math.ceil(state.view.length / ps));
  const cur = state.page;
  const mk = (p, lbl = p, on = false, dis = false) => `<button ${dis ? "disabled" : ""} class="${on ? "on" : ""}" data-p="${p}">${lbl}</button>`;
  let html = mk(cur - 1, "‹", false, cur <= 1);
  const set = new Set([1, pages, cur, cur - 1, cur + 1, cur - 2, cur + 2]);
  const list = [...set].filter(p => p >= 1 && p <= pages).sort((a, b) => a - b);
  let prev = 0;
  for (const p of list) { if (p - prev > 1) html += `<button disabled>…</button>`; html += mk(p, p, p === cur); prev = p; }
  html += mk(cur + 1, "›", false, cur >= pages);
  $("#pager").innerHTML = html;
  const { start, end } = pageBounds();
  $("#footStatus").textContent = state.view.length ? `Showing ${fmtInt(start + 1)}–${fmtInt(end)} of ${fmtInt(state.view.length)}` : "No rows";
}

// ---------- filter chips ----------
function renderFilterChips() {
  const bar = $("#filterbar");
  const chips = [];
  for (const key in state.filters) {
    const col = state.cols.find(c => c.key === key); if (!col) continue;
    const f = state.filters[key];
    let label = col.label + ": ";
    if (f.set && f.set.size) label += f.set.size === 1 ? [...f.set][0] : `${f.set.size} selected`;
    else if (f.text) label += `"${f.text}"`;
    chips.push(`<span class="chip active" data-rmfilter="${key}">${esc(label)} <span class="x">✕</span></span>`);
  }
  bar.innerHTML = chips.join("");
}

// ---------- KPIs ----------
function updateKPIs() {
  const rows = state.view.map(i => state.rows[i]);
  $("#kRecords").textContent = fmtInt(state.view.length);
  $("#kShown").textContent = state.view.length === state.rows.length ? "all records" : "after filters";
  const uniq = new Set();
  let durTotal = 0, durCount = 0;
  const bcount = {}, hour = new Array(24).fill(0), day = {};
  for (const o of rows) {
    if (state.mode === "cdr") { if (o.a) uniq.add(o.a); if (o.b) { uniq.add(o.b); bcount[o.b] = (bcount[o.b] || 0) + 1; } const d = +o.dur || 0; if (d > 0) { durTotal += d; durCount++; } }
    else { if (o.sub) uniq.add(o.sub); if (o.dip) { uniq.add(o.dip); bcount[o.dip] = (bcount[o.dip] || 0) + 1; } const b = +o.bytes || 0; if (b > 0) { durTotal += b; durCount++; } }
    if (o.__dt) { hour[o.__dt.getHours()]++; const dn = DOW[o.__dt.getDay()]; day[dn] = (day[dn] || 0) + 1; }
  }
  $("#kUnique").textContent = fmtInt(uniq.size);
  if (state.mode === "cdr") { $("#kDur").textContent = fmtDur(durTotal); $("#kAvg").textContent = durCount ? `avg ${fmtDur(Math.round(durTotal / durCount))}` : "—"; document.querySelector('#kDur').closest('.kpi').querySelector('.lbl').textContent = "Total duration"; }
  else { $("#kDur").textContent = (durTotal / 1048576).toFixed(1) + " MB"; $("#kAvg").textContent = durCount ? `avg ${(durTotal / durCount / 1024).toFixed(1)} KB` : "—"; document.querySelector('#kDur').closest('.kpi').querySelector('.lbl').textContent = "Total data"; }
  const peakH = hour.indexOf(Math.max(...hour));
  $("#kPeak").textContent = Math.max(...hour) ? `${String(peakH).padStart(2, "0")}:00` : "—";
  const peakDay = Object.entries(day).sort((a, b) => b[1] - a[1])[0];
  $("#kPeakDay").textContent = peakDay ? `busiest: ${peakDay[0]}` : "no time data";
  const top = Object.entries(bcount).sort((a, b) => b[1] - a[1])[0];
  $("#kTop").textContent = top ? top[0] : "—";
  $("#kTopN").textContent = top ? `${fmtInt(top[1])} interactions` : "—";
  state._charts = { bcount, hour, day, rows };
}

// ---------- charts ----------
function renderCharts() {
  const c = state._charts; if (!c) return;
  const top = Object.entries(c.bcount).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxT = top.length ? top[0][1] : 1;
  $("#vizTop").innerHTML = top.map(([n, v]) =>
    `<div class="bar"><span class="name" title="${esc(n)}">${esc(n)}</span><span class="track"><span class="fill" style="width:${(v / maxT * 100).toFixed(1)}%"></span></span><span class="num">${fmtInt(v)}</span></div>`).join("") || `<div style="color:var(--muted)">No data</div>`;
  const maxH = Math.max(...c.hour, 1);
  $("#vizHours").innerHTML = c.hour.map((v, h) =>
    `<div class="hr" title="${String(h).padStart(2, "0")}:00 — ${v}" style="height:${(v / maxH * 100).toFixed(1)}%">${h % 6 === 0 ? `<small>${h}</small>` : ""}</div>`).join("");
  // types / protocol mix
  const typeKey = state.mode === "cdr" ? "type" : "proto";
  const tc = {}; for (const o of c.rows) { const k = o[typeKey] || "unknown"; tc[k] = (tc[k] || 0) + 1; }
  const tEnt = Object.entries(tc).sort((a, b) => b[1] - a[1]).slice(0, 8); const maxTy = tEnt.length ? tEnt[0][1] : 1;
  $("#vizTypes").innerHTML = tEnt.map(([n, v]) =>
    `<div class="bar"><span class="name">${esc(n)}</span><span class="track"><span class="fill" style="width:${(v / maxTy * 100).toFixed(1)}%;background:linear-gradient(90deg,var(--success),var(--primary))"></span></span><span class="num">${fmtInt(v)}</span></div>`).join("");
  // frequent pairs (CDR only)
  if (state.mode === "cdr") {
    const pairs = {};
    for (const o of c.rows) { if (o.a && o.b) { const k = [o.a, o.b].sort().join(" ↔ "); pairs[k] = (pairs[k] || 0) + 1; } }
    const pEnt = Object.entries(pairs).filter(p => p[1] >= 2).sort((a, b) => b[1] - a[1]).slice(0, 8); const maxP = pEnt.length ? pEnt[0][1] : 1;
    $("#vizPairs").innerHTML = pEnt.map(([n, v]) =>
      `<div class="bar"><span class="name" title="${esc(n)}" style="width:170px">${esc(n)}</span><span class="track"><span class="fill" style="width:${(v / maxP * 100).toFixed(1)}%;background:linear-gradient(90deg,var(--warning),var(--secondary))"></span></span><span class="num">${fmtInt(v)}</span></div>`).join("") || `<div style="color:var(--muted)">No repeated pairs</div>`;
  } else $("#vizPairs").innerHTML = `<div style="color:var(--muted)">Pair analysis applies to CDR</div>`;
}

// ---------- column menu ----------
let menuKey = null;
function openColMenu(key, anchor) {
  menuKey = key;
  const col = state.cols.find(c => c.key === key);
  const distinct = new Map();
  for (const i of state.view) { const v = String(state.rows[i][key] ?? ""); distinct.set(v, (distinct.get(v) || 0) + 1); }
  const sorted = [...distinct.entries()].sort((a, b) => b[1] - a[1]).slice(0, 300);
  const f = state.filters[key] || { set: null, text: "" };
  const menu = $("#colMenu");
  menu.innerHTML = `
    <div class="mi" data-m="asc">▲ Sort ascending</div>
    <div class="mi" data-m="desc">▼ Sort descending</div>
    <div class="mi" data-m="hide">🚫 Hide column</div>
    <div class="mi sep"></div>
    <div class="flt">
      <input class="s-input" id="fltText" placeholder="Filter contains…" value="${esc(f.text || "")}"/>
      <div class="fvals" id="fvals">
        ${sorted.map(([v, c]) => `<label class="fval"><input type="checkbox" value="${esc(v)}" ${f.set && f.set.has(v) ? "checked" : ""}/><span>${v === "" ? "<i style='color:var(--muted)'>(empty)</i>" : esc(v)}</span><span class="cnt">${fmtInt(c)}</span></label>`).join("")}
      </div>
      <div class="frow"><button class="s-btn primary" id="fltApply" style="flex:1">Apply</button><button class="s-btn ghost" id="fltClear" style="flex:1">Clear</button></div>
    </div>`;
  const r = anchor.getBoundingClientRect();
  menu.style.left = Math.min(r.left, window.innerWidth - 250) + "px";
  menu.style.top = (r.bottom + 4) + "px";
  menu.classList.add("show");
}
function closeColMenu() { $("#colMenu").classList.remove("show"); menuKey = null; }

// ---------- columns drawer ----------
function renderColDrawer() {
  const list = $("#colList");
  list.innerHTML = state.cols.map(c =>
    `<label class="colrow"><input type="checkbox" data-col="${c.key}" ${state.hidden.has(c.key) ? "" : "checked"}/><span>${esc(c.label)}${c.enriched ? " ✦" : ""}</span></label>`).join("");
}

// ---------- export ----------
function exportCSV() {
  const visible = state.cols.filter(c => !state.hidden.has(c.key));
  const head = visible.map(c => `"${c.label.replace(/"/g, '""')}"`).join(",");
  const lines = [head];
  for (const vi of state.view) {
    const o = state.rows[vi];
    lines.push(visible.map(c => `"${String(o[c.key] ?? "").replace(/"/g, '""')}"`).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `sentinel_${state.mode}_${state.view.length}rows_${Date.now()}.csv`;
  a.click(); URL.revokeObjectURL(a.href);
  toast(`Exported ${fmtInt(state.view.length)} rows`);
}

// ---------- file loading ----------
function loadFile(file) {
  if (!file) return;
  $("#footStatus").textContent = "Parsing " + file.name + "…";
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const rows = parseCSV(e.target.result);
      if (rows.length < 2) { toast("File has no data rows", true); return; }
      ingest(rows[0].map(h => h.trim()), rows.slice(1));
    } catch (err) { toast("Parse failed: " + err.message, true); }
  };
  reader.onerror = () => toast("Could not read file", true);
  reader.readAsText(file);
}

// ---------- demo data ----------
function demoData() {
  const nums = Array.from({ length: 14 }, () => "9" + (Math.floor(1e8 + Math.random() * 8e8)));
  const types = ["IN", "OUT", "SMS-IN", "SMS-OUT"];
  const imeis = Object.keys(TAC).map(t => t + Math.floor(1e6 + Math.random() * 8e6));
  const rows = [["calling_number", "called_number", "call_type", "date_time", "duration", "imei", "imsi", "lac", "cid", "operator", "circle"]];
  const base = new Date(2026, 5, 10, 8);
  for (let i = 0; i < 1200; i++) {
    const a = nums[0]; const b = nums[1 + Math.floor(Math.random() * (nums.length - 1))];
    const d = new Date(base.getTime() + Math.random() * 14 * 864e5);
    const hour = Math.random() < .6 ? 9 + Math.floor(Math.random() * 12) : Math.floor(Math.random() * 24);
    d.setHours(hour, Math.floor(Math.random() * 60), Math.floor(Math.random() * 60));
    const dt = d.toISOString().slice(0, 19).replace("T", " ");
    rows.push([a, b, types[Math.floor(Math.random() * types.length)], dt, Math.floor(Math.random() * 600),
      imeis[Math.floor(Math.random() * imeis.length)], "40411" + Math.floor(1e9 + Math.random() * 8e9),
      100 + Math.floor(Math.random() * 50), 5000 + Math.floor(Math.random() * 900),
      1 + Math.floor(Math.random() * 5), 1 + Math.floor(Math.random() * 10)]);
  }
  state.mode = "cdr"; setModeUI();
  ingest(rows[0], rows.slice(1));
}

// ---------- UI wiring ----------
function setModeUI() { $$("#modePick button").forEach(b => b.classList.toggle("on", b.dataset.mode === state.mode)); }

function bind() {
  // mode
  $("#modePick").addEventListener("click", e => {
    const b = e.target.closest("button"); if (!b) return;
    state.mode = b.dataset.mode; setModeUI();
    if (state.rawHeaders.length) ingest(state.rawHeaders, state.rows.map(o => state.cols.map(c => c.rawIdx > -1 ? o[c.key] : "")));
    else toast(`${state.mode.toUpperCase()} mode — load a file`);
  });
  // upload
  $("#btnUpload").onclick = () => $("#fileInput").click();
  $("#dropzone").onclick = () => $("#fileInput").click();
  $("#fileInput").onchange = e => loadFile(e.target.files[0]);
  $("#btnDemo").onclick = demoData;
  // drag drop
  const dz = $("#gridScroll");
  ["dragover", "dragenter"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); $("#dropzone")?.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); $("#dropzone")?.classList.remove("over"); }));
  dz.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) loadFile(f); });
  // search
  $("#globalSearch").addEventListener("input", debounce(e => { state.search = e.target.value.trim(); state.page = 1; recompute(); }, 160));
  // header click (sort / menu)
  $("#sheetHead").addEventListener("click", e => {
    const menu = e.target.closest('[data-act="menu"]');
    if (menu) { e.stopPropagation(); openColMenu(menu.dataset.key, menu); return; }
    const sort = e.target.closest('[data-act="sort"]');
    if (sort) {
      const k = sort.dataset.key;
      if (state.sort.key === k) state.sort.dir = state.sort.dir === 1 ? -1 : state.sort.dir === -1 ? 0 : 1;
      else { state.sort.key = k; state.sort.dir = 1; }
      if (state.sort.dir === 0) state.sort.key = null;
      renderHead(); recompute();
    }
  });
  // column menu actions
  $("#colMenu").addEventListener("click", e => {
    const mi = e.target.closest(".mi"); 
    if (mi && mi.dataset.m) {
      const k = menuKey;
      if (mi.dataset.m === "asc") { state.sort = { key: k, dir: 1 }; renderHead(); recompute(); closeColMenu(); }
      if (mi.dataset.m === "desc") { state.sort = { key: k, dir: -1 }; renderHead(); recompute(); closeColMenu(); }
      if (mi.dataset.m === "hide") { state.hidden.add(k); delete state.filters[k]; renderHead(); renderColDrawer(); recompute(); closeColMenu(); }
      return;
    }
    if (e.target.id === "fltApply") {
      const checked = $$("#fvals input:checked").map(i => i.value);
      const text = $("#fltText").value.trim();
      if (checked.length || text) state.filters[menuKey] = { set: checked.length ? new Set(checked) : null, text };
      else delete state.filters[menuKey];
      state.page = 1; renderHead(); recompute(); closeColMenu();
    }
    if (e.target.id === "fltClear") { delete state.filters[menuKey]; state.page = 1; renderHead(); recompute(); closeColMenu(); }
  });
  $("#colMenu").addEventListener("input", e => {
    if (e.target.id === "fltText") {
      const q = e.target.value.toLowerCase();
      $$("#fvals .fval").forEach(l => { l.style.display = l.textContent.toLowerCase().includes(q) ? "" : "none"; });
    }
  });
  document.addEventListener("click", e => { if (!e.target.closest("#colMenu") && !e.target.closest('[data-act="menu"]')) closeColMenu(); });
  // remove filter chip
  $("#filterbar").addEventListener("click", e => { const c = e.target.closest("[data-rmfilter]"); if (c) { delete state.filters[c.dataset.rmfilter]; renderHead(); recompute(); } });
  $("#btnClearFilters").onclick = () => { state.filters = {}; state.search = ""; $("#globalSearch").value = ""; state.page = 1; renderHead(); recompute(); };
  // pager
  $("#pager").addEventListener("click", e => { const b = e.target.closest("button[data-p]"); if (b && !b.disabled) { state.page = +b.dataset.p; renderBody(); renderPager(); $("#gridScroll").scrollTop = 0; } });
  $("#pageSize").onchange = e => { state.pageSize = +e.target.value; state.page = 1; recompute(); };
  // freeze
  $("#btnFreeze").onclick = () => { state.frozen = (state.frozen + 1) % 4; $("#freezeN").textContent = state.frozen; renderHead(); renderBody(); };
  // columns drawer
  $("#btnCols").onclick = () => { renderColDrawer(); $("#colDrawer").classList.add("show"); };
  $$('#colDrawer [data-close]').forEach(el => el.onclick = () => $("#colDrawer").classList.remove("show"));
  $("#colList").addEventListener("change", e => { const cb = e.target.closest("[data-col]"); if (cb) { if (cb.checked) state.hidden.delete(cb.dataset.col); else state.hidden.add(cb.dataset.col); renderHead(); recompute(); } });
  $("#colAll").onclick = () => { state.hidden.clear(); renderColDrawer(); renderHead(); recompute(); };
  $("#colNone").onclick = () => { state.cols.forEach((c, i) => { if (i > 0) state.hidden.add(c.key); }); renderColDrawer(); renderHead(); recompute(); };
  // charts toggle
  $("#btnViz").onclick = () => { const v = $("#viz"); v.classList.toggle("show"); if (v.classList.contains("show")) renderCharts(); };
  // export
  $("#btnExport").onclick = () => { if (!state.rows.length) { toast("Load data first", true); return; } exportCSV(); };
  // keyboard
  document.addEventListener("keydown", e => { if (e.key === "/" && document.activeElement.tagName !== "INPUT") { e.preventDefault(); $("#globalSearch").focus(); } if (e.key === "Escape") { closeColMenu(); $("#colDrawer").classList.remove("show"); } });
}

bind();
setModeUI();
})();
