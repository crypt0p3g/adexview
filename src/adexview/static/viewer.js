const S = {
  files: [],
  file: null,
  page: 1,
  pageSize: 100,
  total: 0,
  more: false,
  sortCol: null,
  sortDir: "asc",
  highlightRow: null,
  filters: {},
  treeLoaded: false,
  schemaLoaded: false,
  schemaAttributes: [],
  database: null,
  library: false,
  view: null,
  viewRequest: 0,
  detailRequest: 0,
  auditQueries: [],
  resultSet: null,
  exportData: null,
  debug: false,
  loading: false,
  projectLabel: "",
  projectDebug: "",
  statusData: null,
  tableHeaders: [],
  tableRows: [],
  tableFile: "",
};
let filterTimer = null;
const $ = (id) => document.getElementById(id);
const COLUMN_PREFS_KEY = "adxColumnLayouts",
  DIM_LOADING_KEY = "adxDimLoading";
let columnPrefs = {};
try {
  columnPrefs = JSON.parse(localStorage.getItem(COLUMN_PREFS_KEY) || "{}");
} catch (_e) {
  columnPrefs = {};
}
function syncLoadingStyle() {
  document.body.classList.toggle("is-loading", S.loading);
  document.body.classList.toggle("dim-loading", $("dimLoading").checked);
  $("tableWrap").setAttribute("aria-busy", String(S.loading));
}
function beginLoading(label) {
  if (S.loading) return false;
  S.loading = true;
  syncLoadingStyle();
  if (label) $("status").textContent = label;
  return true;
}
function endLoading() {
  S.loading = false;
  syncLoadingStyle();
}
function esc(v) {
  const e = document.createElement("span");
  e.textContent = v == null ? "" : String(v);
  return e.innerHTML;
}
async function api(path) {
  if (S.database && path.startsWith("/api/") && !path.startsWith("/api/databases"))
    path += (path.includes("?") ? "&" : "?") + "db=" + encodeURIComponent(S.database);
  const r = await fetch(path);
  if (r.status === 401) {
    location.href = "/login";
    throw Error("login required");
  }
  if (!r.ok) {
    let message = r.statusText;
    try {
      message = (await r.json()).error || message;
    } catch (_e) {}
    throw Error(message);
  }
  return r.json();
}
function setCurrent(label, query = "") {
  const current = $("current");
  current.textContent = label;
  current.title = query;
  const copy = $("copyQuery");
  copy.hidden = !query;
  copy.dataset.query = query;
  $("columnsBtn").disabled = true;
  $("columnPanel").hidden = true;
}
function setExport(headers, rows) {
  S.exportData = { headers, rows };
  $("exportCsv").disabled = !headers.length;
}
function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}
function exportCsv() {
  if (!S.exportData) return;
  const lines = [S.exportData.headers, ...S.exportData.rows].map((row) => row.map(csvCell).join(","));
  const blob = new Blob(["\ufeff" + lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download =
    ($("current").textContent || "adexview-export").replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "") +
    ".csv";
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}
function fileLabel(path) {
  return path === "snapshot/objects.csv" ? "All objects" : path.split("/").at(-1);
}
function renderFiles() {
  const box = $("files");
  box.innerHTML = "";
  let folder = "";
  S.files.forEach((f, i) => {
    const p = f.path.split("/");
    const d = f.path === "snapshot/objects.csv" ? "Snapshot" : p.slice(0, -1).join("/") || "Reports";
    if (d !== folder) {
      folder = d;
      const h = document.createElement("div");
      h.className = "folder";
      h.textContent = d;
      box.appendChild(h);
    }
    const b = document.createElement("button");
    b.className = "file" + (f.path === S.file ? " active" : "");
    b.dataset.index = i;
    b.textContent = fileLabel(f.path) + "  (" + f.rows.toLocaleString() + ")";
    b.title =
      (f.path === "snapshot/objects.csv" ? "Decoded snapshot objects" : f.path) + " — " + formatBytes(f.size);
    b.onclick = () => {
      b.focus(); // Safari does not focus buttons on click; keyboard navigation needs it.
      openFile(f.path);
    };
    box.appendChild(b);
  });
}
function formatBytes(n) {
  for (const u of ["B", "KB", "MB", "GB"]) {
    if (n < 1024) return n.toFixed(u === "B" ? 0 : 1) + " " + u;
    n /= 1024;
  }
  return n.toFixed(1) + " TB";
}
function treeIcon(node) {
  const t = node.object_type.toLocaleLowerCase();
  if (node.is_nc_root) return "▾";
  if (t === "computer") return "▣";
  if (t === "user") return "○";
  if (t === "group") return "◎";
  if (t === "dnsnode") return "◇";
  return "□";
}
async function loadTree(parent = null, container = $("tree"), offset = 0) {
  const selectedDatabase = S.database;
  if (offset === 0) container.innerHTML = '<span class="muted">Loading…</span>';
  let u = "/api/tree?limit=500&offset=" + offset;
  if (parent !== null) u += "&parent=" + encodeURIComponent(parent);
  const d = await api(u);
  if (selectedDatabase !== S.database) return;
  if (offset === 0) container.innerHTML = "";
  for (const node of d.nodes) {
    const item = document.createElement("div");
    item.className = "treeNode";
    const line = document.createElement("div");
    line.className = "treeLine";
    const toggle = document.createElement("button");
    toggle.className = "treeToggle";
    toggle.textContent = node.has_children ? "＋" : "";
    toggle.disabled = !node.has_children;
    toggle.setAttribute("aria-label", (node.has_children ? "Expand " : "Leaf ") + node.label);
    const icon = document.createElement("span");
    icon.className = "treeIcon";
    icon.textContent = treeIcon(node);
    const object = document.createElement("button");
    object.className = "treeObject";
    object.title = node.dn;
    const name = document.createElement("span");
    name.className = "treeName";
    name.textContent = node.is_nc_root ? node.dn : node.label;
    const type = document.createElement("span");
    type.className = "treeType";
    type.textContent = node.object_type;
    object.append(name, type);
    if (node.row_number > 0)
      object.onclick = () => {
        object.focus();
        showDetail(node.row_number);
      };
    else object.disabled = true;
    const children = document.createElement("div");
    children.hidden = true;
    toggle.onclick = async () => {
      toggle.focus();
      if (children.hidden) {
        children.hidden = false;
        toggle.textContent = "−";
        toggle.setAttribute("aria-label", "Collapse " + node.label);
        if (!children.dataset.loaded) {
          children.dataset.loaded = "1";
          await loadTree(node.dn, children);
        }
      } else {
        children.hidden = true;
        toggle.textContent = "＋";
        toggle.setAttribute("aria-label", "Expand " + node.label);
      }
    };
    line.append(toggle, icon, object);
    item.append(line, children);
    container.appendChild(item);
  }
  if (d.more) {
    const more = document.createElement("button");
    more.className = "treeMore";
    more.textContent = "Load more…";
    more.onclick = async () => {
      more.remove();
      await loadTree(parent, container, offset + d.nodes.length);
    };
    container.appendChild(more);
  }
  S.treeLoaded = true;
}
function visibleTreeLines() {
  return [...document.querySelectorAll("#tree .treeLine")].filter((line) => line.offsetParent !== null);
}
function focusTreeLine(line) {
  const object = line?.querySelector(".treeObject:not(:disabled)");
  const target = object || line?.querySelector(".treeToggle:not(:disabled)");
  if (target) {
    target.focus();
    target.scrollIntoView({ block: "nearest" });
    if (object) object.click();
  }
}
function treeKeydown(e) {
  if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
  const line = e.target.closest(".treeLine");
  if (!line) return;
  e.preventDefault();
  e.stopPropagation();
  const lines = visibleTreeLines();
  const index = lines.indexOf(line);
  const item = line.parentElement;
  const toggle = line.querySelector(".treeToggle");
  const children = item.children[1];
  if (e.key === "ArrowDown") focusTreeLine(lines[Math.min(lines.length - 1, index + 1)]);
  else if (e.key === "ArrowUp") focusTreeLine(lines[Math.max(0, index - 1)]);
  else if (e.key === "Home") focusTreeLine(lines[0]);
  else if (e.key === "End") focusTreeLine(lines.at(-1));
  else if (e.key === "ArrowRight") {
    if (toggle && !toggle.disabled && children.hidden) toggle.click();
    else if (!children.hidden)
      focusTreeLine([...children.querySelectorAll(".treeLine")].find((x) => x.offsetParent !== null));
  } else if (e.key === "ArrowLeft") {
    if (toggle && !toggle.disabled && !children.hidden) toggle.click();
    else {
      const parentItem = item.parentElement.closest(".treeNode");
      if (parentItem) focusTreeLine(parentItem.querySelector(":scope > .treeLine"));
    }
  }
}
function reportKeydown(e) {
  if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
  const current = e.target.closest(".reportBtn");
  if (!current) return;
  const buttons = [...document.querySelectorAll("#reportButtons .reportBtn:not(:disabled)")];
  const index = buttons.indexOf(current);
  if (index < 0 || !buttons.length) return;
  e.preventDefault();
  e.stopPropagation();
  let next = index;
  if (e.key === "ArrowUp" || e.key === "ArrowLeft") next = Math.max(0, index - 1);
  else if (e.key === "ArrowDown" || e.key === "ArrowRight") next = Math.min(buttons.length - 1, index + 1);
  else if (e.key === "Home") next = 0;
  else if (e.key === "End") next = buttons.length - 1;
  const button = buttons[next];
  if (button && button !== current) {
    button.focus();
    button.click();
  }
}
function updatePager(more) {
  S.more = Boolean(more);
  $("prev").disabled = S.page <= 1;
  $("next").disabled = !S.more;
}
async function openFile(file, page = 1, keepSort = false) {
  if (file !== S.file || S.view?.type !== "rows") {
    S.filters = {};
    if (!keepSort) {
      S.sortCol = null;
      S.sortDir = "asc";
    }
  }
  S.file = file;
  S.page = page;
  $("query").value = "";
  setCurrent(fileLabel(file));
  renderFiles();
  await loadRows();
}
async function loadRows() {
  if (!S.file || !beginLoading("Loading rows…")) return;
  const request = ++S.viewRequest;
  S.resultSet = null;
  const size = +$("pageSize").value;
  try {
    let u =
      "/api/rows?file=" +
      encodeURIComponent(S.file) +
      "&page=" +
      S.page +
      "&page_size=" +
      size +
      "&filters=" +
      encodeURIComponent(JSON.stringify(S.filters));
    if (S.sortCol !== null) u += "&sort_col=" + S.sortCol + "&sort_dir=" + S.sortDir;
    const d = await api(u);
    if (request !== S.viewRequest) return;
    S.total = d.total;
    renderTable(d.headers, d.rows, S.file);
    S.view = { type: "rows", file: S.file, page: S.page };
    updatePager(S.page * size < d.total);
    const narrowed = d.total !== d.source_total ? ` filtered from ${d.source_total.toLocaleString()}` : "";
    $("status").textContent =
      `Rows ${d.start.toLocaleString()}–${d.end.toLocaleString()} of ${d.total.toLocaleString()}${narrowed} • page ${S.page}${S.sortCol === null ? "" : ` • sorted column ${S.sortCol + 1} ${S.sortDir}`}`;
    if (S.highlightRow) {
      const row = document.querySelector(`tr[data-row="${S.highlightRow}"]`);
      if (row) row.scrollIntoView({ block: "center" });
      S.highlightRow = null;
    }
  } catch (e) {
    if (request === S.viewRequest) $("status").textContent = "Load error: " + e.message;
  } finally {
    endLoading();
  }
}
function columnLayoutId(headers) {
  return headers.join("\u001f");
}
function getColumnLayout(headers) {
  const id = columnLayoutId(headers);
  const pref = columnPrefs[id] || {};
  const valid = (i) => Number.isInteger(i) && i >= 0 && i < headers.length;
  const seen = new Set();
  const order = [];
  for (const i of Array.isArray(pref.order) ? pref.order : []) {
    if (valid(i) && !seen.has(i)) {
      seen.add(i);
      order.push(i);
    }
  }
  for (let i = 0; i < headers.length; i++) if (!seen.has(i)) order.push(i);
  const hidden = new Set((Array.isArray(pref.hidden) ? pref.hidden : []).filter(valid));
  const widths = {};
  for (const [key, value] of Object.entries(pref.widths || {})) {
    const i = Number(key),
      width = Number(value);
    if (valid(i) && Number.isFinite(width) && width >= 60 && width <= 900) widths[i] = Math.round(width);
  }
  return { id, order, hidden, widths };
}
function saveColumnLayout(layout) {
  columnPrefs[layout.id] = { order: layout.order, hidden: [...layout.hidden], widths: layout.widths };
  localStorage.setItem(COLUMN_PREFS_KEY, JSON.stringify(columnPrefs));
}
function renderColumnChooser(headers, layout) {
  const panel = $("columnPanel");
  panel.onclick = (e) => e.stopPropagation();
  let h =
    '<div class="columnPanelHead"><b>Columns</b><button id="showAllColumns">Show all</button><button id="hideAllColumns">Hide all</button><button id="resetColumns">Reset</button><button id="closeColumns" aria-label="Close columns">×</button></div><div class="columnHint">Choose visible columns, set width in pixels (blank = automatic), and move columns left or right. You can also drag a column edge in the table to resize it, or double-click the edge to reset.</div>';
  layout.order.forEach((i, position) => {
    const shown = !layout.hidden.has(i);
    h +=
      '<div class="columnChoice"><label title="' +
      esc(headers[i]) +
      '"><input class="columnVisible" type="checkbox" data-col="' +
      i +
      '" ' +
      (shown ? "checked" : "") +
      "> " +
      esc(headers[i]) +
      '</label><input class="columnWidth" type="number" data-col="' +
      i +
      '" min="60" max="900" step="10" placeholder="Auto" aria-label="Width for ' +
      esc(headers[i]) +
      '" value="' +
      (layout.widths[i] || "") +
      '"><button class="columnMove" data-col="' +
      i +
      '" data-delta="-1" ' +
      (position === 0 ? "disabled" : "") +
      ' title="Move left">←</button><button class="columnMove" data-col="' +
      i +
      '" data-delta="1" ' +
      (position === layout.order.length - 1 ? "disabled" : "") +
      ' title="Move right">→</button></div>';
  });
  panel.innerHTML = h;
  $("closeColumns").onclick = () => {
    panel.hidden = true;
  };
  $("showAllColumns").onclick = () => {
    layout.hidden.clear();
    saveColumnLayout(layout);
    renderTable(S.tableHeaders, S.tableRows, S.tableFile);
  };
  $("hideAllColumns").onclick = () => {
    layout.hidden = new Set(layout.order);
    saveColumnLayout(layout);
    renderTable(S.tableHeaders, S.tableRows, S.tableFile);
  };
  $("resetColumns").onclick = () => {
    delete columnPrefs[layout.id];
    localStorage.setItem(COLUMN_PREFS_KEY, JSON.stringify(columnPrefs));
    renderTable(S.tableHeaders, S.tableRows, S.tableFile);
  };
  panel.querySelectorAll(".columnVisible").forEach(
    (input) =>
      (input.onchange = () => {
        const i = +input.dataset.col;
        if (input.checked) layout.hidden.delete(i);
        else layout.hidden.add(i);
        saveColumnLayout(layout);
        renderTable(S.tableHeaders, S.tableRows, S.tableFile);
      }),
  );
  panel.querySelectorAll(".columnWidth").forEach((input) => {
    const save = () => {
      const i = +input.dataset.col;
      const width = Number(input.value);
      if (input.value && Number.isFinite(width))
        layout.widths[i] = Math.max(60, Math.min(900, Math.round(width)));
      else delete layout.widths[i];
      saveColumnLayout(layout);
    };
    input.oninput = save;
    input.onblur = () => {
      save();
      renderTable(S.tableHeaders, S.tableRows, S.tableFile);
    };
    input.onkeydown = (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        input.blur();
      }
    };
  });
  panel.querySelectorAll(".columnMove").forEach(
    (button) =>
      (button.onclick = () => {
        const i = +button.dataset.col;
        const from = layout.order.indexOf(i);
        const to = from + +button.dataset.delta;
        if (to < 0 || to >= layout.order.length) return;
        [layout.order[from], layout.order[to]] = [layout.order[to], layout.order[from]];
        saveColumnLayout(layout);
        renderTable(S.tableHeaders, S.tableRows, S.tableFile);
      }),
  );
}
function renderTable(headers, rows, file) {
  const keepColumnPanelOpen = !$("columnPanel").hidden;
  S.tableHeaders = headers;
  S.tableRows = rows;
  S.tableFile = file;
  const layout = getColumnLayout(headers);
  const visible = layout.order.filter((i) => !layout.hidden.has(i));
  const widthStyle = (i) =>
    layout.widths[i]
      ? ' style="width:' +
        layout.widths[i] +
        "px;min-width:" +
        layout.widths[i] +
        "px;max-width:" +
        layout.widths[i] +
        'px"'
      : "";
  setExport(
    ["row_number", ...visible.map((i) => headers[i])],
    rows.map((row) => [row.row_number || "", ...visible.map((i) => row.values[i])]),
  );
  let h =
    '<table class="grid"><thead><tr><th>#</th>' +
    visible
      .map(
        (i) =>
          "<th" +
          widthStyle(i) +
          '><button class="sortHead" data-col="' +
          i +
          '">' +
          esc(headers[i]) +
          (S.sortCol === i ? (S.sortDir === "asc" ? " ▲" : " ▼") : "") +
          '</button><span class="colResizer" data-col="' +
          i +
          '" title="Drag to resize, double-click to reset"></span></th>',
      )
      .join("") +
    '</tr><tr class="filterRow"><th></th>' +
    visible
      .map(
        (i) =>
          "<th" +
          widthStyle(i) +
          '><input class="fieldFilter" data-col="' +
          i +
          '" aria-label="Filter ' +
          esc(headers[i]) +
          '" title="Contains; = exact; ! excludes; | combines values; Enter applies now" placeholder="Filter…" value="' +
          esc(S.filters[i] || "") +
          '"></th>',
      )
      .join("") +
    "</tr></thead><tbody>";
  // Report rows that carry an LDAP filter open that query on click (for
  // example every object populating a custom attribute).
  const filterIndex = headers.indexOf("ldap_filter");
  const attributeIndex = headers.indexOf("attribute");
  const rowAction = (r) => {
    if (r.row_number > 0)
      return (
        '<button class="rowJump" data-file="' +
        esc(file) +
        '" data-row="' +
        r.row_number +
        '">' +
        (file === "snapshot/objects.csv" ? "View " + r.row_number : r.row_number) +
        "</button>"
      );
    if (filterIndex >= 0 && r.values[filterIndex])
      return (
        '<button class="rowJump rowQuery" data-filter="' +
        esc(r.values[filterIndex]) +
        '" data-attribute="' +
        esc(attributeIndex >= 0 ? r.values[attributeIndex] : "") +
        '" title="Run ' +
        esc(r.values[filterIndex]) +
        '">Query</button>'
      );
    return "";
  };
  for (const r of rows)
    h +=
      '<tr data-row="' +
      r.row_number +
      '" class="' +
      (r.row_number === S.highlightRow ? "highlight" : "") +
      '"><td>' +
      rowAction(r) +
      "</td>" +
      visible.map((i) => "<td" + widthStyle(i) + ">" + esc(r.values[i]) + "</td>").join("") +
      "</tr>";
  h += "</tbody></table>";
  $("tableWrap").innerHTML = h;
  $("columnsBtn").disabled = !headers.length;
  renderColumnChooser(headers, layout);
  if (keepColumnPanelOpen)
    setTimeout(() => {
      $("columnPanel").hidden = false;
    }, 0);
  document.querySelectorAll(".sortHead").forEach((b) => (b.onclick = () => sortColumn(+b.dataset.col)));
  attachColumnResizers(layout, visible);
  document
    .querySelectorAll(".rowJump:not(.rowQuery)")
    .forEach((b) => (b.onclick = () => openHit(b.dataset.file, +b.dataset.row)));
  document.querySelectorAll(".rowQuery").forEach(
    (b) =>
      (b.onclick = () => {
        $("auditQueryPreset").value = "";
        $("ldapFilter").value = b.dataset.filter;
        $("ldapAttributes").value = b.dataset.attribute || "";
        S.page = 1;
        ldapSearch();
      }),
  );
  document.querySelectorAll(".fieldFilter").forEach((input) => {
    input.oninput = () => queueFilter(input);
    input.onkeydown = (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        applyFilter(input);
      }
    };
  });
}
function applyColumnWidth(position, width) {
  // position is the 1-based cell index in every row ("#" is cell 1).
  const style = width ? `width:${width}px;min-width:${width}px;max-width:${width}px` : "";
  document.querySelectorAll(`#tableWrap .grid tr > *:nth-child(${position})`).forEach((cell) => {
    cell.style.cssText = style;
  });
}
function attachColumnResizers(layout, visible) {
  document.querySelectorAll("#tableWrap .colResizer").forEach((handle) => {
    const column = +handle.dataset.col;
    const position = visible.indexOf(column) + 2;
    handle.onpointerdown = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startWidth = handle.parentElement.getBoundingClientRect().width;
      let width = Math.round(startWidth);
      handle.setPointerCapture(e.pointerId);
      handle.classList.add("dragging");
      const move = (ev) => {
        width = Math.max(60, Math.min(900, Math.round(startWidth + ev.clientX - startX)));
        applyColumnWidth(position, width);
      };
      const up = (ev) => {
        handle.releasePointerCapture(ev.pointerId);
        handle.classList.remove("dragging");
        handle.removeEventListener("pointermove", move);
        handle.removeEventListener("pointerup", up);
        handle.removeEventListener("pointercancel", up);
        layout.widths[column] = width;
        saveColumnLayout(layout);
        $("columnPanel")
          .querySelectorAll(`.columnWidth[data-col="${column}"]`)
          .forEach((input) => (input.value = width));
      };
      handle.addEventListener("pointermove", move);
      handle.addEventListener("pointerup", up);
      handle.addEventListener("pointercancel", up);
    };
    handle.ondblclick = (e) => {
      e.stopPropagation();
      delete layout.widths[column];
      saveColumnLayout(layout);
      applyColumnWidth(position, 0);
      $("columnPanel")
        .querySelectorAll(`.columnWidth[data-col="${column}"]`)
        .forEach((input) => (input.value = ""));
    };
  });
}
function filterTerm(value, term) {
  const exact = term.startsWith("=");
  const needle = (exact ? term.slice(1) : term).toLocaleLowerCase();
  const text = String(value ?? "").toLocaleLowerCase();
  return exact ? text === needle : text.includes(needle);
}
function matchesColumnFilter(value, expression) {
  const terms = expression
    .split("|")
    .map((x) => x.trim())
    .filter(Boolean);
  const excluded = terms.filter((x) => x.startsWith("!")).map((x) => x.slice(1));
  if (excluded.some((x) => filterTerm(value, x))) return false;
  const included = terms.filter((x) => !x.startsWith("!"));
  return !included.length || included.some((x) => filterTerm(value, x));
}
function renderResultSet() {
  if (!S.resultSet) return;
  const globalQuery = (S.resultSet.globalQuery || "").toLocaleLowerCase();
  let rows = S.resultSet.rows.filter(
    (row) =>
      (!globalQuery ||
        row.values.some((value) =>
          String(value ?? "")
            .toLocaleLowerCase()
            .includes(globalQuery),
        )) &&
      Object.entries(S.filters).every(([col, value]) => matchesColumnFilter(row.values[+col], value)),
  );
  if (S.sortCol !== null) {
    const direction = S.sortDir === "asc" ? 1 : -1;
    rows = [...rows].sort(
      (a, b) =>
        direction *
        String(a.values[S.sortCol] ?? "").localeCompare(String(b.values[S.sortCol] ?? ""), undefined, {
          numeric: true,
          sensitivity: "base",
        }),
    );
  }
  let visible = rows;
  let more = S.resultSet.more;
  let range = "";
  if (S.view?.type === "audit" || S.resultSet.cacheAll) {
    const size = +$("pageSize").value;
    const start = (S.page - 1) * size;
    visible = rows.slice(start, start + size);
    more = start + size < rows.length || Boolean(S.resultSet.serverMore);
    range = visible.length
      ? ` • rows ${(start + 1).toLocaleString()}–${(start + visible.length).toLocaleString()}`
      : "";
  }
  renderTable(S.resultSet.headers, visible, S.resultSet.file);
  updatePager(more);
  const narrowed =
    rows.length === S.resultSet.rows.length ? "" : ` • ${rows.length.toLocaleString()} after search/filters`;
  const capped =
    S.view?.type === "audit" && S.resultSet.sourceMore
      ? " • first " + S.resultSet.rows.length.toLocaleString() + " loaded"
      : "";
  const cached = S.resultSet.cacheAll ? " • " + S.resultSet.rows.length.toLocaleString() + " cached" : "";
  const diagnostics = S.debug && S.resultSet.diagnostics ? " • " + S.resultSet.diagnostics : "";
  $("status").textContent =
    `${rows.length.toLocaleString()} matches${range}${more ? " • more available" : ""}${narrowed}${cached}${capped}${diagnostics}`;
}
function applyCurrentFilters() {
  if (S.resultSet && ["search", "ldap", "audit"].includes(S.view?.type)) {
    S.page = 1;
    renderResultSet();
  } else {
    S.page = 1;
    loadRows();
  }
}
function queueFilter(input) {
  const col = +input.dataset.col;
  const value = input.value;
  if (value) S.filters[col] = value;
  else delete S.filters[col];
  clearTimeout(filterTimer);
  filterTimer = setTimeout(applyCurrentFilters, 900);
}
function applyFilter(input) {
  clearTimeout(filterTimer);
  const col = +input.dataset.col;
  const value = input.value;
  if (value) S.filters[col] = value;
  else delete S.filters[col];
  applyCurrentFilters();
}
function sortColumn(col) {
  if (S.sortCol === col) S.sortDir = S.sortDir === "asc" ? "desc" : "asc";
  else {
    S.sortCol = col;
    S.sortDir = "asc";
  }
  if (S.resultSet && ["search", "ldap", "audit"].includes(S.view?.type)) {
    S.page = 1;
    S.view.sortCol = S.sortCol;
    S.view.sortDir = S.sortDir;
    renderResultSet();
  } else {
    S.page = 1;
    loadRows();
  }
}
function jumpRow(file, row) {
  S.sortCol = null;
  S.sortDir = "asc";
  S.filters = {};
  S.highlightRow = row;
  openFile(file, Math.ceil(row / +$("pageSize").value), true);
}
function openHit(file, row) {
  if (file === "snapshot/objects.csv") showDetail(row);
  else jumpRow(file, row);
}
async function openAuditReport(name, label) {
  if (!beginLoading("Loading " + label + "…")) return;
  const same = S.view?.type === "audit" && S.view.name === name;
  const globalQuery = same ? S.view.globalQuery || "" : "";
  if (!same) {
    S.page = 1;
    S.sortCol = null;
    S.sortDir = "asc";
    S.filters = {};
  }
  $("query").value = globalQuery;
  const request = ++S.viewRequest;
  try {
    const d = await api("/api/audit-report?name=" + encodeURIComponent(name));
    if (request !== S.viewRequest) return;
    setCurrent(label);
    if (!d.available) {
      S.resultSet = null;
      S.view = { type: "audit", name, label, globalQuery };
      $("tableWrap").innerHTML =
        '<div class="result">This database was created without security audit tables. Convert the snapshot with <b>Include security audit</b> enabled, or run enum.sh.</div>';
      updatePager(false);
      $("status").textContent = label + " — security audit data is not present";
      return;
    }
    S.view = { type: "audit", name, label, globalQuery };
    S.resultSet = {
      headers: d.headers,
      rows: d.rows,
      file: "snapshot/objects.csv",
      more: false,
      sourceMore: d.more,
      globalQuery,
      diagnostics: d.total.toLocaleString() + " rows",
    };
    renderResultSet();
  } catch (e) {
    if (request === S.viewRequest) $("status").textContent = "Error: " + e.message;
  } finally {
    endLoading();
  }
}
async function restoreView(view) {
  if (!view) return openFile("snapshot/objects.csv");
  S.page = view.page || 1;
  S.sortCol = view.sortCol ?? null;
  S.sortDir = view.sortDir || "asc";
  S.filters = { ...(view.filters || {}) };
  if (view.type === "ldap") {
    $("ldapFilter").value = view.filter;
    $("auditQueryPreset").value = view.preset;
    $("ldapAttributes").value = view.attributes || "";
    return ldapSearch();
  }
  if (view.type === "search") {
    S.file = view.file;
    $("query").value = view.query;
    return search();
  }
  if (view.type === "audit") {
    return openAuditReport(view.name, view.label);
  }
  return openFile(view.file, view.page, true);
}
async function showDetail(row) {
  if (!beginLoading("Loading object details…")) return;
  const returnView = S.view
    ? { ...S.view, page: S.page, sortCol: S.sortCol, sortDir: S.sortDir, filters: { ...S.filters } }
    : null;
  const request = ++S.detailRequest;
  try {
    const d = await api("/api/detail?row=" + row);
    if (request !== S.detailRequest) return;
    setCurrent("Snapshot object #" + row);
    setExport(
      ["attribute", "value"],
      d.attributes.map((x) => [x.attribute, x.value]),
    );
    $("status").textContent = d.distinguished_name || "";
    const value = (x) =>
      x.structured
        ? "<details><summary>" +
          esc(x.summary) +
          '</summary><pre class="decodedValue">' +
          esc(x.value) +
          "</pre></details>"
        : '<pre class="decodedValue">' + esc(x.value) + "</pre>";
    const backLabel =
      returnView && returnView.type !== "rows" ? "← Back to search results" : "← Back to objects";
    let h =
      '<div class="detailTools"><button id="backToObjects">' +
      backLabel +
      '</button><input id="attributeFilter" aria-label="Filter object attributes" placeholder="Filter attribute names or decoded values…"><button id="expandAll" title="Open every parsed value">Expand all</button><button id="collapseAll" title="Close every parsed value">Collapse all</button><button id="copyDn" title="Copy the distinguished name">Copy DN</button><span id="attributeCount" class="muted">' +
      d.attributes.length +
      ' attributes</span></div><table class="grid"><thead><tr><th>Attribute</th><th>Value(s)</th></tr></thead><tbody>' +
      d.attributes
        .map(
          (x) => '<tr class="attributeRow"><td>' + esc(x.attribute) + "</td><td>" + value(x) + "</td></tr>",
        )
        .join("") +
      "</tbody></table>";
    $("tableWrap").innerHTML = h;
    $("backToObjects").onclick = () => restoreView(returnView);
    $("expandAll").onclick = () =>
      document.querySelectorAll("#tableWrap details").forEach((x) => (x.open = true));
    $("collapseAll").onclick = () =>
      document.querySelectorAll("#tableWrap details").forEach((x) => (x.open = false));
    $("copyDn").onclick = async () => {
      try {
        await navigator.clipboard.writeText(d.distinguished_name || "");
        $("copyDn").textContent = "Copied";
        setTimeout(() => ($("copyDn").textContent = "Copy DN"), 1200);
      } catch (e) {
        $("status").textContent = "Copy failed: " + e.message;
      }
    };
    $("attributeFilter").oninput = (e) => {
      const q = e.target.value.toLocaleLowerCase();
      let shown = 0;
      const exported = [];
      document.querySelectorAll(".attributeRow").forEach((r, i) => {
        r.hidden = q && !r.textContent.toLocaleLowerCase().includes(q);
        if (!r.hidden) {
          shown++;
          exported.push([d.attributes[i].attribute, d.attributes[i].value]);
        }
      });
      setExport(["attribute", "value"], exported);
      $("attributeCount").textContent = shown + " of " + d.attributes.length + " attributes";
    };
  } catch (e) {
    if (request === S.detailRequest) $("status").textContent = "Detail error: " + e.message;
  } finally {
    endLoading();
  }
}
async function search() {
  const q = $("query").value.trim();
  if (S.view?.type === "audit" && S.resultSet) {
    S.page = 1;
    S.resultSet.globalQuery = q;
    S.view.globalQuery = q;
    setCurrent(S.view.label + (q ? " — search: " + q : ""));
    renderResultSet();
    return;
  }
  if (!q) {
    S.page = 1;
    await loadRows();
    return;
  }
  if (!S.file || !beginLoading("Searching…")) return;
  const searchedFile = S.file;
  const same = S.view?.type === "search" && S.view.query === q && S.view.file === searchedFile;
  if (!same) {
    S.page = 1;
    S.sortCol = null;
    S.sortDir = "asc";
    S.filters = {};
  }
  const request = ++S.viewRequest;
  const limit = +$("pageSize").value;
  const offset = (S.page - 1) * limit;
  try {
    const d = await api("/api/search?q=" + encodeURIComponent(q) + "&limit=" + limit + "&offset=" + offset);
    if (request !== S.viewRequest) return;
    setCurrent("Search: " + q);
    S.view = {
      type: "search",
      query: q,
      file: searchedFile,
      page: S.page,
      sortCol: S.sortCol,
      sortDir: S.sortDir,
    };
    S.resultSet = { headers: d.headers, rows: d.results, file: S.file, more: d.more, diagnostics: "" };
    renderResultSet();
  } catch (e) {
    if (request === S.viewRequest) $("status").textContent = "Search error: " + e.message;
  } finally {
    endLoading();
  }
}
function renderSchemaOptions(selectFirst = false) {
  const select = $("schemaAttribute");
  const previous = select.value;
  const query = $("schemaSearch").value.trim().toLocaleLowerCase();
  let values = S.schemaAttributes;
  if (query) {
    const prefix = [];
    const contains = [];
    for (const item of S.schemaAttributes) {
      const name = item.attribute.toLocaleLowerCase();
      if (name.startsWith(query)) prefix.push(item);
      else if (name.includes(query)) contains.push(item);
    }
    values = [...prefix, ...contains];
  }
  const matchCount = values.length;
  const shown = values.slice(0, 200);
  select.innerHTML =
    shown
      .map(
        (x) =>
          '<option value="' +
          esc(x.attribute) +
          '">' +
          esc(x.attribute) +
          " — " +
          esc(x.syntax) +
          "</option>",
      )
      .join("") || '<option value="">No matching attributes</option>';
  if (!selectFirst && shown.some((x) => x.attribute === previous)) select.value = previous;
  select.disabled = !matchCount;
  $("insertPresence").disabled = !matchCount;
  $("schemaSearch").title =
    matchCount.toLocaleString() +
    " matching attribute names" +
    (matchCount > shown.length ? " (showing first " + shown.length.toLocaleString() + ")" : "");
}
async function refreshSchema() {
  const selectedDatabase = S.database;
  const d = await api("/api/schema");
  if (selectedDatabase !== S.database) return;
  S.schemaAttributes = d.attributes;
  renderSchemaOptions();
  $("schemaSearch").disabled = !d.attributes.length;
  $("ldapSearchBtn").disabled = !d.attributes.length;
  S.schemaLoaded = true;
}
async function refreshAuditQueries() {
  const d = await api("/api/audit-queries");
  S.auditQueries = d.queries;
  const select = $("auditQueryPreset");
  select.innerHTML =
    '<option value="">Saved audit queries…</option>' +
    d.queries.map((x, i) => '<option value="' + i + '">' + esc(x.name) + "</option>").join("");
  renderReports();
}
function renderReports() {
  const box = $("reportButtons");
  if (!box) return;
  box.innerHTML = "";
  const group = (label) => {
    const h = document.createElement("div");
    h.className = "reportGroup";
    h.textContent = label;
    box.appendChild(h);
  };
  const mk = (label, fn, cls) => {
    const b = document.createElement("button");
    b.className = "reportBtn" + (cls ? " " + cls : "");
    b.textContent = label;
    b.onclick = () => {
      b.focus();
      fn();
    };
    box.appendChild(b);
  };
  group("Priority");
  mk("★ Findings", () => openAuditReport("findings", "Audit findings"), "finding");
  mk(
    "★ Dangerous ACLs / DCSync",
    () => openAuditReport("dangerous_acls", "Dangerous ACLs / DCSync"),
    "finding",
  );
  mk("★ RBCD principals", () => openAuditReport("rbcd", "RBCD principals"), "finding");
  group("Computed reports");
  mk("Certificate template ACLs", () =>
    openAuditReport("certificate_template_acl", "Certificate template ACLs"),
  );
  mk("Domain / Enterprise / Administrators", () =>
    openAuditReport("privileged_members", "Privileged group members"),
  );
  mk("DNS name - IP", () => openAuditReport("dns_name_to_ip", "DNS name to IP"));
  mk("Certificate findings", () => openAuditReport("certificate_findings", "Certificate findings"));
  mk("Custom attributes in use", () => openAuditReport("custom_attribute_usage", "Custom attributes in use"));
  mk("Sensitive attributes checklist", () =>
    openAuditReport("sensitive_attribute_schema", "Sensitive attributes checklist"),
  );
  group("Directory reports");
  (S.auditQueries || []).forEach((q, i) => mk(q.name, () => runPreset(i)));
}
function runPreset(i) {
  const s = $("auditQueryPreset");
  if (!s) return;
  s.value = i;
  s.dispatchEvent(new Event("change"));
}
function insertPresence() {
  const attr = $("schemaAttribute").value;
  if (!attr) return;
  const input = $("ldapFilter");
  const term = "(" + attr + "=*)";
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? start;
  if (start !== end) input.setRangeText(term, start, end, "end");
  else {
    const current = input.value.trim();
    if (!current) input.value = term;
    else if (current.startsWith("(&") && current.endsWith(")"))
      input.value = current.slice(0, -1) + term + ")";
    else input.value = "(&" + current + term + ")";
  }
  input.focus();
}
function escapeLdapValue(value) {
  return value
    .replace(/\\/g, "\\5c")
    .replace(/\*/g, "\\2a")
    .replace(/\(/g, "\\28")
    .replace(/\)/g, "\\29")
    .replace(/\0/g, "\\00");
}
function quickCnSearch() {
  const value = $("cnQuick").value.trim();
  if (!value) return;
  $("auditQueryPreset").value = "";
  $("ldapFilter").value = "(name=*" + escapeLdapValue(value) + "*)";
  S.page = 1;
  ldapSearch();
}
async function ldapSearch() {
  const filter = $("ldapFilter").value.trim();
  if (!filter) return;
  // A saved report only keeps its column set while its own filter is running.
  // Once the filter text is edited it is a custom query with the standard
  // columns plus the attributes it mentions and any extra columns requested.
  let preset = $("auditQueryPreset").value;
  if (preset !== "" && S.auditQueries[+preset]?.filter !== filter) {
    preset = "";
    $("auditQueryPreset").value = "";
  }
  const attributes = $("ldapAttributes").value.trim();
  const same =
    S.view?.type === "ldap" &&
    S.view.filter === filter &&
    S.view.preset === preset &&
    S.view.attributes === attributes;
  const label = preset !== "" ? S.auditQueries[+preset]?.name || "LDAP report" : "LDAP results";
  setCurrent(label, filter);
  if (!same) {
    S.page = 1;
    S.sortCol = null;
    S.sortDir = "asc";
    S.filters = {};
    S.resultSet = null;
  }
  const needed = (S.page - 1) * +$("pageSize").value;
  const cache = same && S.resultSet?.cacheAll ? S.resultSet : null;
  if (cache && needed < cache.rows.length) {
    renderResultSet();
    return;
  }
  if (cache && !cache.serverMore) {
    renderResultSet();
    return;
  }
  if (!beginLoading(cache ? "Loading more LDAP matches…" : "Running LDAP filter…")) return;
  const request = ++S.viewRequest;
  try {
    const offset = cache ? cache.rows.length : 0;
    let u = "/api/ldap-search?filter=" + encodeURIComponent(filter) + "&limit=1000&offset=" + offset;
    if (preset !== "") u += "&preset=" + encodeURIComponent(preset);
    if (attributes) u += "&attributes=" + encodeURIComponent(attributes);
    const d = await api(u);
    if (request !== S.viewRequest) return;
    S.view = {
      type: "ldap",
      filter,
      preset,
      attributes,
      page: S.page,
      sortCol: S.sortCol,
      sortDir: S.sortDir,
    };
    const rows = cache ? [...cache.rows, ...d.results] : d.results;
    const scanned = (cache?.scannedTotal || 0) + d.scanned;
    const elapsed = (cache?.elapsedTotal || 0) + d.elapsed_ms;
    S.resultSet = {
      headers: d.headers,
      rows,
      file: "snapshot/objects.csv",
      more: false,
      serverMore: d.more,
      cacheAll: true,
      scannedTotal: scanned,
      elapsedTotal: elapsed,
      diagnostics: `scanned ${scanned.toLocaleString()} candidate visits in ${elapsed.toLocaleString()} ms`,
    };
    renderResultSet();
  } catch (e) {
    if (request === S.viewRequest) $("status").textContent = "LDAP error: " + e.message;
  } finally {
    endLoading();
  }
}
const themeMedia = matchMedia("(prefers-color-scheme: dark)");
function applyTheme(preference) {
  const resolved = preference === "system" ? (themeMedia.matches ? "dark" : "light") : preference;
  document.documentElement.dataset.theme = resolved;
}
function updateProjectLabel() {
  const diagnostics = S.debug && S.projectDebug ? " • " + S.projectDebug : "";
  $("project").textContent = S.projectLabel + diagnostics;
}
function updateDiagnostics() {
  S.debug = !S.debug;
  $("toggleDiagnostics").textContent = S.debug ? "Hide debug" : "Diagnostics";
  updateProjectLabel();
  if (S.statusData) $("indexing").hidden = S.statusData.state === "ready" && !S.debug;
  if (S.resultSet) renderResultSet();
}
const savedTheme = localStorage.getItem("adxTheme") || "system";
$("theme").value = savedTheme;
applyTheme(savedTheme);
themeMedia.addEventListener("change", () => {
  if ($("theme").value === "system") applyTheme("system");
});
$("theme").onchange = (e) => {
  localStorage.setItem("adxTheme", e.target.value);
  applyTheme(e.target.value);
};
$("toggleDiagnostics").onclick = updateDiagnostics;
$("copyQuery").onclick = async () => {
  const text = $("copyQuery").dataset.query || "";
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    $("copyQuery").textContent = "Copied";
    setTimeout(() => {
      $("copyQuery").textContent = "Copy query";
    }, 1200);
  } catch (e) {
    $("status").textContent = "Copy failed: " + e.message;
  }
};
$("exportCsv").onclick = exportCsv;
$("columnsBtn").onclick = () => {
  $("columnPanel").hidden = !$("columnPanel").hidden;
};
$("searchBtn").onclick = search;
$("query").onkeydown = (e) => {
  if (e.key === "Enter") search();
};
$("ldapSearchBtn").onclick = ldapSearch;
$("ldapFilter").onkeydown = (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    ldapSearch();
  }
};
$("ldapAttributes").onkeydown = (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    ldapSearch();
  }
};
$("insertPresence").onclick = insertPresence;
$("cnQuick").onkeydown = (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    quickCnSearch();
  }
};
$("schemaSearch").oninput = () => renderSchemaOptions(true);
$("schemaSearch").onkeydown = (e) => {
  if (e.key === "ArrowDown") {
    e.preventDefault();
    $("schemaAttribute").focus();
  } else if (e.key === "Enter" && !$("schemaAttribute").disabled) {
    e.preventDefault();
    insertPresence();
  }
};
$("auditQueryPreset").onchange = (e) => {
  if (e.target.value === "") return;
  const item = S.auditQueries[+e.target.value];
  if (!item) return;
  const input = $("ldapFilter");
  input.value = item.filter;
  $("auditQueryInfo").textContent = "Running " + item.name + "… (edit the filter and press Enter to refine)";
  S.page = 1;
  S.sortCol = null;
  S.sortDir = "asc";
  S.filters = {};
  ldapSearch();
};
$("tree").addEventListener("keydown", treeKeydown);
$("reportButtons").addEventListener("keydown", reportKeydown);
$("prev").onclick = () => {
  if (S.page <= 1) return;
  S.page--;
  if (S.view?.type === "search") search();
  else if (S.view?.type === "ldap") ldapSearch();
  else if (S.view?.type === "audit") renderResultSet();
  else loadRows();
};
$("next").onclick = () => {
  if (!S.more) return;
  S.page++;
  if (S.view?.type === "search") search();
  else if (S.view?.type === "ldap") ldapSearch();
  else if (S.view?.type === "audit") renderResultSet();
  else loadRows();
};
$("pageSize").onchange = () => {
  const nextSize = +$("pageSize").value;
  const first = (S.page - 1) * S.pageSize;
  S.page = Math.floor(first / nextSize) + 1;
  S.pageSize = nextSize;
  if (S.view?.type === "search") search();
  else if (S.view?.type === "ldap") ldapSearch();
  else if (S.view?.type === "audit") renderResultSet();
  else loadRows();
};
$("clearFilters").onclick = () => {
  S.filters = {};
  applyCurrentFilters();
};
$("fullCells").onchange = (e) => $("tableWrap").classList.toggle("full-cells", e.target.checked);
const dimLoadingSaved = localStorage.getItem(DIM_LOADING_KEY);
$("dimLoading").checked = dimLoadingSaved !== "0";
$("dimLoading").onchange = (e) => {
  localStorage.setItem(DIM_LOADING_KEY, e.target.checked ? "1" : "0");
  syncLoadingStyle();
};
syncLoadingStyle();
document.addEventListener("keydown", (e) => {
  if (["INPUT", "SELECT", "TEXTAREA"].includes(e.target.tagName)) {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    $("query").focus();
    $("query").select();
    return;
  }
  if (e.key === "l" && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    $("ldapFilter").focus();
    return;
  }
  if (S.loading || e.target.id === "splitter" || e.target.closest("#tree,#columnPanel")) return;
  const i = S.files.findIndex((f) => f.path === S.file);
  if (e.key === "ArrowDown" && i < S.files.length - 1) {
    e.preventDefault();
    openFile(S.files[i + 1].path);
  } else if (e.key === "ArrowUp" && i > 0) {
    e.preventDefault();
    openFile(S.files[i - 1].path);
  } else if (e.key === "ArrowRight") {
    e.preventDefault();
    $("next").click();
  } else if (e.key === "ArrowLeft") {
    e.preventDefault();
    $("prev").click();
  }
});
function resetWorkspaceState() {
  S.viewRequest++;
  S.detailRequest++;
  S.files = [];
  S.file = null;
  S.page = 1;
  S.total = 0;
  S.more = false;
  S.sortCol = null;
  S.sortDir = "asc";
  S.highlightRow = null;
  S.filters = {};
  S.view = null;
  S.resultSet = null;
  S.exportData = null;
  $("exportCsv").disabled = true;
  setCurrent("Choose a report");
  S.treeLoaded = false;
  S.schemaLoaded = false;
  S.schemaAttributes = [];
  $("query").value = "";
  $("cnQuick").value = "";
  $("ldapFilter").value = "(objectClass=*)";
  $("ldapAttributes").value = "";
  $("ldapSearchBtn").disabled = false;
  $("schemaSearch").value = "";
  $("schemaAttribute").innerHTML = '<option value="">Loading schema attributes…</option>';
  $("schemaAttribute").disabled = true;
  $("insertPresence").disabled = true;
  $("auditQueryPreset").value = "";
  $("tree").innerHTML = "";
  updatePager(false);
}
async function refreshFiles(openFirst = false) {
  const selectedDatabase = S.database;
  const d = await api("/api/files");
  if (selectedDatabase !== S.database) return;
  S.files = d.files;
  S.projectLabel = d.project + (d.server ? " • " + d.server : "");
  S.projectDebug = [
    d.captured_utc ? "captured " + d.captured_utc : "",
    d.audit ? "audit tables" : "no audit tables",
  ]
    .filter(Boolean)
    .join(" • ");
  updateProjectLabel();
  renderFiles();
  $("treeSection").hidden = !d.snapshot;
  $("reportsSection").hidden = !d.snapshot;
  if (d.snapshot && !S.treeLoaded)
    loadTree().catch((e) => {
      $("tree").textContent = e.message;
    });
  if (d.snapshot && !S.schemaLoaded)
    refreshSchema().catch((e) => {
      $("status").textContent = e.message;
    });
  if (openFirst && !S.file && S.files.length) openFile(S.files[0].path);
}
async function refreshStatus() {
  const selectedDatabase = S.database;
  try {
    const d = await api("/api/status");
    if (selectedDatabase !== S.database) return;
    S.statusData = d;
    const p = $("indexProgress");
    p.max = Math.max(1, d.total_bytes);
    p.value = d.processed_bytes;
    $("indexText").textContent =
      d.state === "ready"
        ? `Index ready • ${d.rows.toLocaleString()} rows`
        : d.state === "error"
          ? `Index error: ${d.error}`
          : `Indexing ${d.files_done}/${d.total_files}: ${d.current_file || ""} • ${formatBytes(d.processed_bytes)}/${formatBytes(d.total_bytes)} • ${d.rows.toLocaleString()} rows`;
    $("indexing").hidden = d.state === "ready" && !S.debug;
    if (d.state === "indexing") {
      await refreshFiles(false);
      setTimeout(refreshStatus, 1000);
    } else await refreshFiles(true);
  } catch (e) {
    if (selectedDatabase !== S.database) return;
    $("indexing").hidden = false;
    $("indexText").textContent = e.message;
  }
}
async function refreshDatabases() {
  const d = await api("/api/databases");
  S.library = d.library;
  $("databaseBox").hidden = !d.library;
  $("adminLink").hidden = !d.admin_enabled;
  if (!d.library) return false;
  const previous = S.database;
  const remembered = sessionStorage.getItem("adxDatabase");
  if (!d.databases.some((x) => x.id === S.database))
    S.database = d.databases.some((x) => x.id === remembered) ? remembered : d.databases[0]?.id || null;
  const select = $("database");
  select.innerHTML = d.databases
    .map(
      (x) => '<option value="' + esc(x.id) + '">' + esc(x.name) + " · " + formatBytes(x.size) + "</option>",
    )
    .join("");
  if (S.database) select.value = S.database;
  $("databaseScan").textContent =
    d.databases.length + " database" + (d.databases.length === 1 ? "" : "s") + " · live";
  return previous !== S.database;
}
$("database").onchange = async (e) => {
  S.database = e.target.value;
  sessionStorage.setItem("adxDatabase", S.database);
  resetWorkspaceState();
  await refreshStatus();
};
$("refreshTree").onclick = () => {
  S.treeLoaded = false;
  loadTree().catch((e) => {
    $("tree").textContent = e.message;
  });
};
document.addEventListener(
  "wheel",
  (e) => {
    if (Math.abs(e.deltaX) <= Math.abs(e.deltaY)) return;
    const pane = e.target.closest("main,aside");
    if (!pane) return;
    e.preventDefault();
    const scroller = e.target.closest("#tableWrap,aside") || $("tableWrap");
    scroller.scrollLeft += e.deltaX;
  },
  { passive: false },
);
const splitter = $("splitter");
const savedWidth = Number(localStorage.getItem("adxSidebarWidth"));
if (savedWidth)
  document.body.style.setProperty(
    "--sidebar-width",
    Math.max(280, Math.min(savedWidth, innerWidth - 320)) + "px",
  );
splitter.onpointerdown = (e) => {
  splitter.setPointerCapture(e.pointerId);
  splitter.classList.add("dragging");
};
splitter.onpointermove = (e) => {
  if (!splitter.hasPointerCapture(e.pointerId)) return;
  const width = Math.max(280, Math.min(e.clientX, innerWidth - 320));
  document.body.style.setProperty("--sidebar-width", width + "px");
  localStorage.setItem("adxSidebarWidth", width);
};
splitter.onpointerup = (e) => {
  splitter.releasePointerCapture(e.pointerId);
  splitter.classList.remove("dragging");
};
splitter.onkeydown = (e) => {
  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
  e.preventDefault();
  const current = parseInt(getComputedStyle(document.body).getPropertyValue("--sidebar-width")) || 420;
  const width = Math.max(280, Math.min(current + (e.key === "ArrowLeft" ? -24 : 24), innerWidth - 320));
  document.body.style.setProperty("--sidebar-width", width + "px");
  localStorage.setItem("adxSidebarWidth", width);
};
async function refreshSession() {
  const s = await api("/api/session");
  $("logoutForm").hidden = !s.auth_enabled;
}
// Deep links: #row=123 opens an object, #report=findings a computed report,
// #ldap=(filter) runs a query. They are applied once the index is ready.
async function applyHashRoute() {
  const params = new URLSearchParams(location.hash.slice(1));
  // The initial object list may still be loading; the views below refuse to
  // start while another request is in flight.
  for (let waited = 0; S.loading && waited < 100; waited++) await new Promise((r) => setTimeout(r, 50));
  if (params.has("row")) return showDetail(+params.get("row"));
  if (params.has("report")) {
    const name = params.get("report");
    const label = [...document.querySelectorAll("#reportButtons .reportBtn")].find((b) =>
      b.textContent.replace("★ ", "").toLocaleLowerCase().startsWith(name.replace(/_/g, " ")),
    );
    return openAuditReport(name, label ? label.textContent.replace("★ ", "") : name);
  }
  if (params.has("ldap")) {
    $("ldapFilter").value = params.get("ldap");
    return ldapSearch();
  }
}
window.addEventListener("hashchange", () => {
  if (location.hash) applyHashRoute().catch((e) => ($("status").textContent = e.message));
});
(async () => {
  await refreshSession();
  await refreshAuditQueries();
  await refreshDatabases();
  if (!S.library || S.database) {
    await refreshStatus();
    if (location.hash) await applyHashRoute().catch((e) => ($("status").textContent = e.message));
  } else {
    $("tableWrap").textContent = "Add a viewer .sqlite3 database anywhere below the library folder.";
    $("indexText").textContent = "Waiting for a database…";
  }
  if (S.library)
    setInterval(async () => {
      try {
        const changed = await refreshDatabases();
        if (changed && S.database) {
          resetWorkspaceState();
          await refreshStatus();
        } else if (changed) {
          resetWorkspaceState();
          renderFiles();
          $("treeSection").hidden = true;
          $("tableWrap").textContent = "Add a viewer .sqlite3 database anywhere below the library folder.";
          $("indexText").textContent = "Waiting for a database…";
        }
      } catch (e) {
        $("databaseScan").textContent = e.message;
      }
    }, 3000);
})().catch((e) => {
  $("tableWrap").textContent = e.message;
});
