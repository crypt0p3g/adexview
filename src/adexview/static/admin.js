const $ = (id) => document.getElementById(id);
let nameEdited = false,
  snapshotNameEdited = false,
  snapshotRenderSignature = "";
const knownJobs = new Map(),
  conversionNameDrafts = new Map();
function formatBytes(value) {
  let n = Number(value);
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (n < 1024 || unit === "TB") return n.toFixed(unit === "B" ? 0 : 1) + " " + unit;
    n /= 1024;
  }
}
async function responseJson(response) {
  if (response.status === 401) {
    location.href = "/login";
    throw Error("login required");
  }
  let value = {};
  try {
    value = await response.json();
  } catch {}
  if (!response.ok) throw Error(value.error || response.statusText);
  return value;
}
async function adminFetch(url, options = {}) {
  return responseJson(await fetch(url, options));
}
async function refresh() {
  try {
    const value = await adminFetch("/api/admin/databases");
    render(value.databases);
    const viewers = value.databases.filter((database) => database.valid !== false).length;
    const others = value.databases.length - viewers;
    $("listStatus").textContent =
      viewers +
      " viewer database" +
      (viewers === 1 ? "" : "s") +
      (others ? " · " + others + " other database file" + (others === 1 ? "" : "s") : "");
  } catch (error) {
    $("listStatus").textContent = error.message;
  }
}
function render(databases) {
  const body = $("databaseRows");
  body.textContent = "";
  $("empty").hidden = databases.length !== 0;
  for (const database of databases) {
    const viewer = database.valid !== false;
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    const name = document.createElement("input");
    name.className = "dbName";
    name.value = database.name;
    name.maxLength = 120;
    name.disabled = !viewer;
    name.setAttribute("aria-label", "Name for " + database.name);
    const path = document.createElement("div");
    path.className = "path";
    path.textContent = database.relative_path;
    identity.append(name, path);
    if (!viewer) {
      const problem = document.createElement("div");
      problem.className = "invalidFile";
      problem.textContent = database.error || "Not an adexview database";
      identity.append(problem);
    }
    const size = document.createElement("td");
    size.textContent = formatBytes(database.size);
    const rows = document.createElement("td");
    rows.textContent = viewer ? Number(database.rows).toLocaleString() : "—";
    const modified = document.createElement("td");
    modified.textContent = new Date(database.mtime_ns / 1e6).toLocaleString();
    const actions = document.createElement("td");
    actions.className = "actions";
    const rename = document.createElement("button");
    rename.textContent = "Save name";
    rename.disabled = true;
    if (viewer) {
      name.oninput = () => {
        rename.disabled = name.value.trim() === database.name || !name.value.trim();
      };
      name.onkeydown = (event) => {
        if (event.key === "Enter" && !rename.disabled) rename.click();
      };
      rename.onclick = () => renameDatabase(database, name.value);
    }
    const remove = document.createElement("button");
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.onclick = () => {
      if (remove.dataset.confirm === "1") {
        deleteDatabase(database);
        return;
      }
      remove.dataset.confirm = "1";
      remove.textContent = "Confirm delete";
      remove.title = "Permanently delete " + database.relative_path;
      setTimeout(() => {
        if (remove.isConnected) {
          remove.dataset.confirm = "";
          remove.textContent = "Delete";
        }
      }, 5000);
    };
    actions.append(rename, remove);
    row.append(identity, size, rows, modified, actions);
    body.append(row);
  }
}
async function renameDatabase(database, next) {
  if (next.trim() === database.name) return;
  try {
    await adminFetch("/api/admin/rename", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: database.id, name: next }),
    });
    await refresh();
  } catch (error) {
    $("listStatus").textContent = error.message;
  }
}
async function deleteDatabase(database) {
  try {
    await adminFetch("/api/admin/database?id=" + encodeURIComponent(database.id), { method: "DELETE" });
    if (sessionStorage.getItem("adxDatabase") === database.id) sessionStorage.removeItem("adxDatabase");
    await refresh();
  } catch (error) {
    $("listStatus").textContent = error.message;
  }
}
function latestJob(snapshot, jobs) {
  return jobs
    .filter((job) => job.snapshot_id === snapshot.id)
    .sort((a, b) => b.started_at.localeCompare(a.started_at))[0];
}
function renderSnapshots(value) {
  const focusedInput = document.activeElement?.matches?.("input[data-snapshot-id]")
    ? document.activeElement
    : null;
  const selectionStart = focusedInput?.selectionStart,
    selectionEnd = focusedInput?.selectionEnd,
    focusedId = focusedInput?.dataset.snapshotId;
  $("snapshotDirectory").textContent = value.directory ? "Directory: " + value.directory : "";
  const body = $("snapshotRows");
  body.textContent = "";
  $("snapshotEmpty").hidden = value.snapshots.length !== 0;
  for (const snapshot of value.snapshots) {
    const job = latestJob(snapshot, value.jobs);
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    const title = document.createElement("div");
    title.className = "dbName";
    title.textContent = snapshot.name;
    const path = document.createElement("div");
    path.className = "path";
    path.textContent = snapshot.relative_path;
    identity.append(title, path);
    const size = document.createElement("td");
    size.textContent = formatBytes(snapshot.size);
    const modified = document.createElement("td");
    modified.textContent = new Date(snapshot.mtime_ns / 1e6).toLocaleString();
    const conversion = document.createElement("td");
    const convertBox = document.createElement("div");
    convertBox.className = "convert";
    const outputName = document.createElement("input");
    outputName.dataset.snapshotId = snapshot.id;
    outputName.value = conversionNameDrafts.has(snapshot.id)
      ? conversionNameDrafts.get(snapshot.id)
      : job?.database_name || snapshot.name;
    outputName.maxLength = 120;
    outputName.setAttribute("aria-label", "Database name for " + snapshot.name);
    outputName.oninput = () => conversionNameDrafts.set(snapshot.id, outputName.value);
    const convert = document.createElement("button");
    convert.textContent = job && ["queued", "running"].includes(job.state) ? "Converting…" : "Convert";
    convert.disabled = !!job && ["queued", "running"].includes(job.state);
    convert.onclick = () => convertSnapshot(snapshot, outputName.value, $("snapshotAudit").checked);
    convertBox.append(outputName, convert);
    conversion.append(convertBox);
    const progressCell = document.createElement("td");
    progressCell.className = "job";
    if (job) {
      const message = document.createElement("div");
      message.textContent =
        job.state === "complete"
          ? `Complete${job.audit ? " with audit" : ""} · ${Number(job.rows).toLocaleString()} objects`
          : job.state === "error"
            ? `Failed: ${job.error || "unknown error"}`
            : `${job.stage} · ${Number(job.rows).toLocaleString()} objects`;
      progressCell.append(message);
      if (["queued", "running"].includes(job.state)) {
        const progress = document.createElement("progress");
        progress.max = Math.max(1, job.total_bytes);
        progress.value = job.processed_bytes;
        progressCell.append(progress);
      }
    } else progressCell.textContent = "Not converted in this session";
    const actions = document.createElement("td");
    actions.className = "actions";
    const remove = document.createElement("button");
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.disabled = !!job && ["queued", "running"].includes(job.state);
    remove.onclick = () => {
      if (remove.dataset.confirm === "1") {
        deleteSnapshot(snapshot);
        return;
      }
      remove.dataset.confirm = "1";
      remove.textContent = "Confirm delete";
      remove.title = "Permanently delete " + snapshot.name;
      setTimeout(() => {
        if (remove.isConnected) {
          remove.dataset.confirm = "";
          remove.textContent = "Delete";
        }
      }, 5000);
    };
    actions.append(remove);
    row.append(identity, size, modified, conversion, progressCell, actions);
    body.append(row);
  }
  if (focusedId) {
    const replacement = [...body.querySelectorAll("input[data-snapshot-id]")].find(
      (input) => input.dataset.snapshotId === focusedId,
    );
    if (replacement) {
      replacement.focus();
      if (selectionStart !== null && selectionStart !== undefined)
        replacement.setSelectionRange(selectionStart, selectionEnd);
    }
  }
}
function snapshotsSignature(value) {
  return JSON.stringify([
    value.directory,
    value.snapshots.map((snapshot) => [
      snapshot.id,
      snapshot.relative_path,
      snapshot.size,
      snapshot.mtime_ns,
    ]),
    value.jobs.map((job) => [
      job.id,
      job.snapshot_id,
      job.database_name,
      job.audit,
      job.state,
      job.stage,
      job.processed_bytes,
      job.total_bytes,
      job.rows,
      job.error,
    ]),
  ]);
}
async function refreshSnapshots() {
  try {
    const value = await adminFetch("/api/admin/snapshots");
    let databaseChanged = false;
    for (const job of value.jobs) {
      const previous = knownJobs.get(job.id);
      if (previous && previous !== job.state && job.state === "complete") databaseChanged = true;
      knownJobs.set(job.id, job.state);
    }
    const ids = new Set(value.snapshots.map((snapshot) => snapshot.id));
    for (const id of conversionNameDrafts.keys()) if (!ids.has(id)) conversionNameDrafts.delete(id);
    const signature = snapshotsSignature(value);
    if (signature !== snapshotRenderSignature) {
      snapshotRenderSignature = signature;
      renderSnapshots(value);
    }
    const active = value.jobs.filter((job) => ["queued", "running"].includes(job.state));
    $("snapshotStatus").textContent =
      value.snapshots.length +
      " snapshot" +
      (value.snapshots.length === 1 ? "" : "s") +
      (active.length ? " · conversion running" : "");
    if (databaseChanged) await refresh();
  } catch (error) {
    $("snapshotStatus").textContent = error.message;
  }
}
async function convertSnapshot(snapshot, name, audit) {
  const outputName = name.trim();
  conversionNameDrafts.set(snapshot.id, outputName || snapshot.name);
  try {
    await adminFetch("/api/admin/snapshot-convert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: snapshot.id, name: outputName, audit: Boolean(audit) }),
    });
    await refreshSnapshots();
  } catch (error) {
    $("snapshotStatus").textContent = error.message;
  }
}
async function deleteSnapshot(snapshot) {
  try {
    await adminFetch("/api/admin/snapshot?id=" + encodeURIComponent(snapshot.id), { method: "DELETE" });
    conversionNameDrafts.delete(snapshot.id);
    await refreshSnapshots();
  } catch (error) {
    $("snapshotStatus").textContent = error.message;
  }
}
$("snapshotFile").onchange = () => {
  const file = $("snapshotFile").files[0];
  if (file && (!snapshotNameEdited || !$("snapshotName").value.trim())) {
    $("snapshotName").value = file.name.replace(/\.dat$/i, "");
    snapshotNameEdited = false;
  }
};
$("snapshotName").oninput = () => {
  snapshotNameEdited = true;
};
$("snapshotUploadButton").onclick = () => {
  const file = $("snapshotFile").files[0];
  const name = $("snapshotName").value.trim();
  if (!file) {
    $("snapshotUploadStatus").textContent = "Choose a .dat snapshot first.";
    return;
  }
  const button = $("snapshotUploadButton");
  const progress = $("snapshotUploadProgress");
  button.disabled = true;
  progress.hidden = false;
  progress.max = file.size || 1;
  progress.value = 0;
  $("snapshotUploadStatus").textContent = "Uploading " + file.name + "…";
  const request = new XMLHttpRequest();
  request.open(
    "PUT",
    "/api/admin/snapshot-upload?name=" +
      encodeURIComponent(name) +
      "&filename=" +
      encodeURIComponent(file.name),
  );
  request.upload.onprogress = (event) => {
    if (event.lengthComputable) {
      progress.max = event.total;
      progress.value = event.loaded;
      $("snapshotUploadStatus").textContent =
        "Uploading… " +
        formatBytes(event.loaded) +
        " / " +
        formatBytes(event.total) +
        " (" +
        Math.floor((event.loaded * 100) / event.total) +
        "%)";
    }
  };
  request.onload = async () => {
    button.disabled = false;
    if (request.status === 401) {
      location.href = "/login";
      return;
    }
    let value = {};
    try {
      value = JSON.parse(request.responseText || "{}");
    } catch {}
    if (request.status < 200 || request.status >= 300) {
      $("snapshotUploadStatus").textContent = value.error || request.statusText;
      return;
    }
    progress.value = progress.max;
    $("snapshotUploadStatus").textContent =
      "Uploaded " + value.snapshot.name + " · " + Number(value.details.objects).toLocaleString() + " objects";
    $("snapshotFile").value = "";
    $("snapshotName").value = "";
    snapshotNameEdited = false;
    await refreshSnapshots();
  };
  request.onerror = () => {
    button.disabled = false;
    $("snapshotUploadStatus").textContent = "Upload failed: connection interrupted.";
  };
  request.onabort = () => {
    button.disabled = false;
    $("snapshotUploadStatus").textContent = "Upload cancelled.";
  };
  request.send(file);
};
$("uploadFile").onchange = () => {
  const file = $("uploadFile").files[0];
  if (file && (!nameEdited || !$("uploadName").value.trim())) {
    $("uploadName").value = file.name.replace(/\.(sqlite3?|db)$/i, "");
    nameEdited = false;
  }
};
$("uploadName").oninput = () => {
  nameEdited = true;
};
$("uploadButton").onclick = () => {
  const file = $("uploadFile").files[0];
  const name = $("uploadName").value.trim();
  if (!file) {
    $("uploadStatus").textContent = "Choose a database file first.";
    return;
  }
  const button = $("uploadButton");
  const progress = $("uploadProgress");
  button.disabled = true;
  progress.hidden = false;
  progress.max = file.size || 1;
  progress.value = 0;
  $("uploadStatus").textContent = "Uploading " + file.name + "…";
  const request = new XMLHttpRequest();
  request.open(
    "PUT",
    "/api/admin/upload?name=" + encodeURIComponent(name) + "&filename=" + encodeURIComponent(file.name),
  );
  request.upload.onprogress = (event) => {
    if (event.lengthComputable) {
      progress.max = event.total;
      progress.value = event.loaded;
      $("uploadStatus").textContent =
        "Uploading… " +
        formatBytes(event.loaded) +
        " / " +
        formatBytes(event.total) +
        " (" +
        Math.floor((event.loaded * 100) / event.total) +
        "%)";
    }
  };
  request.onload = async () => {
    button.disabled = false;
    if (request.status === 401) {
      location.href = "/login";
      return;
    }
    let value = {};
    try {
      value = JSON.parse(request.responseText || "{}");
    } catch {}
    if (request.status < 200 || request.status >= 300) {
      $("uploadStatus").textContent = value.error || request.statusText;
      return;
    }
    progress.value = progress.max;
    $("uploadStatus").textContent =
      "Uploaded " + value.database.name + " · " + formatBytes(value.database.size);
    $("uploadFile").value = "";
    $("uploadName").value = "";
    nameEdited = false;
    await refresh();
  };
  request.onerror = () => {
    button.disabled = false;
    $("uploadStatus").textContent = "Upload failed: connection interrupted.";
  };
  request.onabort = () => {
    button.disabled = false;
    $("uploadStatus").textContent = "Upload cancelled.";
  };
  request.send(file);
};
$("refresh").onclick = refresh;
$("snapshotRefresh").onclick = refreshSnapshots;
refresh();
refreshSnapshots();
setInterval(refreshSnapshots, 1000);
