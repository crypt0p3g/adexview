"""SQLite index of a decoded snapshot: schema, build, and connection helpers.

One row per directory object holds a compact summary (the object-list
columns), a full-text payload of its real values, and the complete decoded
object as a compressed JSON blob. A tree table gives parent/child navigation,
and an identity table resolves SIDs, GUIDs, sAMAccountNames and UPNs back to
objects for cross-reference links.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import threading
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .decoders import DEFAULT_TIMEZONE, build_search_text, decode_record, json_default
from .search import (
    display_value, is_naming_context_root, normalize_dn, object_type_for,
    parent_dn, split_distinguished_name,
)
from .snapshot import SnapshotReader

SNAPSHOT_FILE_KEY = "snapshot/objects.csv"
SCHEMA_VERSION = 11
BATCH_ROWS = 5000
BATCH_BYTES = 32 * 1024 * 1024
AUTO_VACUUM_MAX_BYTES = 1024 * 1024 * 1024
DETAIL_COMPRESSION_LEVEL = 6
SUMMARY_HEADERS = [
    "object_index", "distinguishedName", "objectType", "objectClass", "name",
    "sAMAccountName", "userPrincipalName", "servicePrincipalName", "dNSHostName", "enabled",
    "operatingSystem", "operatingSystemVersion", "uac_flags", "description",
    "whenCreated", "whenChanged", "attribute_count",
]
ADS_TYPE_NAMES = {
    1: "DN", 2: "DirectoryString", 3: "DirectoryString", 4: "DirectoryString",
    5: "NumericString", 6: "Boolean", 7: "Integer", 8: "OctetString",
    9: "GeneralizedTime", 10: "LargeInteger", 11: "ProviderSpecific", 12: "ObjectClass",
    25: "NT Security Descriptor", 27: "DNWithBinary", 28: "DNWithString",
}


class IndexStatus:
    """Thread-safe progress shared between a build and the HTTP status endpoint."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data: Dict[str, Any] = {
            "state": "starting", "current_file": "", "files_done": 0,
            "total_files": 0, "processed_bytes": 0, "total_bytes": 0,
            "rows": 0, "error": "",
        }

    def update(self, **values: Any) -> None:
        with self.lock:
            self.data.update(values)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.data)


class ScaledIndexStatus:
    """Map a nested index build into the latter part of an outer progress bar."""

    def __init__(self, target: IndexStatus, total_bytes: int, start_fraction: float = 0.4) -> None:
        self.target = target
        self.total_bytes = max(1, total_bytes)
        self.start_fraction = start_fraction
        self.source_total = 1

    def update(self, **values: Any) -> None:
        if "total_bytes" in values:
            self.source_total = max(1, int(values["total_bytes"]))
        if "processed_bytes" in values:
            ratio = min(1.0, max(0.0, int(values["processed_bytes"]) / self.source_total))
            values["processed_bytes"] = int(
                self.total_bytes * (self.start_fraction + (1.0 - self.start_fraction) * ratio)
            )
        values["total_bytes"] = self.total_bytes
        self.target.update(**values)

    def snapshot(self) -> Dict[str, Any]:
        return self.target.snapshot()


def report_index_stage(status: Optional[IndexStatus], label: str) -> None:
    """Publish a post-scan stage to both the admin UI and the terminal."""
    if status:
        status.update(current_file=label)
    print(f"{label}…", flush=True)


def connect(index_path: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        db = sqlite3.connect(Path(index_path).as_uri() + "?mode=ro", uri=True, timeout=60, check_same_thread=False)
    else:
        db = sqlite3.connect(index_path, timeout=60, check_same_thread=False)
    db.row_factory = sqlite3.Row
    if readonly:
        db.execute("PRAGMA query_only=ON")
    else:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
    # Index creation and VACUUM can otherwise consume most of a small
    # machine's RAM. Read-only queries stay in memory; writers spill temporary
    # b-trees and sort data to disk.
    db.execute(f"PRAGMA temp_store={'MEMORY' if readonly else 'FILE'}")
    db.execute("PRAGMA cache_size=-65536")
    return db


def database_allocated_bytes(db: sqlite3.Connection) -> int:
    page_count = int(db.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
    return page_count * page_size


def should_auto_vacuum(allocated_bytes: int) -> bool:
    """Keep automatic compaction away from multi-gigabyte databases."""
    return allocated_bytes < AUTO_VACUUM_MAX_BYTES


def viewer_meta_value(db: sqlite3.Connection, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM viewer_meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else default


def initialize(db: sqlite3.Connection) -> str:
    """Create or upgrade the schema; returns the FTS tokenizer in use."""
    previous_schema = db.execute("PRAGMA user_version").fetchone()[0]
    db.executescript("""
        CREATE TABLE IF NOT EXISTS files(
            path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
            row_count INTEGER NOT NULL, headers_json TEXT NOT NULL, indexed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rows(
            id INTEGER PRIMARY KEY, file TEXT NOT NULL, row_number INTEGER NOT NULL,
            row_json TEXT NOT NULL, search_text TEXT NOT NULL, detail_blob BLOB,
            source_offset INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS rows_file_number ON rows(file,row_number);
        CREATE TABLE IF NOT EXISTS object_tree(
            file TEXT NOT NULL, row_number INTEGER NOT NULL, dn TEXT NOT NULL,
            dn_norm TEXT NOT NULL, parent_norm TEXT NOT NULL, label TEXT NOT NULL,
            object_type TEXT NOT NULL, is_nc_root INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(file,row_number)
        );
        CREATE INDEX IF NOT EXISTS object_tree_parent ON object_tree(file,parent_norm,label COLLATE NOCASE);
        CREATE UNIQUE INDEX IF NOT EXISTS object_tree_dn ON object_tree(file,dn_norm);
        CREATE TABLE IF NOT EXISTS viewer_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS snapshot_properties(
            file TEXT NOT NULL,attribute TEXT NOT NULL,ads_type INTEGER NOT NULL,
            syntax TEXT NOT NULL,PRIMARY KEY(file,attribute)
        );
        CREATE TABLE IF NOT EXISTS object_lookup(
            key_type TEXT NOT NULL, key_norm TEXT NOT NULL, row_number INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS object_lookup_key ON object_lookup(key_type,key_norm);
    """)
    row_columns = {row[1] for row in db.execute("PRAGMA table_info(rows)")}
    if "detail_blob" not in row_columns:
        db.execute("ALTER TABLE rows ADD COLUMN detail_blob BLOB")
    if "source_offset" not in row_columns:
        db.execute("ALTER TABLE rows ADD COLUMN source_offset INTEGER")
    tree_columns = {row[1] for row in db.execute("PRAGMA table_info(object_tree)")}
    if "is_nc_root" not in tree_columns:
        db.execute("ALTER TABLE object_tree ADD COLUMN is_nc_root INTEGER NOT NULL DEFAULT 0")
    try:
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS row_fts USING fts5(search_text, content='rows', content_rowid='id', tokenize='trigram')")
    except sqlite3.OperationalError:
        db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS row_fts USING fts5(search_text, content='rows', content_rowid='id', tokenize='unicode61')")
    definition = db.execute("SELECT sql FROM sqlite_master WHERE name='row_fts'").fetchone()[0]
    tokenizer = "trigram" if "trigram" in definition.casefold() else "unicode61"
    lean_layout = viewer_meta_value(db, "snapshot_storage_mode", "embedded") == "lean"
    if previous_schema and (previous_schema < 10 or lean_layout):
        # Older layouts (and the removed "lean" mode, which kept no detail
        # blob) are dropped so the snapshot rebuilds in the current form.
        remove_snapshot_rows(db)
    db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    db.commit()
    return tokenizer


def remove_snapshot_rows(db: sqlite3.Connection) -> None:
    db.execute("DELETE FROM row_fts WHERE rowid IN (SELECT id FROM rows WHERE file=?)", (SNAPSHOT_FILE_KEY,))
    db.execute("DELETE FROM rows WHERE file=?", (SNAPSHOT_FILE_KEY,))
    db.execute("DELETE FROM object_tree WHERE file=?", (SNAPSHOT_FILE_KEY,))
    db.execute("DELETE FROM snapshot_properties WHERE file=?", (SNAPSHOT_FILE_KEY,))
    db.execute("DELETE FROM files WHERE path=?", (SNAPSHOT_FILE_KEY,))
    db.execute("DELETE FROM object_lookup")
    db.execute("DELETE FROM viewer_meta WHERE key LIKE 'snapshot_%'")


def add_missing_tree_ancestors(db: sqlite3.Connection, relative: str) -> int:
    """Add navigation-only containers when a real ancestor exists higher in the DN tree."""
    rows = db.execute("SELECT dn,dn_norm FROM object_tree WHERE file=?", (relative,)).fetchall()
    known = {row["dn_norm"] for row in rows}
    synthetic: Dict[str, str] = {}
    checked: set = set()
    for row in rows:
        parts = split_distinguished_name(row["dn"])
        folded = [part.casefold() for part in parts]
        missing: List[Tuple[str, str]] = []
        found_ancestor = False
        for start in range(1, len(parts)):
            normalized = ",".join(folded[start:])
            if normalized in known:
                found_ancestor = True
                break
            if normalized in checked:
                # Every ancestor above this one was already classified.
                found_ancestor = normalized in synthetic
                break
            checked.add(normalized)
            missing.append((normalized, ",".join(parts[start:])))
        if found_ancestor:
            for normalized, display in missing:
                synthetic.setdefault(normalized, display)
    if not synthetic:
        return 0
    inserts = []
    for number, (normalized, display) in enumerate(
        sorted(synthetic.items(), key=lambda item: len(split_distinguished_name(item[1]))), start=1,
    ):
        first_rdn = split_distinguished_name(display)[0]
        label = first_rdn.split("=", 1)[-1].replace("\\,", ",").replace("\\\\", "\\")
        inserts.append((relative, -number, display, normalized, normalize_dn(parent_dn(display)), label, "missing container", 0))
    db.executemany(
        "INSERT OR IGNORE INTO object_tree(file,row_number,dn,dn_norm,parent_norm,label,object_type,is_nc_root) "
        "VALUES(?,?,?,?,?,?,?,?)",
        inserts,
    )
    return len(inserts)


def _is_current(db: sqlite3.Connection, snapshot: Path, reader: SnapshotReader) -> Optional[int]:
    """Return the indexed row count when the database already matches the snapshot."""
    stat = snapshot.stat()
    previous = db.execute(
        "SELECT size,mtime_ns,row_count,headers_json FROM files WHERE path=?", (SNAPSHOT_FILE_KEY,)
    ).fetchone()
    if not previous:
        return None
    tree_rows = db.execute("SELECT COUNT(*) FROM object_tree WHERE file=?", (SNAPSHOT_FILE_KEY,)).fetchone()[0]
    property_rows = db.execute("SELECT COUNT(*) FROM snapshot_properties WHERE file=?", (SNAPSHOT_FILE_KEY,)).fetchone()[0]
    expected_rows = reader.header.num_objects
    if (
        previous["size"] == stat.st_size and previous["mtime_ns"] == stat.st_mtime_ns
        and previous["row_count"] == expected_rows
        and previous["headers_json"] == json.dumps(SUMMARY_HEADERS, ensure_ascii=False)
        and (tree_rows > 0 or expected_rows == 0)
        and property_rows == len(reader.properties)
        and viewer_meta_value(db, "snapshot_schema_version") == str(SCHEMA_VERSION)
    ):
        return int(previous["row_count"])
    return None


def index_snapshot(
    snapshot: Path,
    db: sqlite3.Connection,
    timezone_name: str = DEFAULT_TIMEZONE,
    status: Optional[IndexStatus] = None,
) -> Tuple[int, int]:
    """Decode every object of ``snapshot`` into ``db``. Returns (changed, rows)."""
    snapshot = Path(snapshot)
    stat = snapshot.stat()
    headers = SUMMARY_HEADERS
    with SnapshotReader(snapshot) as reader:
        expected_rows = reader.header.num_objects
        if status:
            status.update(
                state="indexing", current_file=str(snapshot), files_done=0, total_files=1,
                processed_bytes=0, total_bytes=stat.st_size, rows=0, error="",
            )
        current = _is_current(db, snapshot, reader)
        if current is not None:
            if status:
                status.update(
                    state="ready", current_file="", files_done=1, total_files=1,
                    processed_bytes=stat.st_size, total_bytes=stat.st_size, rows=current,
                )
            return 0, current

        print(f"Indexing snapshot {snapshot.name}: {expected_rows:,} objects, {stat.st_size / 1024 / 1024:.1f} MB…", flush=True)
        remove_snapshot_rows(db)
        db.commit()
        # A build is restartable from scratch, so durability of every batch is
        # not needed; skipping the fsyncs saves a large share of the SQLite time.
        db.execute("PRAGMA synchronous=OFF")
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO files(path,size,mtime_ns,row_count,headers_json,indexed_at) VALUES(?,?,?,?,?,?)",
            (SNAPSHOT_FILE_KEY, stat.st_size, stat.st_mtime_ns, 0, json.dumps(headers, ensure_ascii=False), now),
        )
        ads_types = reader.ads_types
        db.executemany(
            "INSERT INTO snapshot_properties(file,attribute,ads_type,syntax) VALUES(?,?,?,?)",
            ((SNAPSHOT_FILE_KEY, prop.name, prop.ads_type, ADS_TYPE_NAMES.get(prop.ads_type, f"ADS type {prop.ads_type}"))
             for prop in reader.properties),
        )
        db.commit()
        next_id = db.execute("SELECT COALESCE(MAX(id),0)+1 FROM rows").fetchone()[0]
        batch: List[Tuple[Any, ...]] = []
        tree_batch: List[Tuple[Any, ...]] = []
        lookup_batch: List[Tuple[str, str, int]] = []
        batch_bytes = 0
        row_count = 0
        properties = reader.properties

        def flush(processed: int) -> None:
            nonlocal batch, tree_batch, lookup_batch, batch_bytes
            if not batch:
                return
            db.executemany(
                "INSERT INTO rows(id,file,row_number,row_json,search_text,detail_blob,source_offset) VALUES(?,?,?,?,?,?,?)",
                batch,
            )
            # The trigram index is fed batch by batch so each commit stays
            # bounded; one whole-table rebuild at the end would hold a
            # multi-gigabyte transaction open on large snapshots.
            db.executemany("INSERT INTO row_fts(rowid,search_text) VALUES(?,?)", ((item[0], item[4]) for item in batch))
            db.executemany(
                "INSERT OR REPLACE INTO object_tree(file,row_number,dn,dn_norm,parent_norm,label,object_type,is_nc_root) VALUES(?,?,?,?,?,?,?,?)",
                tree_batch,
            )
            db.executemany("INSERT INTO object_lookup(key_type,key_norm,row_number) VALUES(?,?,?)", lookup_batch)
            db.execute("UPDATE files SET row_count=?,indexed_at=? WHERE path=?", (row_count, datetime.now(timezone.utc).isoformat(), SNAPSHOT_FILE_KEY))
            db.commit()
            batch, tree_batch, lookup_batch, batch_bytes = [], [], [], 0
            if status:
                status.update(processed_bytes=processed, rows=row_count)

        for row_count, entry in enumerate(reader.iter_entries(), start=1):
            raw = entry.to_dict(decode=False)
            decoded = decode_record(raw, ads_types=ads_types, timezone_name=timezone_name)
            lower = {name.casefold(): value for name, value in decoded.items()}
            get = lower.get
            object_classes = get("objectclass", [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes] if object_classes else []
            object_type = object_type_for(object_classes)
            class_names = [str(item).casefold() for item in object_classes]
            uac = get("useraccountcontrol")
            if isinstance(uac, dict):
                uac_value = uac.get("value")
                uac_flags = ", ".join(str(item) for item in uac.get("flags", []))
            else:
                uac_value = uac if uac not in ("", None) else None
                uac_flags = display_value(uac)
            try:
                enabled = "false" if int(uac_value) & 0x2 else "true"
            except (TypeError, ValueError):
                enabled = ""
            object_dn = display_value(get("distinguishedname", ""))
            values = [
                str(row_count), object_dn, object_type, display_value(get("objectclass", "")),
                display_value(get("name", "")), display_value(get("samaccountname", "")),
                display_value(get("userprincipalname", "")), display_value(get("serviceprincipalname", "")),
                display_value(get("dnshostname", "")), enabled,
                display_value(get("operatingsystem", "")), display_value(get("operatingsystemversion", "")),
                uac_flags, display_value(get("description", "")),
                display_value(get("whencreated", "")), display_value(get("whenchanged", "")),
                str(len(entry.mapping)),
            ]
            row_json = json.dumps(values, ensure_ascii=False, separators=(",", ":"))
            attribute_names = sorted((properties[index].name for index, _offset in entry.mapping), key=str.casefold)
            # The full decoded object is stored verbatim (compressed) so the
            # detail view is complete; the full-text payload is a compact
            # projection of the object's real values so the trigram index does
            # not carry every security-descriptor and binary blob.
            detail_json = json.dumps(decoded, ensure_ascii=False, default=json_default)
            search_text = build_search_text(decoded, attribute_names)
            detail_blob = zlib.compress(detail_json.encode("utf-8"), DETAIL_COMPRESSION_LEVEL)
            batch.append((next_id, SNAPSHOT_FILE_KEY, row_count, row_json, search_text, detail_blob, entry.offset))
            if object_dn:
                parts = split_distinguished_name(object_dn)
                dn_norm = ",".join(part.casefold() for part in parts)
                parent_norm = ",".join(part.casefold() for part in parts[1:])
                label = display_value(get("name", "")) or (parts[0].split("=", 1)[-1] if parts else object_dn)
                tree_batch.append((
                    SNAPSHOT_FILE_KEY, row_count, object_dn, dn_norm, parent_norm, label,
                    object_type, int(is_naming_context_root(class_names, object_type)),
                ))
            for kind, raw_value in (
                ("sid", get("objectsid")), ("sam", get("samaccountname")),
                ("upn", get("userprincipalname")), ("guid", get("objectguid")),
            ):
                if isinstance(raw_value, dict):
                    text = str(raw_value.get("guid") or raw_value.get("sid") or "")
                else:
                    text = display_value(raw_value)
                text = text.strip()
                if text:
                    lookup_batch.append((kind, text.casefold(), row_count))
            next_id += 1
            batch_bytes += len(row_json) + len(search_text) + len(detail_blob)
            processed = stat.st_size * row_count // max(1, expected_rows)
            if len(batch) >= BATCH_ROWS or batch_bytes >= BATCH_BYTES:
                flush(processed)
            if row_count % 1000 == 0 or row_count == expected_rows:
                percent = processed * 100 // max(1, stat.st_size)
                print(
                    f"\r  {row_count:,}/{expected_rows:,} objects • {processed / 1024 / 1024:.1f}/{stat.st_size / 1024 / 1024:.1f} MB ({percent}%)",
                    end="", flush=True,
                )
        flush(stat.st_size)
        if row_count:
            print(flush=True)
        report_index_stage(status, "Finalizing directory tree")
        add_missing_tree_ancestors(db, SNAPSHOT_FILE_KEY)
        db.execute(
            "UPDATE files SET size=?,mtime_ns=?,row_count=?,headers_json=?,indexed_at=? WHERE path=?",
            (stat.st_size, stat.st_mtime_ns, row_count, json.dumps(headers, ensure_ascii=False), datetime.now(timezone.utc).isoformat(), SNAPSHOT_FILE_KEY),
        )
        metadata = {
            "snapshot_schema_version": str(SCHEMA_VERSION),
            "snapshot_source_path": str(snapshot.resolve()),
            "snapshot_source_name": snapshot.name,
            "snapshot_source_size": str(stat.st_size),
            "snapshot_source_mtime_ns": str(stat.st_mtime_ns),
            "snapshot_timezone": timezone_name,
            "snapshot_server": reader.header.server,
            "snapshot_captured_utc": reader.header.captured_at.isoformat(),
        }
        db.executemany(
            "INSERT INTO viewer_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            metadata.items(),
        )
        db.commit()
    # Merge the FTS b-tree segments written during the batched build so the
    # trigram index is stored compactly instead of as many partial segments.
    report_index_stage(status, "Optimizing search index")
    try:
        db.execute("INSERT INTO row_fts(row_fts) VALUES('optimize')")
        db.execute("PRAGMA optimize")
        db.commit()
    except sqlite3.OperationalError:
        pass
    report_index_stage(status, "Checkpointing database")
    try:
        db.commit()
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.commit()
    except sqlite3.OperationalError:
        pass
    allocated_bytes = database_allocated_bytes(db)
    if should_auto_vacuum(allocated_bytes):
        report_index_stage(status, "Compacting database")
        try:
            db.execute("VACUUM")
            db.commit()
        except sqlite3.OperationalError:
            pass
    else:
        report_index_stage(status, f"Finalizing database; automatic compaction skipped for {allocated_bytes / 1024 / 1024 / 1024:.1f} GB file")
    if status:
        status.update(
            state="ready", current_file="", files_done=1, total_files=1,
            processed_bytes=stat.st_size, total_bytes=stat.st_size, rows=row_count,
        )
    return 1, row_count


def ensure_sort_index(db: sqlite3.Connection, sort_col: int) -> None:
    """Create, on first use, an expression index that matches the list sort.

    Sorting the object list by a column is ``ORDER BY json_extract(row_json,
    '$[N]') COLLATE NOCASE, row_number``. Without an index this is a full scan
    plus filesort of the whole file on every page; the matching expression
    index turns it into an ordered range scan. It is best-effort: on a
    read-only connection the create is skipped and the query falls back to
    the unindexed sort.
    """
    if sort_col < 0:
        return
    try:
        db.execute(
            f"CREATE INDEX IF NOT EXISTS rows_sort_c{sort_col} "
            f"ON rows(file, json_extract(row_json, '$[{sort_col}]') COLLATE NOCASE, row_number)"
        )
    except sqlite3.OperationalError:
        pass


def project_index_path(project: Path) -> Path:
    """The viewer database of an audit project directory."""
    return project / f"{project.name}.sqlite3"


def snapshot_index_path(snapshot: Path, database: Optional[str] = None) -> Path:
    if database:
        return Path(database).expanduser().resolve()
    return snapshot.with_name(snapshot.stem + ".sqlite3")


def project_snapshot_path(project: Path) -> Optional[Path]:
    """The snapshot an audit project was built from, when it is still present."""
    metadata_path = project / "metadata.json"
    if not metadata_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
        candidate = Path(str(metadata.get("snapshot", ""))).expanduser()
    except (OSError, ValueError, TypeError):
        return None
    return candidate.resolve() if candidate.is_file() else None
