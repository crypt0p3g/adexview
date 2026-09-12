"""Multi-database library: discovery, validation, naming and confinement.

Discovery is cached by file signature (path, size, mtime) so the periodic
polls from every open browser tab do not re-open and re-validate each SQLite
file; only new or changed files are inspected.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import threading
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .index import SNAPSHOT_FILE_KEY, connect, viewer_meta_value
from .snapshot import SnapshotReader

LIBRARY_REGISTRY_NAME = ".adexview-library.json"
DATABASE_SUFFIXES = {".sqlite3", ".sqlite", ".db"}
WORK_PREFIX = ".adexview-"


def opaque_id(relative: str) -> str:
    return hashlib.sha256(relative.encode("utf-8")).hexdigest()[:20]


def database_display_name(filename: str) -> str:
    """Use the SQLite filename without its suffix as the default name."""
    path = Path(filename)
    return path.stem if path.suffix.casefold() in DATABASE_SUFFIXES else path.name


def validate_database_name(value: str) -> str:
    """Validate one portable library display-name/path component."""
    name = value.strip()
    if not name:
        raise ValueError("database name is required")
    if name in {".", ".."} or name.startswith("."):
        raise ValueError("database name cannot be hidden or relative")
    if len(name) > 120:
        raise ValueError("database name must be 120 characters or fewer")
    if any(ord(character) < 32 for character in name):
        raise ValueError("database name cannot contain control characters")
    if any(character in name for character in '/\\<>:"|?*'):
        raise ValueError("database name contains a reserved filename character")
    return name


def library_registry_path(library: Path) -> Path:
    return library / LIBRARY_REGISTRY_NAME


def load_library_registry(library: Path) -> Dict[str, str]:
    try:
        value = json.loads(library_registry_path(library).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {
        str(relative): str(name) for relative, name in value.items()
        if isinstance(relative, str) and isinstance(name, str) and name.strip()
    }


def save_library_registry(library: Path, registry: Dict[str, str]) -> None:
    """Atomically save display names without modifying the databases."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=f"{LIBRARY_REGISTRY_NAME}.", suffix=".tmp", dir=library)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(registry, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, library_registry_path(library))
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def validate_viewer_database(path: Path) -> Dict[str, Any]:
    """Confirm a file is a standalone adexview database."""
    with path.open("rb") as handle:
        if handle.read(16) != b"SQLite format 3\x00":
            raise ValueError("not an SQLite database")
    try:
        with closing(connect(path, readonly=True)) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")}
            if not {"files", "rows", "object_tree"}.issubset(tables):
                raise ValueError("not an adexview database")
            if "viewer_meta" in tables and viewer_meta_value(db, "snapshot_storage_mode", "embedded") == "lean":
                raise ValueError("built in the removed lean mode; rebuild it from the snapshot")
            rows = db.execute("SELECT COALESCE(SUM(row_count),0) FROM files").fetchone()[0]
            snapshot = bool(db.execute(
                "SELECT EXISTS(SELECT 1 FROM object_tree WHERE file=?)", (SNAPSHOT_FILE_KEY,)
            ).fetchone()[0])
            server = viewer_meta_value(db, "snapshot_server", "") if "viewer_meta" in tables else ""
            audit = "audit_findings" in tables
    except sqlite3.Error as exc:
        raise ValueError(f"cannot read SQLite database: {exc}") from exc
    return {"rows": int(rows), "tables": len(tables), "snapshot": snapshot, "server": server, "audit": audit}


def validate_snapshot_file(path: Path) -> Dict[str, Any]:
    """Read enough AD Explorer metadata to reject invalid snapshot uploads."""
    try:
        with SnapshotReader(path, parse_object_offsets=False) as reader:
            return {
                "objects": int(reader.header.num_objects),
                "attributes": int(reader.header.num_attributes),
                "server": reader.header.server,
                "complete": reader.header.complete,
            }
    except Exception as exc:
        raise ValueError(f"not a readable AD Explorer snapshot: {exc}") from exc


def confined_file(path: Path, root: Path, what: str) -> Path:
    """Resolve an admin target and reject symlinks or paths outside ``root``."""
    if path.is_symlink():
        raise ValueError(f"symbolic-link {what}s cannot be administered")
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{what} is outside the configured directory") from exc
    return resolved


def snapshot_upload_path(snapshot_library: Path, name: str) -> Path:
    """Return the flat, confined destination for an uploaded snapshot."""
    safe_name = validate_database_name(name)
    return confined_file(snapshot_library / f"{safe_name}.dat", snapshot_library, "snapshot")


def _is_work_file(relative_parts: Tuple[str, ...]) -> bool:
    return any(part.startswith(WORK_PREFIX) for part in relative_parts)


class LibraryScanner:
    """Cached discovery of viewer databases and snapshots below two directories."""

    def __init__(self, library: Optional[Path], snapshot_library: Optional[Path], ttl: float = 1.0):
        self.library = library
        self.snapshot_library = snapshot_library
        self.ttl = ttl
        self._lock = threading.Lock()
        self._database_cache: Dict[str, Tuple[Tuple[int, int], Dict[str, Any]]] = {}
        self._databases: Dict[str, Dict[str, Any]] = {}
        self._databases_time = 0.0
        self._registry_signature: Any = None

    # -- databases -----------------------------------------------------------------

    def databases(self, force: bool = False, include_invalid: bool = False) -> Dict[str, Dict[str, Any]]:
        if self.library is None:
            return {}
        import time

        with self._lock:
            now = time.monotonic()
            if force or now - self._databases_time >= self.ttl:
                self._databases = self._scan_databases()
                self._databases_time = now
            items = self._databases
        if include_invalid:
            return {key: dict(value) for key, value in items.items()}
        return {key: dict(value) for key, value in items.items() if value["valid"]}

    def _scan_databases(self) -> Dict[str, Dict[str, Any]]:
        library = self.library
        assert library is not None
        registry = load_library_registry(library)
        discovered: Dict[str, Dict[str, Any]] = {}
        seen = set()
        candidates = sorted(
            (path for path in library.rglob("*")
             if path.suffix.casefold() in DATABASE_SUFFIXES and path.is_file() and not path.is_symlink()
             and not _is_work_file(path.relative_to(library).parts)),
            key=lambda item: item.relative_to(library).as_posix().casefold(),
        )
        for path in candidates:
            relative = path.relative_to(library).as_posix()
            try:
                confined_file(path, library, "database")
                stat = path.stat()
            except (OSError, ValueError):
                continue
            signature = (stat.st_size, stat.st_mtime_ns)
            seen.add(relative)
            cached = self._database_cache.get(relative)
            if cached is None or cached[0] != signature:
                details = self._inspect_database(path)
                self._database_cache[relative] = (signature, details)
            else:
                details = cached[1]
            database_id = opaque_id(relative)
            discovered[database_id] = {
                "id": database_id,
                "name": registry.get(relative, database_display_name(path.name)),
                "relative_path": relative, "path": path,
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
                **details,
            }
        for stale in set(self._database_cache) - seen:
            del self._database_cache[stale]
        return discovered

    @staticmethod
    def _inspect_database(path: Path) -> Dict[str, Any]:
        try:
            details = validate_viewer_database(path)
        except (OSError, ValueError) as exc:
            return {"rows": 0, "snapshot": False, "valid": False, "error": str(exc) or exc.__class__.__name__, "server": "", "audit": False}
        return {"rows": details["rows"], "snapshot": details["snapshot"], "valid": True, "error": "", "server": details["server"], "audit": details["audit"]}

    # -- snapshots -----------------------------------------------------------------

    def snapshots(self) -> Dict[str, Dict[str, Any]]:
        """Return flat and nested .dat snapshots below the snapshot directory."""
        root = self.snapshot_library
        if root is None:
            return {}
        discovered: Dict[str, Dict[str, Any]] = {}
        paths = sorted(
            (path for path in root.rglob("*.dat") if path.is_file() and not path.is_symlink()
             and not _is_work_file(path.relative_to(root).parts)),
            key=lambda item: item.relative_to(root).as_posix().casefold(),
        )
        for path in paths:
            relative = path.relative_to(root).as_posix()
            try:
                confined_file(path, root, "snapshot")
                stat = path.stat()
            except (OSError, ValueError):
                continue
            snapshot_id = opaque_id(relative)
            discovered[snapshot_id] = {
                "id": snapshot_id, "name": path.stem, "relative_path": relative, "path": path,
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            }
        return discovered


def discover_database_files(library: Path) -> Dict[str, Dict[str, Any]]:
    """Every database-like file below a library, including incompatible ones."""
    return LibraryScanner(library, None).databases(force=True, include_invalid=True)


def discover_databases(library: Path) -> Dict[str, Dict[str, Any]]:
    """Valid viewer databases below a library, keyed by opaque IDs."""
    return LibraryScanner(library, None).databases(force=True)


def discover_snapshots(snapshot_library: Path) -> Dict[str, Dict[str, Any]]:
    return LibraryScanner(None, snapshot_library).snapshots()
