"""HTTP server: the browser viewer, its JSON API, and database administration."""

from __future__ import annotations

import html
import json
import os
import secrets
import shutil
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import traceback
from contextlib import closing
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .auth import AuthManager
from .decoders import DEFAULT_TIMEZONE, json_default
from .index import (
    SNAPSHOT_FILE_KEY, IndexStatus, ScaledIndexStatus, connect, ensure_sort_index,
    index_snapshot, initialize, viewer_meta_value,
)
from .ldapfilter import FilterSyntaxError, parse_filter
from .library import (
    LibraryScanner, confined_file, database_display_name, load_library_registry,
    opaque_id, save_library_registry, snapshot_upload_path, validate_database_name,
    validate_snapshot_file, validate_viewer_database, DATABASE_SUFFIXES,
)
from .presets import AUDIT_QUERY_PRESETS, COMPUTED_REPORTS
from .search import (
    build_field_filters, can_evaluate_from_summary, decode_indexed_detail, display_value,
    evaluate_node, indexed_attribute_value, ldap_fts_candidate_query, normalize_dn,
    normalize_viewer_ldap_filter, summary_filter_detail, ci_value,
)
from .ldapfilter import filter_attributes

STATIC_DIR = Path(__file__).parent / "static"
MAX_PAGE_SIZE = 500
UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024
CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:"
STATIC_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".html": "text/html; charset=utf-8", ".svg": "image/svg+xml"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class AdminAuthorizationError(ValueError):
    """Raised when an administration request is not permitted."""


class AuthenticationRequired(Exception):
    """Raised when a request has no valid session."""


def build_tls_context(certificate: Optional[str], private_key: Optional[str]) -> Optional[ssl.SSLContext]:
    """Return an HTTPS server context, requiring a complete cert/key pair."""
    if not certificate and not private_key:
        return None
    if not certificate or not private_key:
        raise ValueError("--tls-cert and --tls-key must be provided together")
    certificate_path = Path(certificate).expanduser().resolve()
    key_path = Path(private_key).expanduser().resolve()
    if not certificate_path.is_file():
        raise ValueError(f"TLS certificate not found: {certificate_path}")
    if not key_path.is_file():
        raise ValueError(f"TLS private key not found: {key_path}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"cannot load TLS certificate/key: {exc}") from exc
    return context


def is_loopback_host(host: str) -> bool:
    return host.strip("[]") in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def create_server(host: str, port: int, handler: type, tls_context: Optional[ssl.SSLContext] = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), handler)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def _read_static(name: str) -> bytes:
    return (STATIC_DIR / name).read_bytes()


class ViewerApp:
    """Shared state for every request handler of one server process."""

    def __init__(
        self,
        *,
        auth: AuthManager,
        project: Optional[Path] = None,
        index_path: Optional[Path] = None,
        status: Optional[IndexStatus] = None,
        library: Optional[Path] = None,
        snapshot_library: Optional[Path] = None,
        admin_enabled: bool = False,
        access_log: bool = False,
        conversion_timezone: str = DEFAULT_TIMEZONE,
        bind_host: str = "127.0.0.1",
        allowed_hosts: Optional[List[str]] = None,
    ) -> None:
        self.auth = auth
        self.project = project
        self.index_path = index_path
        self.status = status
        self.library = library.resolve() if library is not None else None
        self.snapshot_library = snapshot_library.resolve() if snapshot_library is not None else None
        library = self.library
        snapshot_library = self.snapshot_library
        self.admin_enabled = admin_enabled and library is not None
        self.access_log = access_log
        self.conversion_timezone = conversion_timezone
        self.scanner = LibraryScanner(library, snapshot_library)
        self.admin_lock = threading.Lock()
        self.conversion_jobs: Dict[str, Dict[str, Any]] = {}
        self.reserved_names: set = set()
        self.static_cache: Dict[str, bytes] = {}
        # When bound to loopback, only loopback Host headers are accepted so a
        # web page cannot reach the viewer through DNS rebinding. On other
        # binds the operator chooses the names; the login protects the data.
        self.enforce_host = is_loopback_host(bind_host)
        self.allowed_hosts = {host.casefold() for host in (allowed_hosts or [])}

    @property
    def library_mode(self) -> bool:
        return self.library is not None

    def static(self, name: str) -> bytes:
        body = self.static_cache.get(name)
        if body is None:
            body = self.static_cache[name] = _read_static(name)
        return body

    def host_allowed(self, host_header: Optional[str]) -> bool:
        if not host_header:
            return not self.enforce_host
        host = host_header.rsplit(":", 1)[0] if not host_header.startswith("[") else host_header.split("]")[0] + "]"
        host = host.casefold()
        if host in self.allowed_hosts:
            return True
        if not self.enforce_host:
            return True
        return host.strip("[]") in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")

    # -- conversions ---------------------------------------------------------------

    def public_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        state = job["status"].snapshot()
        stage = state["current_file"] or state["state"]
        if stage and Path(stage).is_absolute():
            stage = Path(stage).name
        return {key: value for key, value in job.items() if key != "status"} | {
            "stage": stage, "processed_bytes": state["processed_bytes"],
            "total_bytes": state["total_bytes"], "rows": state["rows"], "error": state["error"],
        }

    def convert_snapshot(self, job_id: str, snapshot: Path, name: str, include_audit: bool) -> None:
        library = self.library
        assert library is not None
        temporary_directory = Path(tempfile.mkdtemp(prefix=f".adexview-convert-{job_id}-", dir=library))
        temporary_database = temporary_directory / f"{name}.sqlite3"
        with self.admin_lock:
            job = self.conversion_jobs[job_id]
            job["state"] = "running"
            job["status"].update(state="indexing", current_file="Reading snapshot metadata")
        try:
            if include_audit:
                from .audit import main as audit_main

                snapshot_size = snapshot.stat().st_size

                def audit_progress(stage: str, completed: int, total: int) -> None:
                    fraction = 0.0
                    if stage.startswith("Loading objects"):
                        fraction = 0.2 * completed / max(1, total)
                    elif stage.startswith("Scanning sensitive"):
                        fraction = 0.2 + 0.2 * completed / max(1, total)
                    elif stage.startswith(("Building security", "Finalizing audit", "Building searchable")):
                        fraction = 0.4
                    elif stage.startswith("Audit and database"):
                        fraction = 1.0
                    job["status"].update(
                        state="indexing", current_file=stage,
                        processed_bytes=int(snapshot_size * fraction), total_bytes=snapshot_size, rows=completed,
                    )

                result = audit_main(
                    ["--snapshot", str(snapshot), "--output", str(temporary_directory),
                     "--output-mode", "both", "--database", str(temporary_database),
                     "--timezone", self.conversion_timezone],
                    progress=audit_progress,
                    index_status=ScaledIndexStatus(job["status"], snapshot_size),
                )
                if result:
                    raise ValueError(f"audit conversion exited with status {result}")
                rows = validate_viewer_database(temporary_database)["rows"]
            else:
                with closing(connect(temporary_database)) as db:
                    initialize(db)
                    _changed, rows = index_snapshot(snapshot, db, self.conversion_timezone, job["status"])
            job["status"].update(state="indexing", current_file="Publishing database")
            with self.admin_lock:
                target_directory = library / name
                target_database = target_directory / f"{name}.sqlite3"
                if target_directory.exists() or target_database.exists():
                    raise ValueError(f'database destination for "{name}" already exists')
                os.replace(temporary_directory, target_directory)
                relative = target_database.relative_to(library).as_posix()
                registry = load_library_registry(library)
                registry[relative] = name
                try:
                    save_library_registry(library, registry)
                except Exception:
                    os.replace(target_directory, temporary_directory)
                    raise
                self.scanner.databases(force=True)
                job["state"] = "complete"
                job["finished_at"] = datetime.now(timezone.utc).isoformat()
                job["status"].update(state="ready", current_file="Conversion complete", rows=rows)
        except Exception as exc:
            shutil.rmtree(temporary_directory, ignore_errors=True)
            with self.admin_lock:
                job["state"] = "error"
                job["finished_at"] = datetime.now(timezone.utc).isoformat()
                job["status"].update(state="error", current_file="Conversion failed", error=str(exc))
        finally:
            with self.admin_lock:
                self.reserved_names.discard(name.casefold())


def make_handler(app: ViewerApp) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "adexview"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # -- plumbing ----------------------------------------------------------------

        def log_message(self, fmt: str, *args: Any) -> None:
            if app.access_log:
                sys.stderr.write("viewer: " + fmt % args + "\n")

        def client_address_text(self) -> str:
            return str(self.client_address[0])

        def send_bytes(self, body: bytes, content_type: str, status: int = 200, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, value: Any, status: int = 200, extra: Optional[Dict[str, str]] = None) -> None:
            body = json.dumps(value, ensure_ascii=False, default=json_default).encode("utf-8")
            self.send_bytes(body, "application/json; charset=utf-8", status, {"Cache-Control": "no-store", **(extra or {})})

        def send_page(self, name: str, status: int = 200, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_bytes(app.static(name), "text/html; charset=utf-8", status, {
                "Content-Security-Policy": CSP, "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                **(extra or {}),
            })

        def redirect(self, location: str, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()

        def dispatch(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            try:
                if not app.host_allowed(self.headers.get("Host")):
                    self.close_connection = True
                    self.send_json({"error": "request host is not allowed for this server"}, 421)
                    return
                if path.startswith("/static/"):
                    self.serve_static(path[len("/static/"):])
                    return
                if path == "/login":
                    self.login(method, parsed)
                    return
                if path == "/logout" and method == "POST":
                    self.logout()
                    return
                session = app.auth.session_from_cookie(self.headers.get("Cookie"))
                if session is None:
                    raise AuthenticationRequired()
                if method == "GET":
                    self.do_get_authenticated(path, query)
                elif method == "POST":
                    self.do_post_authenticated(path)
                elif method == "PUT":
                    self.do_put_authenticated(path, query)
                elif method == "DELETE":
                    self.do_delete_authenticated(path, query)
                else:
                    self.send_json({"error": "method not allowed"}, 405)
            except AuthenticationRequired:
                self.close_connection = True
                if path.startswith("/api/"):
                    self.send_json({"error": "authentication required"}, 401)
                else:
                    self.redirect("/login")
            except AdminAuthorizationError as exc:
                self.close_connection = True
                self.send_json({"error": str(exc)}, 403)
            except (ValueError, sqlite3.Error, FilterSyntaxError, OSError) as exc:
                self.close_connection = True
                self.send_json({"error": str(exc) or exc.__class__.__name__}, 400)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:  # pragma: no cover - defensive
                traceback.print_exc()
                self.close_connection = True
                try:
                    self.send_json({"error": f"internal error: {exc.__class__.__name__}"}, 500)
                except Exception:
                    pass

        def do_GET(self) -> None:
            self.dispatch("GET")

        def do_POST(self) -> None:
            self.dispatch("POST")

        def do_PUT(self) -> None:
            self.dispatch("PUT")

        def do_DELETE(self) -> None:
            self.dispatch("DELETE")

        # -- public routes -----------------------------------------------------------

        def serve_static(self, name: str) -> None:
            if (
                not name or Path(name).name != name or name.startswith(".")
                or Path(name).suffix not in STATIC_TYPES or not (STATIC_DIR / name).is_file()
            ):
                self.send_json({"error": "not found"}, 404)
                return
            self.send_bytes(app.static(name), STATIC_TYPES[Path(name).suffix], 200, {"Cache-Control": "no-cache"})

        def login(self, method: str, parsed: Any) -> None:
            if not app.auth.enabled:
                self.redirect("/")
                return
            if method == "GET":
                self.send_page("login.html")
                return
            if method != "POST":
                self.send_json({"error": "method not allowed"}, 405)
                return
            client = self.client_address_text()
            delay = app.auth.login_delay(client)
            if delay > 0:
                time.sleep(min(delay, 5.0))
                if delay > 5.0:
                    self.send_page("login.html", 429, {"Retry-After": str(int(delay))})
                    return
            form = self.read_form_body()
            password = form.get("password", [""])[0]
            if app.auth.check_password(password):
                app.auth.clear_failures(client)
                token = app.auth.create_session()
                self.redirect("/", {"Set-Cookie": app.auth.cookie_header(token)})
                return
            app.auth.record_failure(client)
            body = app.static("login.html").replace(b"<!--error-->", b'<p class="error">Incorrect password.</p>')
            self.send_bytes(body, "text/html; charset=utf-8", 401, {
                "Content-Security-Policy": CSP, "X-Frame-Options": "DENY", "Cache-Control": "no-store",
            })

        def logout(self) -> None:
            cookie = self.headers.get("Cookie")
            token = app.auth.session_from_cookie(cookie) if app.auth.enabled else None
            app.auth.revoke(token)
            self.redirect("/login" if app.auth.enabled else "/", {"Set-Cookie": app.auth.clear_cookie_header()})

        # -- authenticated routing -----------------------------------------------------

        def do_get_authenticated(self, path: str, query: Dict[str, List[str]]) -> None:
            routes = {
                "/api/files": self.files, "/api/rows": self.rows, "/api/search": self.search,
                "/api/ldap-search": self.ldap_search, "/api/schema": self.schema,
                "/api/audit-report": self.audit_report, "/api/status": self.viewer_status,
                "/api/detail": self.detail, "/api/resolve": self.resolve, "/api/tree": self.tree,
            }
            if path == "/":
                self.send_page("viewer.html")
            elif path == "/admin":
                self.require_admin()
                self.send_page("admin.html")
            elif path == "/api/audit-queries":
                self.send_json({"queries": AUDIT_QUERY_PRESETS})
            elif path == "/api/databases":
                self.databases()
            elif path == "/api/session":
                self.send_json({"authenticated": True, "auth_enabled": app.auth.enabled, "admin_enabled": app.admin_enabled, "library": app.library_mode})
            elif path == "/api/admin/snapshots":
                self.require_admin()
                self.admin_snapshots()
            elif path == "/api/admin/databases":
                self.require_admin()
                self.admin_databases()
            elif path in routes:
                routes[path](query)
            else:
                self.send_json({"error": "not found"}, 404)

        def do_post_authenticated(self, path: str) -> None:
            if path not in {"/api/admin/rename", "/api/admin/snapshot-convert"}:
                self.send_json({"error": "not found"}, 404)
                return
            self.require_admin()
            request = self.read_json_body()
            if path == "/api/admin/rename":
                self.admin_rename(request)
            else:
                self.admin_snapshot_convert(request)

        def do_put_authenticated(self, path: str, query: Dict[str, List[str]]) -> None:
            if path not in {"/api/admin/upload", "/api/admin/snapshot-upload"}:
                self.send_json({"error": "not found"}, 404)
                return
            self.require_admin()
            if path == "/api/admin/upload":
                self.admin_upload(query)
            else:
                self.admin_snapshot_upload(query)

        def do_delete_authenticated(self, path: str, query: Dict[str, List[str]]) -> None:
            if path not in {"/api/admin/database", "/api/admin/snapshot"}:
                self.send_json({"error": "not found"}, 404)
                return
            self.require_admin()
            if path == "/api/admin/database":
                self.admin_delete(query)
            else:
                self.admin_snapshot_delete(query)

        def require_admin(self) -> None:
            if not app.admin_enabled:
                raise AdminAuthorizationError("database administration is disabled")

        # -- request bodies ---------------------------------------------------------------

        def read_form_body(self) -> Dict[str, List[str]]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("invalid request length") from exc
            if length < 0 or length > 65536:
                raise ValueError("invalid form size")
            return parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))

        def read_json_body(self) -> Dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("invalid request length") from exc
            if length < 1 or length > 65536:
                raise ValueError("invalid JSON request size")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("invalid JSON request") from exc
            if not isinstance(value, dict):
                raise ValueError("JSON request must be an object")
            return value

        def receive_upload(self, destination_dir: Path, prefix: str) -> Path:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("invalid upload size") from exc
            if length < 16:
                raise ValueError("uploaded file is empty or incomplete")
            free = shutil.disk_usage(destination_dir).free
            if length + 64 * 1024 * 1024 > free:
                raise ValueError(f"not enough free space: upload needs {length:,} bytes and the destination has {free:,} bytes free")
            descriptor, temporary_name = tempfile.mkstemp(prefix=prefix, suffix=".part", dir=destination_dir)
            temporary = Path(temporary_name)
            try:
                remaining = length
                with os.fdopen(descriptor, "wb") as handle:
                    while remaining:
                        block = self.rfile.read(min(UPLOAD_CHUNK_BYTES, remaining))
                        if not block:
                            raise ValueError("upload connection ended before the file was complete")
                        handle.write(block)
                        remaining -= len(block)
                    handle.flush()
                    os.fsync(handle.fileno())
                return temporary
            except Exception:
                temporary.unlink(missing_ok=True)
                raise

        # -- database selection -----------------------------------------------------------

        def _database_path(self, query: Dict[str, List[str]]) -> Path:
            if not app.library_mode:
                if app.index_path is None:
                    raise ValueError("viewer database is unavailable")
                return app.index_path
            selected = app.scanner.databases().get(query.get("db", [""])[0])
            if not selected:
                raise ValueError("select an available database")
            return selected["path"]

        def _connect(self, query: Dict[str, List[str]]) -> sqlite3.Connection:
            return connect(self._database_path(query), readonly=app.library_mode)

        @staticmethod
        def _tokenizer(db: sqlite3.Connection) -> str:
            row = db.execute("SELECT sql FROM sqlite_master WHERE name='row_fts'").fetchone()
            return "trigram" if row and "trigram" in row[0].casefold() else "unicode61"

        # -- viewer API ------------------------------------------------------------------

        def databases(self) -> None:
            if not app.library_mode:
                self.send_json({"library": False, "admin_enabled": False, "databases": []})
                return
            available = app.scanner.databases()
            self.send_json({
                "library": True, "admin_enabled": app.admin_enabled,
                "databases": [{key: value for key, value in item.items() if key != "path"} for item in available.values()],
            })

        def viewer_status(self, query: Dict[str, List[str]]) -> None:
            if app.status is not None:
                self.send_json(app.status.snapshot())
                return
            rows = 0
            if app.library_mode and query.get("db"):
                with closing(self._connect(query)) as db:
                    rows = db.execute("SELECT COALESCE(SUM(row_count),0) FROM files").fetchone()[0]
            self.send_json({"state": "ready", "current_file": "", "files_done": 0, "total_files": 0, "processed_bytes": 1, "total_bytes": 1, "rows": rows, "error": ""})

        def files(self, query: Dict[str, List[str]]) -> None:
            with closing(self._connect(query)) as db:
                rows = db.execute("SELECT path,size,row_count FROM files ORDER BY path COLLATE NOCASE").fetchall()
                snapshot_available = bool(db.execute(
                    "SELECT EXISTS(SELECT 1 FROM object_tree WHERE file=?)", (SNAPSHOT_FILE_KEY,)
                ).fetchone()[0])
                audit_available = bool(db.execute(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_findings')"
                ).fetchone()[0])
                server = viewer_meta_value(db, "snapshot_server", "")
                captured = viewer_meta_value(db, "snapshot_captured_utc", "")
            label = self._database_path(query).stem if app.library_mode else (app.project.stem if app.project else "")
            self.send_json({
                "project": label, "snapshot": snapshot_available, "audit": audit_available,
                "server": server, "captured_utc": captured,
                "files": [{"path": row["path"], "size": row["size"], "rows": row["row_count"]} for row in rows],
            })

        def _file_info(self, db: sqlite3.Connection, relative: str) -> sqlite3.Row:
            row = db.execute("SELECT * FROM files WHERE path=?", (relative,)).fetchone()
            if not row:
                raise ValueError("unknown report file")
            return row

        def rows(self, query: Dict[str, List[str]]) -> None:
            relative = query.get("file", [SNAPSHOT_FILE_KEY])[0] or SNAPSHOT_FILE_KEY
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = min(MAX_PAGE_SIZE, max(1, int(query.get("page_size", ["50"])[0])))
            database_path = self._database_path(query)
            with closing(self._connect(query)) as db:
                info = self._file_info(db, relative)
                offset = (page - 1) * page_size
                headers = json.loads(info["headers_json"])
                try:
                    field_filters = json.loads(query.get("filters", ["{}"])[0])
                except json.JSONDecodeError as exc:
                    raise ValueError("invalid filters JSON") from exc
                filter_clauses, filter_parameters = build_field_filters(headers, field_filters)
                where = " AND ".join(["file=?", *filter_clauses])
                sort_value = query.get("sort_col", [""])[0]
                if sort_value != "":
                    sort_col = int(sort_value)
                    if sort_col < 0 or sort_col >= len(headers):
                        raise ValueError("invalid sort column")
                    direction = "DESC" if query.get("sort_dir", ["asc"])[0].casefold() == "desc" else "ASC"
                    order = f"json_extract(row_json, '$[{sort_col}]') COLLATE NOCASE {direction}, row_number"
                    self._ensure_sort_index(db, database_path, sort_col)
                else:
                    order = "row_number"
                if filter_clauses:
                    total = db.execute(f"SELECT COUNT(*) FROM rows WHERE {where}", [relative, *filter_parameters]).fetchone()[0]
                else:
                    total = info["row_count"]
                found = db.execute(
                    f"SELECT row_number,row_json FROM rows WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                    [relative, *filter_parameters, page_size, offset],
                ).fetchall()
            values = [{"row_number": row["row_number"], "values": json.loads(row["row_json"])} for row in found]
            self.send_json({
                "headers": headers, "rows": values, "total": total, "source_total": info["row_count"],
                "start": offset + 1 if values else 0, "end": offset + len(values),
            })

        def _ensure_sort_index(self, db: sqlite3.Connection, database_path: Path, sort_col: int) -> None:
            """Create the sort index; library databases are opened read-only so use a short writer."""
            if not app.library_mode:
                ensure_sort_index(db, sort_col)
                return
            with app.admin_lock:
                try:
                    with closing(connect(database_path)) as writer:
                        ensure_sort_index(writer, sort_col)
                except sqlite3.Error:
                    pass

        def search(self, query: Dict[str, List[str]]) -> None:
            text = query.get("q", [""])[0].strip()
            limit = min(1000, max(1, int(query.get("limit", ["250"])[0])))
            offset = max(0, int(query.get("offset", ["0"])[0]))
            if not text:
                raise ValueError("empty search")
            with closing(self._connect(query)) as db:
                info = self._file_info(db, SNAPSHOT_FILE_KEY)
                uses_fts = self._tokenizer(db) == "trigram" and len(text) >= 3
                if uses_fts:
                    sql = (
                        "SELECT rows.row_number,rows.row_json,rows.detail_blob FROM row_fts "
                        "JOIN rows ON rows.id=row_fts.rowid WHERE row_fts MATCH ? AND rows.file=? "
                        "ORDER BY row_fts.rowid LIMIT ? OFFSET ?"
                    )
                    parameters: List[Any] = ['"' + text.replace('"', '""') + '"', SNAPSHOT_FILE_KEY, limit + 1, offset]
                else:
                    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    sql = (
                        "SELECT row_number,row_json,detail_blob FROM rows WHERE file=? AND search_text LIKE ? ESCAPE '\\' "
                        "ORDER BY row_number LIMIT ? OFFSET ?"
                    )
                    parameters = [SNAPSHOT_FILE_KEY, f"%{escaped}%", limit + 1, offset]
                found = db.execute(sql, parameters).fetchall()
            more = len(found) > limit
            found = found[:limit]
            headers = [*json.loads(info["headers_json"]), "matching_attributes"]
            needle = text.casefold()
            results = []
            for row in found:
                detail = decode_indexed_detail(row)
                matches = []
                for name, value in detail.items():
                    rendered = display_value(value)
                    if needle in name.casefold() or needle in rendered.casefold():
                        matches.append(f"{name}: {rendered[:1500]}")
                        if len(matches) >= 20:
                            break
                results.append({"row_number": row["row_number"], "values": [*json.loads(row["row_json"]), "\n".join(matches)]})
            self.send_json({"headers": headers, "results": results, "count": len(results), "more": more})

        def detail(self, query: Dict[str, List[str]]) -> None:
            row_number = int(query.get("row", ["0"])[0])
            if row_number < 1:
                raise ValueError("invalid object row")
            with closing(self._connect(query)) as db:
                row = db.execute(
                    "SELECT detail_blob FROM rows WHERE file=? AND row_number=?", (SNAPSHOT_FILE_KEY, row_number),
                ).fetchone()
            if not row or row["detail_blob"] is None:
                raise ValueError("snapshot object is not indexed yet")
            detail = decode_indexed_detail(row)
            attributes = []
            for name, value in sorted(detail.items(), key=lambda item: item[0].casefold()):
                structured = isinstance(value, (dict, list))
                if isinstance(value, dict):
                    summary = f"Parsed object • {len(value)} fields"
                elif isinstance(value, list):
                    summary = f"Parsed list • {len(value)} values"
                else:
                    summary = ""
                attributes.append({
                    "attribute": name,
                    "value": json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, default=json_default) if structured else display_value(value),
                    "structured": structured, "summary": summary,
                })
            self.send_json({
                "row_number": row_number,
                "distinguished_name": display_value(ci_value(detail, "distinguishedName")),
                "attributes": attributes,
            })

        def resolve(self, query: Dict[str, List[str]]) -> None:
            """Resolve a DN, SID, sAMAccountName, GUID or UPN to an object row."""
            key_type = query.get("type", ["dn"])[0].strip().casefold()
            value = query.get("value", [""])[0].strip()
            if not value:
                raise ValueError("missing reference value")
            with closing(self._connect(query)) as db:
                if key_type == "dn":
                    row = db.execute(
                        "SELECT row_number,dn FROM object_tree WHERE file=? AND dn_norm=? AND row_number>0",
                        (SNAPSHOT_FILE_KEY, normalize_dn(value)),
                    ).fetchone()
                    if row:
                        self.send_json({"row_number": row["row_number"], "dn": row["dn"], "matches": 1})
                        return
                elif key_type in {"sid", "sam", "guid", "upn"}:
                    hits = db.execute(
                        "SELECT row_number FROM object_lookup WHERE key_type=? AND key_norm=? LIMIT 2",
                        (key_type, value.casefold()),
                    ).fetchall()
                    if hits:
                        self.send_json({"row_number": hits[0]["row_number"], "matches": len(hits)})
                        return
                else:
                    raise ValueError("invalid reference type")
            self.send_json({"row_number": 0, "matches": 0})

        def schema(self, query: Dict[str, List[str]]) -> None:
            with closing(self._connect(query)) as db:
                rows = db.execute(
                    "SELECT attribute,ads_type,syntax FROM snapshot_properties WHERE file=? ORDER BY attribute COLLATE NOCASE",
                    (SNAPSHOT_FILE_KEY,),
                ).fetchall()
            self.send_json({"attributes": [dict(row) for row in rows]})

        def audit_report(self, query: Dict[str, List[str]]) -> None:
            """Return a precomputed audit table with rows resolved to snapshot objects."""
            name = query.get("name", [""])[0].strip().casefold()
            table = COMPUTED_REPORTS.get(name)
            if not table:
                raise ValueError("invalid audit report")
            with closing(self._connect(query)) as db:
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                if not exists:
                    self.send_json({"available": False, "headers": [], "rows": [], "total": 0})
                    return
                columns = [row[1] for row in db.execute(f"PRAGMA table_info({table})")]
                total = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                fetched = db.execute(f"SELECT {','.join(columns)} FROM {table} LIMIT 5000").fetchall()
                dn_index = columns.index("distinguished_name") if "distinguished_name" in columns else -1
                results = []
                dn_cache: Dict[str, int] = {}
                for row in fetched:
                    values = [row[column] for column in columns]
                    row_number = 0
                    if dn_index >= 0 and values[dn_index]:
                        key = normalize_dn(str(values[dn_index]))
                        if key not in dn_cache:
                            hit = db.execute(
                                "SELECT row_number FROM object_tree WHERE file=? AND dn_norm=? AND row_number>0",
                                (SNAPSHOT_FILE_KEY, key),
                            ).fetchone()
                            dn_cache[key] = hit["row_number"] if hit else 0
                        row_number = dn_cache[key]
                    results.append({"row_number": row_number, "values": values})
            self.send_json({"available": True, "headers": columns, "rows": results, "total": total, "more": total > len(results)})

        def ldap_search(self, query: Dict[str, List[str]]) -> None:
            filter_text = normalize_viewer_ldap_filter(query.get("filter", [""])[0].strip())
            limit = min(1000, max(1, int(query.get("limit", ["250"])[0])))
            offset = max(0, int(query.get("offset", ["0"])[0]))
            if not filter_text:
                raise ValueError("empty LDAP filter")
            try:
                filter_node = parse_filter(filter_text)
            except FilterSyntaxError as exc:
                raise ValueError(f"invalid LDAP filter: {exc}") from exc
            preset_value = query.get("preset", [""])[0]
            preset: Optional[Dict[str, Any]] = None
            if preset_value != "":
                try:
                    preset = AUDIT_QUERY_PRESETS[int(preset_value)]
                except (ValueError, IndexError) as exc:
                    raise ValueError("invalid audit query preset") from exc
            started = time.monotonic()
            matched: List[Dict[str, Any]] = []
            skipped = 0
            scanned = 0
            requested = [name.strip() for name in query.get("attributes", [""])[0].split(",") if name.strip()]
            with closing(self._connect(query)) as db:
                info = self._file_info(db, SNAPSHOT_FILE_KEY)
                summary_headers = json.loads(info["headers_json"])
                if preset:
                    output_headers = list(preset["attributes"])
                    known = {name.casefold() for name in output_headers}
                    output_headers += [name for name in requested if name.casefold() not in known and not known.add(name.casefold())]
                    extra_attributes = output_headers
                else:
                    known = {name.casefold() for name in summary_headers}
                    extra_attributes = [
                        name for name in [*filter_attributes(filter_node), *requested]
                        if name.casefold() not in known and not known.add(name.casefold())
                    ]
                    output_headers = [*summary_headers, *extra_attributes]
                prefilter = preset.get("prefilter") if preset else None
                property_types = {
                    row["attribute"].casefold(): row["ads_type"]
                    for row in db.execute("SELECT attribute,ads_type FROM snapshot_properties WHERE file=?", (SNAPSHOT_FILE_KEY,))
                }
                candidate_query = ldap_fts_candidate_query(filter_node, property_types) if self._tokenizer(db) == "trigram" else None
                where = "rows.file=?" + (f" AND ({prefilter})" if prefilter else "")
                parameters: List[Any] = []
                if candidate_query:
                    sql = (
                        "SELECT rows.row_number,rows.row_json,rows.detail_blob FROM row_fts JOIN rows ON rows.id=row_fts.rowid "
                        f"WHERE row_fts MATCH ? AND {where} ORDER BY row_fts.rowid"
                    )
                    parameters.append(candidate_query)
                else:
                    sql = f"SELECT row_number,row_json,detail_blob FROM rows WHERE {where} ORDER BY row_number"
                parameters.append(SNAPSHOT_FILE_KEY)
                summary_only = can_evaluate_from_summary(filter_node, summary_headers)
                for row in db.execute(sql, parameters):
                    scanned += 1
                    detail: Optional[Dict[str, Any]] = None
                    if summary_only:
                        evaluation_detail = summary_filter_detail(summary_headers, row["row_json"])
                    else:
                        detail = evaluation_detail = decode_indexed_detail(row)
                    if not evaluate_node(filter_node, evaluation_detail):
                        continue
                    if skipped < offset:
                        skipped += 1
                        continue
                    if extra_attributes and detail is None:
                        detail = decode_indexed_detail(row)
                    detail = detail or evaluation_detail
                    extra_values = [display_value(indexed_attribute_value(detail, name)) for name in extra_attributes]
                    matched.append({
                        "row_number": row["row_number"],
                        "values": extra_values if preset else [*json.loads(row["row_json"]), *extra_values],
                    })
                    if len(matched) > limit:
                        break
            self.send_json({
                "headers": output_headers, "results": matched[:limit], "count": min(len(matched), limit),
                "more": len(matched) > limit, "scanned": scanned,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            })

        def tree(self, query: Dict[str, List[str]]) -> None:
            parent = query.get("parent", [None])[0]
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = min(1000, max(1, int(query.get("limit", ["500"])[0])))
            with closing(self._connect(query)) as db:
                root_count = db.execute(
                    "SELECT COUNT(*) FROM object_tree WHERE file=? AND is_nc_root=1", (SNAPSHOT_FILE_KEY,),
                ).fetchone()[0]
                if parent is None:
                    condition = "t.file=? AND t.is_nc_root=1" if root_count else (
                        "t.file=? AND (t.parent_norm='' OR NOT EXISTS "
                        "(SELECT 1 FROM object_tree p WHERE p.file=t.file AND p.dn_norm=t.parent_norm))"
                    )
                    parameters: List[Any] = [SNAPSHOT_FILE_KEY]
                else:
                    condition = "t.file=? AND t.parent_norm=?" + (" AND t.is_nc_root=0" if root_count else "")
                    parameters = [SNAPSHOT_FILE_KEY, normalize_dn(parent)]
                child_root_clause = " AND c.is_nc_root=0" if root_count else ""
                root_order = (
                    "CASE WHEN lower(t.dn) LIKE 'dc=domaindnszones,%' THEN 3 "
                    "WHEN lower(t.dn) LIKE 'dc=forestdnszones,%' THEN 4 "
                    "WHEN lower(t.dn) LIKE 'cn=configuration,%' THEN 1 "
                    "WHEN lower(t.dn) LIKE 'cn=schema,%' THEN 2 ELSE 0 END,"
                    if parent is None and root_count else ""
                )
                found = db.execute(
                    "SELECT t.row_number,t.dn,t.dn_norm,t.label,t.object_type,t.is_nc_root, "
                    f"EXISTS(SELECT 1 FROM object_tree c WHERE c.file=t.file AND c.parent_norm=t.dn_norm{child_root_clause}) has_children "
                    f"FROM object_tree t WHERE {condition} "
                    f"ORDER BY {root_order}t.label COLLATE NOCASE,t.dn COLLATE NOCASE LIMIT ? OFFSET ?",
                    [*parameters, limit + 1, offset],
                ).fetchall()
            more = len(found) > limit
            nodes = [{
                "row_number": row["row_number"], "dn": row["dn"], "dn_norm": row["dn_norm"],
                "label": row["label"], "object_type": row["object_type"],
                "is_nc_root": bool(row["is_nc_root"]), "has_children": bool(row["has_children"]),
            } for row in found[:limit]]
            self.send_json({"nodes": nodes, "offset": offset, "more": more})

        # -- administration ----------------------------------------------------------------

        def admin_snapshots(self) -> None:
            snapshots = app.scanner.snapshots()
            with app.admin_lock:
                jobs = [app.public_job(job) for job in app.conversion_jobs.values()]
            self.send_json({
                "enabled": app.snapshot_library is not None,
                "directory": str(app.snapshot_library) if app.snapshot_library else "",
                "snapshots": [{key: value for key, value in item.items() if key != "path"} for item in snapshots.values()],
                "jobs": jobs,
            })

        def admin_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
            if app.snapshot_library is None:
                raise ValueError("snapshot administration is unavailable")
            selected = app.scanner.snapshots().get(snapshot_id)
            if not selected:
                raise ValueError("snapshot no longer exists")
            selected["path"] = confined_file(selected["path"], app.snapshot_library, "snapshot")
            return selected

        def admin_snapshot_upload(self, query: Dict[str, List[str]]) -> None:
            if app.snapshot_library is None:
                raise ValueError("snapshot uploads require --snapshot-dir")
            filename = query.get("filename", [""])[0].strip()
            if not filename or Path(filename).name != filename:
                raise ValueError("a valid source filename is required")
            if Path(filename).suffix.casefold() != ".dat":
                raise ValueError("upload an AD Explorer .dat snapshot")
            name = validate_database_name(query.get("name", [""])[0] or Path(filename).stem)
            target = snapshot_upload_path(app.snapshot_library, name)
            if target.exists():
                raise ValueError(f'snapshot "{name}" already exists')
            temporary = self.receive_upload(app.snapshot_library, ".adexview-snapshot-upload-")
            try:
                details = validate_snapshot_file(temporary)
                with app.admin_lock:
                    if target.exists():
                        raise ValueError(f'snapshot "{name}" already exists')
                    os.replace(temporary, target)
                relative = target.relative_to(app.snapshot_library).as_posix()
                stat = target.stat()
                self.send_json({
                    "snapshot": {"id": opaque_id(relative), "name": name, "relative_path": relative, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns},
                    "details": details,
                }, 201)
            finally:
                temporary.unlink(missing_ok=True)

        def admin_snapshot_convert(self, request: Dict[str, Any]) -> None:
            if not app.library_mode:
                raise ValueError("snapshot conversion requires library mode")
            snapshot_id = str(request.get("id", ""))
            selected = self.admin_snapshot(snapshot_id)
            include_audit = request.get("audit", True)
            if not isinstance(include_audit, bool):
                raise ValueError("audit must be true or false")
            name = validate_database_name(str(request.get("name", "")) or selected["name"])
            with app.admin_lock:
                active = next((job for job in app.conversion_jobs.values() if job["state"] in {"queued", "running"}), None)
                if active:
                    raise ValueError(f'conversion already running for "{active["snapshot_name"]}"')
                self.unique_database_name(name, app.scanner.databases(force=True, include_invalid=True))
                job_id = secrets.token_urlsafe(12)
                app.conversion_jobs[job_id] = {
                    "id": job_id, "snapshot_id": snapshot_id, "snapshot_name": selected["name"],
                    "database_name": name, "audit": include_audit, "state": "queued",
                    "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": "",
                    "status": IndexStatus(),
                }
                app.reserved_names.add(name.casefold())
            threading.Thread(
                target=app.convert_snapshot, args=(job_id, selected["path"], name, include_audit), daemon=True,
            ).start()
            self.send_json({"job": app.public_job(app.conversion_jobs[job_id])}, 202)

        def admin_snapshot_delete(self, query: Dict[str, List[str]]) -> None:
            selected = self.admin_snapshot(query.get("id", [""])[0])
            with app.admin_lock:
                active = next((
                    job for job in app.conversion_jobs.values()
                    if job["snapshot_id"] == selected["id"] and job["state"] in {"queued", "running"}
                ), None)
                if active:
                    raise ValueError("cannot delete a snapshot while it is converting")
                snapshot_path = selected["path"]
                snapshot_path.unlink()
                if app.snapshot_library and snapshot_path.parent != app.snapshot_library:
                    try:
                        snapshot_path.parent.rmdir()
                    except OSError:
                        pass
            self.send_json({"deleted": selected["name"], "relative_path": selected["relative_path"]})

        def admin_database(self, database_id: str) -> Dict[str, Any]:
            if not app.library_mode:
                raise ValueError("database administration requires library mode")
            selected = app.scanner.databases(force=True, include_invalid=True).get(database_id)
            if not selected:
                raise ValueError("database file no longer exists")
            selected["path"] = confined_file(selected["path"], app.library, "database")
            return selected

        def admin_databases(self) -> None:
            available = app.scanner.databases(force=True, include_invalid=True)
            self.send_json({
                "library": True, "admin_enabled": True,
                "databases": [{key: value for key, value in item.items() if key != "path"} for item in available.values()],
            })

        def unique_database_name(self, name: str, available: Dict[str, Dict[str, Any]], except_id: Optional[str] = None) -> None:
            conflict = next((item for item in available.values() if item["id"] != except_id and item["name"].casefold() == name.casefold()), None)
            if conflict:
                raise ValueError(f'database name "{name}" is already in use')
            if name.casefold() in app.reserved_names:
                raise ValueError(f'database name "{name}" is reserved by a conversion')

        def admin_upload(self, query: Dict[str, List[str]]) -> None:
            library = app.library
            if library is None:
                raise ValueError("database uploads require library mode")
            filename = query.get("filename", [""])[0].strip()
            if not filename or Path(filename).name != filename:
                raise ValueError("a valid source filename is required")
            if Path(filename).suffix.casefold() not in DATABASE_SUFFIXES:
                raise ValueError("upload a .sqlite3, .sqlite, or .db file")
            name = validate_database_name(query.get("name", [""])[0] or database_display_name(filename))
            self.unique_database_name(name, app.scanner.databases(force=True, include_invalid=True))
            temporary = self.receive_upload(library, ".adexview-upload-")
            try:
                details = validate_viewer_database(temporary)
                with app.admin_lock:
                    self.unique_database_name(name, app.scanner.databases(force=True, include_invalid=True))
                    target_directory = library / name
                    target = target_directory / f"{name}.sqlite3"
                    if target.exists():
                        raise ValueError(f'database file for "{name}" already exists')
                    target_directory.mkdir(parents=False, exist_ok=True)
                    confined_file(target_directory, library, "database")
                    os.replace(temporary, target)
                    relative = target.relative_to(library).as_posix()
                    registry = load_library_registry(library)
                    registry[relative] = name
                    try:
                        save_library_registry(library, registry)
                    except Exception:
                        target.unlink(missing_ok=True)
                        try:
                            target_directory.rmdir()
                        except OSError:
                            pass
                        raise
                    uploaded = next(item for item in app.scanner.databases(force=True, include_invalid=True).values() if item["relative_path"] == relative)
                self.send_json({
                    "database": {key: value for key, value in uploaded.items() if key != "path"},
                    "validated_rows": details["rows"],
                }, 201)
            finally:
                temporary.unlink(missing_ok=True)

        def admin_rename(self, request: Dict[str, Any]) -> None:
            library = app.library
            if library is None:
                raise ValueError("database rename requires library mode")
            database_id = str(request.get("id", ""))
            name = validate_database_name(str(request.get("name", "")))
            with app.admin_lock:
                selected = self.admin_database(database_id)
                if not selected["valid"]:
                    raise ValueError("only viewer databases can be renamed")
                self.unique_database_name(name, app.scanner.databases(force=True, include_invalid=True), except_id=database_id)
                registry = load_library_registry(library)
                registry[selected["relative_path"]] = name
                save_library_registry(library, registry)
                renamed = app.scanner.databases(force=True, include_invalid=True)[database_id]
            self.send_json({"database": {key: value for key, value in renamed.items() if key != "path"}})

        def admin_delete(self, query: Dict[str, List[str]]) -> None:
            library = app.library
            if library is None:
                raise ValueError("database deletion requires library mode")
            with app.admin_lock:
                selected = self.admin_database(query.get("id", [""])[0])
                database_path = selected["path"]
                delete_paths = [database_path] + [
                    confined_file(sidecar, library, "database")
                    for suffix in ("-wal", "-shm", "-journal")
                    if (sidecar := Path(str(database_path) + suffix)).exists()
                ]
                for delete_path in reversed(delete_paths):
                    delete_path.unlink()
                registry = load_library_registry(library)
                registry.pop(selected["relative_path"], None)
                save_library_registry(library, registry)
                try:
                    database_path.parent.rmdir()
                except OSError:
                    pass
                app.scanner.databases(force=True)
            self.send_json({"deleted": selected["name"], "relative_path": selected["relative_path"]})

    return Handler
