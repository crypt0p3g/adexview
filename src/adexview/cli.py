"""Command-line entry points: ``adexview view``, ``adexview audit``, ``adexview query``."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from contextlib import closing
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from . import __version__
from .auth import AuthManager, generate_password
from .decoders import DEFAULT_TIMEZONE
from .index import (
    IndexStatus, connect, index_snapshot, initialize, project_index_path,
    project_snapshot_path, snapshot_index_path,
)
from .server import ViewerApp, build_tls_context, create_server, is_loopback_host, make_handler

PASSWORD_ENV = "ADEXVIEW_PASSWORD"


def view_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("source", nargs="?", help="Audit project directory or AD Explorer .dat snapshot")
    parser.add_argument("--library", metavar="DIRECTORY", help="Serve every viewer database below this directory, with live discovery.")
    parser.add_argument("--snapshot-dir", metavar="DIRECTORY", help="Directory for uploaded .dat snapshots in library mode (default: snapshots/ beside the library).")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: local machine only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open-browser", action="store_true", help="Open the viewer in the default browser once it is serving")
    parser.add_argument("--no-browser", action="store_true", help=argparse.SUPPRESS)  # former default; kept for old scripts
    parser.add_argument("--access-log", action="store_true", help="Print HTTP requests (off by default)")
    auth = parser.add_argument_group("authentication")
    auth.add_argument("--password", help=f"Viewer login password (default: generated and printed; also read from ${PASSWORD_ENV})")
    auth.add_argument("--password-file", metavar="PATH", help="Read the viewer login password from a file")
    auth.add_argument("--no-auth", action="store_true", help="Disable the login page (only allowed when bound to a loopback address)")
    auth.add_argument("--session-hours", type=float, default=12, help="Idle session lifetime (default: 12)")
    auth.add_argument("--allowed-host", action="append", default=[], metavar="HOST", help="Additional Host header values accepted on a loopback bind")
    parser.add_argument("--no-admin", action="store_true", help="Disable upload, convert, rename, and delete in library mode")
    tls = parser.add_argument_group("HTTPS")
    tls.add_argument("--tls-cert", "--certfile", dest="tls_cert", metavar="PATH", help="PEM certificate (or certificate chain)")
    tls.add_argument("--tls-key", "--keyfile", dest="tls_key", metavar="PATH", help="PEM private key")
    parser.add_argument("--reindex", action="store_true", help="Rebuild the search index")
    parser.add_argument("--index-only", action="store_true", help="Update the index and exit")
    parser.add_argument("--database", dest="database", help="SQLite database path override")
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE, help=f"Snapshot date timezone (default: {DEFAULT_TIMEZONE})")
    return parser


def resolve_password(args: argparse.Namespace) -> Tuple[Optional[str], bool]:
    """Return (password, generated) honouring --no-auth, flags, file and environment."""
    if args.no_auth:
        if not is_loopback_host(args.host):
            raise ValueError("--no-auth is only allowed together with a loopback --host such as 127.0.0.1")
        return None, False
    if args.password:
        return args.password, False
    if args.password_file:
        return Path(args.password_file).expanduser().read_text(encoding="utf-8").strip(), False
    if os.environ.get(PASSWORD_ENV):
        return os.environ[PASSWORD_ENV], False
    return generate_password(), True


def _print_banner(url: str, password: Optional[str], generated: bool, admin_url: Optional[str]) -> None:
    print(f"Viewer: {url}")
    if password is None:
        print("Login: disabled (--no-auth)")
    elif generated:
        print(f"Login password (generated for this run): {password}")
        print(f"  Set --password, --password-file or ${PASSWORD_ENV} for a stable one.")
    else:
        print("Login: password configured")
    if admin_url:
        print(f"Database admin: {admin_url}")
    print("Press Ctrl-C to stop.")


def view_main(args: argparse.Namespace) -> int:
    try:
        tls_context = build_tls_context(args.tls_cert, args.tls_key)
        password, generated = resolve_password(args)
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    scheme = "https" if tls_context is not None else "http"
    auth = AuthManager(password, secure_cookie=tls_context is not None, session_hours=args.session_hours)

    if args.library:
        if args.source:
            print("Use either SOURCE or --library DIRECTORY, not both.", file=sys.stderr)
            return 2
        library = Path(args.library).expanduser().resolve()
        if not library.is_dir():
            print(f"Database library directory not found: {library}", file=sys.stderr)
            return 2
        snapshot_library = Path(args.snapshot_dir).expanduser().resolve() if args.snapshot_dir else library.parent / "snapshots"
        try:
            snapshot_library.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"Cannot create snapshot directory {snapshot_library}: {exc}", file=sys.stderr)
            return 2
        if args.reindex or args.index_only or args.database:
            print("--reindex, --index-only, and --database are unavailable with --library.", file=sys.stderr)
            return 2
        app = ViewerApp(
            auth=auth, library=library, snapshot_library=snapshot_library, admin_enabled=not args.no_admin,
            access_log=args.access_log, conversion_timezone=args.timezone, bind_host=args.host,
            allowed_hosts=args.allowed_host,
        )
        server = create_server(args.host, args.port, make_handler(app), tls_context)
        url = f"{scheme}://{args.host}:{server.server_port}/"
        print(f"Watching for .sqlite3, .sqlite, and .db files in: {library}")
        print(f"Snapshot uploads: {snapshot_library}")
        _print_banner(url, password, generated, f"{url}admin" if not args.no_admin else None)
        return _serve(server, url, args.open_browser)

    if not args.source:
        print("SOURCE or --library DIRECTORY is required.", file=sys.stderr)
        return 2
    if args.snapshot_dir:
        print("--snapshot-dir is available only with --library.", file=sys.stderr)
        return 2
    source = Path(args.source).expanduser().resolve()
    snapshot_mode = source.is_file() and source.suffix.casefold() == ".dat"
    if not snapshot_mode and not source.is_dir():
        print(f"Audit project or .dat snapshot not found: {source}", file=sys.stderr)
        return 2
    if args.database:
        index_path = Path(args.database).expanduser().resolve()
    elif snapshot_mode:
        index_path = snapshot_index_path(source)
    else:
        index_path = project_index_path(source)
    if args.reindex and index_path.exists():
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(index_path) + suffix)
            if candidate.exists():
                candidate.unlink()
    with closing(connect(index_path)) as db:
        initialize(db)

    def build_index(db, status: IndexStatus) -> Tuple[int, int]:
        if snapshot_mode:
            return index_snapshot(source, db, args.timezone, status)
        embedded_snapshot = project_snapshot_path(source)
        if embedded_snapshot:
            return index_snapshot(embedded_snapshot, db, args.timezone, status)
        total_rows = db.execute("SELECT COALESCE(SUM(row_count),0) FROM files").fetchone()[0]
        if not total_rows:
            raise ValueError(
                f"{source} has no indexed snapshot and its metadata.json does not point to a readable .dat file"
            )
        return 0, total_rows

    def ready_message(changed: int, total_rows: int) -> str:
        return f"Index ready: {total_rows:,} objects ({'rebuilt' if changed else 'unchanged'})."

    if args.index_only:
        status = IndexStatus()
        with closing(connect(index_path)) as db:
            changed, total_rows = build_index(db, status)
        print(ready_message(changed, total_rows))
        return 0

    status = IndexStatus()

    def update_index() -> None:
        try:
            with closing(connect(index_path)) as worker_db:
                changed, total_rows = build_index(worker_db, status)
            print(ready_message(changed, total_rows))
        except Exception as exc:
            status.update(state="error", error=str(exc))
            print(f"Indexing failed: {exc}", file=sys.stderr)

    app = ViewerApp(
        auth=auth, project=source, index_path=index_path, status=status, access_log=args.access_log,
        bind_host=args.host, allowed_hosts=args.allowed_host,
    )
    server = create_server(args.host, args.port, make_handler(app), tls_context)
    url = f"{scheme}://{args.host}:{server.server_port}/"
    _print_banner(url, password, generated, None)
    print("The UI opens immediately; indexing continues in the background.")
    threading.Thread(target=update_index, daemon=True).start()
    return _serve(server, url, args.open_browser)


def _serve(server, url: str, open_browser: bool) -> int:
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="adexview", description="Offline AD Explorer snapshot viewer, audit, and query tools.")
    parser.add_argument("--version", action="version", version=f"adexview {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    view_parser(subparsers.add_parser("view", help="Serve the browser viewer"))
    subparsers.add_parser("audit", help="Run the offline security audit", add_help=False)
    subparsers.add_parser("query", help="Evaluate an LDAP filter against a snapshot", add_help=False)
    if not argv or argv[0] not in {"view", "audit", "query", "--version", "-h", "--help"}:
        parser.print_help(sys.stderr)
        return 2
    command = argv[0]
    if command == "audit":
        from .audit import main as audit_main

        return audit_main(argv[1:])
    if command == "query":
        from .querycli import main as query_main

        return query_main(argv[1:])
    args = parser.parse_args(argv)
    return view_main(args)
