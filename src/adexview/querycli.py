# Origin: takito1812/adx-query (MIT), Copyright (c) 2025 Víctor García.
# Included in this extended edition; see LICENSE and NOTICE.md.
"""Command line interface for querying AD Explorer snapshot files."""

from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Sequence

from .decoders import DEFAULT_TIMEZONE, format_datetime
from .formatters import write_csv, write_excel, write_json, write_table
from .ldapfilter import FilterSyntaxError, parse_filter
from .query import QueryEngine
from .snapshot import SnapshotFormatError, SnapshotReader


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="adexview query",
        description="Execute LDAP filters directly against AD Explorer .dat snapshots",
    )
    parser.add_argument("--snapshot", required=True, help="Path to the AD Explorer .dat snapshot file")
    parser.add_argument("--filter", dest="ldap_filter", required=True, help='LDAP filter to evaluate (e.g. "(objectClass=user)")')
    parser.add_argument("--attributes", nargs="+", help="Attributes to return (space or comma separated).")
    parser.add_argument("--format", choices=("json", "csv", "table", "excel"), default="table", help="Output format (defaults to table).")
    parser.add_argument("--limit", type=int, help="Maximum number of results to return.")
    parser.add_argument("--ignore-case", action="store_true", help="Perform case-insensitive comparisons.")
    parser.add_argument("--benchmark", action="store_true", help="Print performance statistics after the query.")
    parser.add_argument("--dump-header", action="store_true", help="Display snapshot metadata before running the query.")
    parser.add_argument("--output", help="Write results to the specified output file.")
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE, help=f"IANA timezone used for dates (default: {DEFAULT_TIMEZONE}).")
    parser.add_argument("--raw-values", action="store_true", help="Do not decode dates, flags, GUIDs, SIDs, DNS, DFS, certificates, or ACLs.")
    return parser.parse_args(argv)


def _expand_attributes(values: Optional[Sequence[str]]) -> Optional[List[str]]:
    if not values:
        return None
    attrs: List[str] = []
    for item in values:
        for part in item.split(","):
            part = part.strip()
            if part:
                attrs.append(part)
    return attrs or None


@contextmanager
def _maybe_open_output(path: Optional[str]):
    if not path:
        yield sys.stdout
        return
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        yield fh


def _print_header(reader: SnapshotReader, timezone_name: str) -> None:
    header = reader.header
    print(f"File:         {reader.path}")
    print(f"Server:       {header.server or 'N/A'}")
    print(f"Description:  {header.description or 'N/A'}")
    print(f"Captured:     {format_datetime(header.captured_at, timezone_name)}")
    print(f"Objects:      {header.num_objects}")
    print(f"Attributes:   {header.num_attributes}")
    print(f"Size:         {header.file_size / (1024 * 1024):.2f} MB")
    print("-")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)
    attributes = _expand_attributes(args.attributes)
    try:
        filter_node = parse_filter(args.ldap_filter)
    except FilterSyntaxError as exc:
        print(f"Filter syntax error: {exc}", file=sys.stderr)
        return 1
    try:
        reader = SnapshotReader(args.snapshot)
    except (OSError, SnapshotFormatError) as exc:
        print(f"Cannot open snapshot: {exc}", file=sys.stderr)
        return 1
    with reader:
        if args.dump_header:
            _print_header(reader, args.timezone)
        engine = QueryEngine(
            reader, filter_node, ignore_case=args.ignore_case, attributes=attributes,
            limit=args.limit, decode=not args.raw_values, timezone_name=args.timezone,
        )
        if engine.unknown_attributes:
            print(f"Warning: the following attributes do not exist in the snapshot: {', '.join(engine.unknown_attributes)}", file=sys.stderr)
        if args.format == "excel":
            if not args.output:
                print("Excel output requires --output pointing to an .xlsx file.", file=sys.stderr)
                return 1
            rows = [engine.materialise(entry) for entry in engine.search()]
            write_excel(rows, args.output, fieldnames=engine.selected_attributes)
        else:
            results = (engine.materialise(entry) for entry in engine.search())
            with _maybe_open_output(args.output) as output_stream:
                if args.format == "json":
                    write_json(results, output_stream)
                elif args.format == "csv":
                    write_csv(results, output_stream, fieldnames=engine.selected_attributes)
                else:
                    table_rows = list(results)
                    if table_rows:
                        write_table(table_rows, output_stream, field_order=engine.selected_attributes)
        if args.benchmark:
            stats = engine.stats
            print("\nBenchmark:", file=sys.stderr)
            print(f"  Entries evaluated: {stats.entries_evaluated}", file=sys.stderr)
            print(f"  Matches:            {stats.matches}", file=sys.stderr)
            print(f"  Total time:         {stats.duration_seconds:.3f}s", file=sys.stderr)
    return 0
