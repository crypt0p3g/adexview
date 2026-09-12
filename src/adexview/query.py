# Origin: takito1812/adx-query (MIT), Copyright (c) 2025 Víctor García.
# See LICENSE and NOTICE.md.
"""Streaming evaluation of LDAP filters against snapshot entries."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .ldapfilter import EvaluationContext, FilterNode
from .snapshot import SnapshotEntry, SnapshotReader


@dataclass
class QueryStats:
    entries_evaluated: int = 0
    matches: int = 0
    duration_seconds: float = 0.0


class QueryEngine:
    def __init__(
        self,
        reader: SnapshotReader,
        filter_node: FilterNode,
        ignore_case: bool = False,
        attributes: Optional[Sequence[str]] = None,
        limit: Optional[int] = None,
        decode: bool = True,
        timezone_name: str = "Asia/Tokyo",
    ):
        self.reader = reader
        self.filter_node = filter_node
        self.ignore_case = ignore_case
        self.limit = limit
        self.decode = decode
        self.timezone_name = timezone_name
        self._selected_attributes, self._unknown_attributes = self._normalise_attributes(attributes)
        self.stats = QueryStats()

    @property
    def selected_attributes(self) -> Optional[Sequence[str]]:
        return self._selected_attributes

    @property
    def unknown_attributes(self) -> Sequence[str]:
        return self._unknown_attributes

    def search(self) -> Iterator[SnapshotEntry]:
        start = time.perf_counter()
        matches = 0
        evaluated = 0
        node = self.filter_node
        reader = self.reader
        ignore_case = self.ignore_case
        for entry in reader.iter_entries():
            evaluated += 1
            if node.evaluate(EvaluationContext(reader=reader, entry=entry, ignore_case=ignore_case)):
                matches += 1
                yield entry
                if self.limit is not None and matches >= self.limit:
                    break
        self.stats = QueryStats(
            entries_evaluated=evaluated, matches=matches,
            duration_seconds=time.perf_counter() - start,
        )

    def materialise(self, entry: SnapshotEntry) -> Dict[str, object]:
        return entry.to_dict(
            self._selected_attributes, decode=self.decode, timezone_name=self.timezone_name,
        )

    def _normalise_attributes(
        self, attributes: Optional[Sequence[str]]
    ) -> Tuple[Optional[List[str]], List[str]]:
        if not attributes:
            return None, []
        selected: List[str] = []
        unknown: List[str] = []
        for attr in attributes:
            attr = attr.strip()
            if not attr:
                continue
            prop = self.reader.get_property(attr)
            if prop is None:
                unknown.append(attr)
            else:
                selected.append(prop.name)
        return (selected or None), unknown
