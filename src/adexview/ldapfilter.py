# Derived from takito1812/adx-query (MIT), Copyright (c) 2025 Víctor García.
# See LICENSE and NOTICE.md.
"""LDAP filter parser and evaluator tailored for AD Explorer snapshot queries.

The parser supports the subset of RFC 4515 needed for directory triage:
 - Equality match (attr=value) and approximate match (attr~=value)
 - Presence (attr=*)
 - Substring matching (attr=pre*mid*suf)
 - Ordering comparisons (attr>=value, attr<=value)
 - Boolean operators: AND, OR, NOT
 - Active Directory bitwise AND/OR matching rules (1.2.840.113556.1.4.803/804)

Filter values honour hexadecimal escapes (\\xx) and allow literal asterisks via
the \\2a escape sequence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .snapshot import PropertyDefinition, SnapshotEntry, SnapshotReader, _parse_sid


class FilterSyntaxError(ValueError):
    pass


@dataclass
class FilterValue:
    raw: bytes

    def as_bytes(self) -> bytes:
        return self.raw

    def as_str(self) -> str:
        try:
            return self.raw.decode("utf-8")
        except UnicodeDecodeError:
            return self.raw.decode("latin-1", errors="ignore")


@dataclass
class SubstringPattern:
    initial: Optional[str]
    any: List[str]
    final: Optional[str]

    def normalised(self, casefold: bool) -> "SubstringPattern":
        if not casefold:
            return self
        return SubstringPattern(
            initial=self.initial.casefold() if self.initial is not None else None,
            any=[segment.casefold() for segment in self.any],
            final=self.final.casefold() if self.final is not None else None,
        )

    def matches(self, candidate: str) -> bool:
        pos = 0
        if self.initial is not None:
            if not candidate.startswith(self.initial):
                return False
            pos = len(self.initial)
        for segment in self.any:
            idx = candidate.find(segment, pos)
            if idx == -1:
                return False
            pos = idx + len(segment)
        if self.final is not None:
            # The final segment must start at or after the consumed prefix so
            # "a*a" does not match a single "a".
            return len(candidate) - len(self.final) >= pos and candidate.endswith(self.final)
        return True


@dataclass
class EvaluationContext:
    reader: SnapshotReader
    entry: SnapshotEntry
    ignore_case: bool

    def get_property(self, attr: str) -> Optional[PropertyDefinition]:
        return self.reader.get_property(attr)


class FilterNode:
    def evaluate(self, ctx: EvaluationContext) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError


def _extract_rdn_value(dn: str) -> Optional[str]:
    if "=" not in dn:
        return None
    first = dn.split(",", 1)[0]
    if "=" not in first:
        return None
    return first.split("=", 1)[1].strip()


def _entry_values(ctx: EvaluationContext, attr: str) -> Optional[List[object]]:
    prop = ctx.get_property(attr)
    if prop is None:
        return None
    try:
        return ctx.entry.get_attribute_values(prop.name)
    except KeyError:
        return None


def _scalar(value: object) -> object:
    """Unwrap decoder dictionaries ({"value": n}, {"sid": s}, {"guid": g}) for comparison."""
    if isinstance(value, dict):
        for key in ("value", "sid", "guid"):
            if key in value:
                return value[key]
    return value


class AndNode(FilterNode):
    def __init__(self, nodes: Sequence[FilterNode]):
        self.nodes = list(nodes)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return all(node.evaluate(ctx) for node in self.nodes)


class OrNode(FilterNode):
    def __init__(self, nodes: Sequence[FilterNode]):
        self.nodes = list(nodes)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return any(node.evaluate(ctx) for node in self.nodes)


class NotNode(FilterNode):
    def __init__(self, node: FilterNode):
        self.node = node

    def evaluate(self, ctx: EvaluationContext) -> bool:
        return not self.node.evaluate(ctx)


class PresenceNode(FilterNode):
    def __init__(self, attr: str):
        self.attr = attr

    def evaluate(self, ctx: EvaluationContext) -> bool:
        values = _entry_values(ctx, self.attr)
        return bool(values)


class EqualityNode(FilterNode):
    def __init__(self, attr: str, value: FilterValue, approximate: bool = False):
        self.attr = attr
        self.value = value
        self.approximate = approximate

    def evaluate(self, ctx: EvaluationContext) -> bool:
        values = _entry_values(ctx, self.attr)
        if not values:
            return False
        typed_value = self._prepare_value(values, self.value)
        if typed_value is None:
            return False
        return any(self._compare(_scalar(candidate), typed_value) for candidate in values)

    @staticmethod
    def _prepare_value(sample_values: Sequence[object], needle: FilterValue):
        sample = _scalar(sample_values[0]) if sample_values else None
        if isinstance(sample, bool):
            raw = needle.as_str().lower()
            if raw in {"true", "1"}:
                return True
            if raw in {"false", "0"}:
                return False
            return None
        if isinstance(sample, int):
            try:
                return int(needle.as_str(), 0)
            except ValueError:
                return None
        if isinstance(sample, bytes):
            text = needle.as_str()
            # Allow SIDs and GUIDs to be written in their textual form even
            # though the snapshot stores them as raw bytes.
            if text.upper().startswith("S-1-"):
                return text.casefold()
            try:
                return uuid.UUID(text).bytes_le
            except ValueError:
                return needle.as_bytes()
        return needle.as_str().casefold()

    @staticmethod
    def _compare(value: object, needle: object) -> bool:
        if needle is None:
            return False
        if isinstance(value, bool) and isinstance(needle, bool):
            return value is needle
        if isinstance(value, int) and isinstance(needle, int):
            return value == needle
        if isinstance(value, bytes):
            if isinstance(needle, bytes):
                return value == needle
            return _parse_sid(value).casefold() == needle
        value_str = str(value)
        value_norm = value_str.casefold()
        needle_norm = str(needle).casefold()
        if value_norm == needle_norm:
            return True
        rdn = _extract_rdn_value(value_str)
        return rdn is not None and rdn.casefold() == needle_norm


class ComparisonNode(FilterNode):
    """RFC 4515 greaterOrEqual / lessOrEqual on integers, timestamps or strings."""

    def __init__(self, attr: str, operator: str, value: FilterValue):
        self.attr = attr
        self.operator = operator
        self.value = value

    def evaluate(self, ctx: EvaluationContext) -> bool:
        values = _entry_values(ctx, self.attr)
        if not values:
            return False
        text = self.value.as_str()
        for candidate in values:
            candidate = _scalar(candidate)
            if isinstance(candidate, bool):
                continue
            if isinstance(candidate, int):
                try:
                    needle: object = int(text, 0)
                except ValueError:
                    continue
            elif isinstance(candidate, str):
                candidate = candidate.casefold()
                needle = text.casefold()
            else:
                continue
            if self.operator == ">=" and candidate >= needle:
                return True
            if self.operator == "<=" and candidate <= needle:
                return True
        return False


class BitwiseMatchNode(FilterNode):
    """Evaluate Active Directory's LDAP bitwise matching rules."""

    BIT_AND = "1.2.840.113556.1.4.803"
    BIT_OR = "1.2.840.113556.1.4.804"

    def __init__(self, attr: str, rule: str, value: FilterValue):
        self.attr = attr
        self.rule = rule
        self.value = value

    def evaluate(self, ctx: EvaluationContext) -> bool:
        try:
            mask = int(self.value.as_str(), 0)
        except ValueError:
            return False
        values = _entry_values(ctx, self.attr)
        if not values:
            return False
        for value in values:
            value = _scalar(value)
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if self.rule == self.BIT_AND and number & mask == mask:
                return True
            if self.rule == self.BIT_OR and number & mask:
                return True
        return False


class SubstringNode(FilterNode):
    def __init__(self, attr: str, pattern: SubstringPattern):
        self.attr = attr
        self.pattern = pattern
        self._folded = pattern.normalised(True)

    def evaluate(self, ctx: EvaluationContext) -> bool:
        values = _entry_values(ctx, self.attr)
        if not values:
            return False
        pattern = self._folded
        for value in values:
            value = _scalar(value)
            if isinstance(value, bytes):
                value = _parse_sid(value) if value[:1] == b"\x01" else value.hex()
            elif not isinstance(value, str):
                value = str(value)
            if pattern.matches(value.casefold()):
                return True
        return False


class Parser:
    def __init__(self, data: str):
        self.data = data
        self.length = len(data)
        self.pos = 0

    def parse(self) -> FilterNode:
        node = self._parse_filter()
        self._skip_spaces()
        if self.pos != self.length:
            raise FilterSyntaxError("Unexpected trailing characters in filter")
        return node

    # -- parsing helpers ---------------------------------------------------------

    def _parse_filter(self) -> FilterNode:
        self._skip_spaces()
        self._expect("(")
        self._skip_spaces()

        ch = self._peek()
        if ch in "&|":
            self._consume()
            nodes = []
            while True:
                self._skip_spaces()
                if self._peek() != "(":
                    break
                nodes.append(self._parse_filter())
            self._expect(")")
            if not nodes:
                raise FilterSyntaxError("Empty AND expression" if ch == "&" else "Empty OR expression")
            return AndNode(nodes) if ch == "&" else OrNode(nodes)

        if ch == "!":
            self._consume()
            node = self._parse_filter()
            self._expect(")")
            return NotNode(node)

        attr_spec = self._parse_attribute()
        operator = self._parse_operator()
        segments, star_count = self._parse_value_segments()

        attr = attr_spec
        matching_rule: Optional[str] = None
        if ":" in attr_spec:
            parts = attr_spec.split(":")
            if len(parts) == 3 and parts[0] and not parts[2]:
                attr, matching_rule = parts[0], parts[1]
            else:
                raise FilterSyntaxError(f"Unsupported extensible match: {attr_spec}")

        if matching_rule is not None:
            if operator != "=":
                raise FilterSyntaxError("Matching rules only support '='")
            if star_count:
                raise FilterSyntaxError("Wildcards are not valid in a bitwise match")
            if matching_rule not in {BitwiseMatchNode.BIT_AND, BitwiseMatchNode.BIT_OR}:
                raise FilterSyntaxError(f"Unsupported matching rule: {matching_rule}")
            self._expect(")")
            return BitwiseMatchNode(attr, matching_rule, FilterValue(segments[0]))

        if operator in {">=", "<="}:
            if star_count:
                raise FilterSyntaxError("Wildcards are not valid in a comparison")
            self._expect(")")
            return ComparisonNode(attr, operator, FilterValue(segments[0]))

        if operator == "~=":
            if star_count:
                raise FilterSyntaxError("Wildcards are not valid in an approximate match")
            self._expect(")")
            return EqualityNode(attr, FilterValue(segments[0]), approximate=True)

        if star_count == 1 and segments == [b"", b""]:
            self._expect(")")
            return PresenceNode(attr)

        if star_count >= 1:
            pattern = self._build_substring_pattern(attr, segments)
            self._expect(")")
            return SubstringNode(attr, pattern)

        self._expect(")")
        return EqualityNode(attr, FilterValue(segments[0]))

    def _parse_attribute(self) -> str:
        start = self.pos
        while self.pos < self.length:
            ch = self.data[self.pos]
            if ch in "=~><(":
                break
            self.pos += 1
        if start == self.pos:
            raise FilterSyntaxError("Missing attribute name")
        return self.data[start:self.pos].strip()

    def _parse_operator(self) -> str:
        ch = self._peek()
        if ch == "=":
            self._consume()
            return "="
        if ch in "~><":
            self._consume()
            self._expect("=")
            return ch + "="
        raise FilterSyntaxError("Expected '='")

    def _parse_value_segments(self) -> Tuple[List[bytes], int]:
        segments: List[bytes] = []
        buf = bytearray()
        star_count = 0
        while True:
            if self.pos >= self.length:
                raise FilterSyntaxError("Unterminated filter value")
            ch = self._peek()
            if ch == ")":
                segments.append(bytes(buf))
                break
            if ch == "*":
                segments.append(bytes(buf))
                buf.clear()
                star_count += 1
                self._consume()
                continue
            if ch == "\\":
                self._consume()
                buf.append(self._parse_escape())
                continue
            # LDAP filter text arrives as Unicode; assertion values are kept
            # as UTF-8 bytes so every code point survives intact.
            buf.extend(ch.encode("utf-8"))
            self._consume()
        return segments, star_count

    def _build_substring_pattern(self, attr: str, segments: List[bytes]) -> SubstringPattern:
        if not segments:
            raise FilterSyntaxError(f"Malformed substring filter for {attr}")
        segments_str = [FilterValue(seg).as_str() for seg in segments]
        initial = segments_str[0] or None
        final = segments_str[-1] or None
        any_segments = [seg for seg in segments_str[1:-1] if seg]
        return SubstringPattern(initial=initial, any=any_segments, final=final)

    def _parse_escape(self) -> int:
        if self.pos + 2 > self.length:
            raise FilterSyntaxError("Incomplete escape sequence")
        hex_pair = self.data[self.pos:self.pos + 2]
        self.pos += 2
        try:
            return int(hex_pair, 16)
        except ValueError as exc:
            raise FilterSyntaxError(f"Invalid escape sequence \\{hex_pair}") from exc

    def _peek(self) -> str:
        if self.pos >= self.length:
            raise FilterSyntaxError("Unexpected end of filter")
        return self.data[self.pos]

    def _consume(self) -> None:
        self.pos += 1

    def _expect(self, token: str) -> None:
        for ch in token:
            if self._peek() != ch:
                raise FilterSyntaxError(f"Expected '{token}'")
            self._consume()

    def _skip_spaces(self) -> None:
        while self.pos < self.length and self.data[self.pos].isspace():
            self.pos += 1


def parse_filter(data: str) -> FilterNode:
    return Parser(data).parse()


def filter_attributes(node: FilterNode) -> List[str]:
    """Return the attribute names referenced by a parsed filter, in first-use order."""
    found: List[str] = []
    seen = set()

    def visit(current: FilterNode) -> None:
        attribute = getattr(current, "attr", None)
        if attribute and attribute.casefold() not in seen:
            seen.add(attribute.casefold())
            found.append(attribute)
        for child in getattr(current, "nodes", []):
            visit(child)
        child = getattr(current, "node", None)
        if child is not None:
            visit(child)

    visit(node)
    return found
