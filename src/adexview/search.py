"""Query planning and evaluation over the viewer's SQLite index.

LDAP filters run against decoded objects stored in the index. Before an
object is decompressed, the filter is turned into a conservative FTS5
candidate query (never dropping a real match) and, when every term can be
answered from the compact summary columns, evaluated without touching the
detail blob at all.
"""

from __future__ import annotations

import json
import sqlite3
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .decoders import FLAG_MAPS, json_default
from .ldapfilter import (
    AndNode, BitwiseMatchNode, ComparisonNode, EqualityNode, EvaluationContext,
    NotNode, OrNode, PresenceNode, SubstringNode, parse_filter,
)
from .snapshot import ADSTYPE_OBJECT_CLASS

# AD syntaxes whose decoded scalar values are retained in build_search_text().
# Octet strings and security descriptors are deliberately excluded: using
# their values as FTS candidates could otherwise hide a real LDAP match.
FTS_SAFE_ADS_TYPES = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 10, ADSTYPE_OBJECT_CLASS})
SUMMARY_FILTER_ATTRIBUTES = frozenset({
    "object_index", "distinguishedname", "objecttype", "objectclass", "name",
    "samaccountname", "userprincipalname", "serviceprincipalname", "dnshostname",
    "enabled", "operatingsystem", "operatingsystemversion", "uac_flags",
    "whencreated", "whenchanged", "attribute_count",
})
SUMMARY_JSON_ATTRIBUTES = frozenset({"objectclass", "serviceprincipalname"})
UAC_FLAG_BITS = FLAG_MAPS["useraccountcontrol"]
UAC_FLAG_VALUES = {name: bit for bit, name in UAC_FLAG_BITS.items()}
UAC_KNOWN_MASK = sum(UAC_FLAG_BITS)
OBJECT_TYPE_CLASSES = ("computer", "user", "group", "dnsnode")


def object_type_for(object_classes: Sequence[Any]) -> str:
    """The viewer's virtual objectType: the most specific well-known class."""
    normalized = [str(item).casefold() for item in object_classes]
    for name in OBJECT_TYPE_CLASSES:
        if name in normalized:
            return name
    return str(object_classes[-1]) if object_classes else ""


def display_value(value: Any) -> str:
    kind = type(value)
    if kind is str:
        return value
    if value is None:
        return ""
    if kind is dict or kind is list or kind is tuple:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=json_default)
    if kind is bytes:
        return value.hex()
    return str(value)


def ci_value(record: Dict[str, Any], name: str, default: Any = "") -> Any:
    """Case-insensitive lookup in a decoded object (small dictionaries only)."""
    value = record.get(name)
    if value is not None:
        return value
    wanted = name.casefold()
    for key, value in record.items():
        if key.casefold() == wanted:
            return value
    return default


# -- decoded-object adapters for the LDAP evaluator ---------------------------------


class _IndexedProperty:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class _IndexedReader:
    def __init__(self, detail: Dict[str, Any]) -> None:
        self.properties = {name.casefold(): _IndexedProperty(name) for name in detail}
        if "objectclass" in self.properties:
            self.properties["objecttype"] = _IndexedProperty("__objectType")

    def get_property(self, name: str) -> Optional[_IndexedProperty]:
        return self.properties.get(name.casefold())


class _IndexedEntry:
    def __init__(self, detail: Dict[str, Any]) -> None:
        self.detail = detail

    def get_attribute_values(self, name: str) -> List[Any]:
        if name == "__objectType":
            object_classes = ci_value(self.detail, "objectClass", [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes] if object_classes else []
            return [object_type_for(object_classes)]
        value = ci_value(self.detail, name, None)
        if value is None:
            raise KeyError(name)
        return value if isinstance(value, list) else [value]


class _SnapshotReaderAdapter:
    """Expose the virtual objectType field when evaluating raw snapshot entries."""

    def __init__(self, reader: Any) -> None:
        self.reader = reader

    def get_property(self, name: str) -> Any:
        if name.casefold() == "objecttype":
            return _IndexedProperty("__objectType")
        return self.reader.get_property(name)


class _SnapshotEntryAdapter:
    def __init__(self, entry: Any) -> None:
        self.entry = entry

    def get_attribute_values(self, name: str) -> List[Any]:
        if name == "__objectType":
            try:
                values = self.entry.get_attribute_values("objectClass")
            except KeyError:
                return []
            return [object_type_for(values)]
        return self.entry.get_attribute_values(name)


def normalize_viewer_ldap_filter(filter_text: str) -> str:
    """Accept the common non-RFC backslash-star spelling as a wildcard."""
    return filter_text.replace(r"\*", "*")


def evaluate_indexed_filter(detail: Dict[str, Any], filter_text: str) -> bool:
    """Evaluate a decoded viewer object using the CLI LDAP filter grammar."""
    node = parse_filter(normalize_viewer_ldap_filter(filter_text))
    return node.evaluate(EvaluationContext(
        reader=_IndexedReader(detail), entry=_IndexedEntry(detail), ignore_case=True,
    ))


def evaluate_node(node: Any, detail: Dict[str, Any]) -> bool:
    return node.evaluate(EvaluationContext(
        reader=_IndexedReader(detail), entry=_IndexedEntry(detail), ignore_case=True,
    ))


def indexed_attribute_value(detail: Dict[str, Any], name: str) -> Any:
    if name.casefold() == "objecttype":
        return _IndexedEntry(detail).get_attribute_values("__objectType")[0]
    return ci_value(detail, name, "")


def decode_indexed_detail(row: sqlite3.Row) -> Dict[str, Any]:
    detail_blob = row["detail_blob"]
    return json.loads(zlib.decompress(detail_blob).decode("utf-8"))


# -- FTS candidate planning -----------------------------------------------------------


def _fts_phrase(value: str) -> Optional[str]:
    """Return a literal trigram FTS phrase, or None for an unusable term."""
    value = value.strip()
    if len(value) < 3:
        return None
    return '"' + value.replace('"', '""') + '"'


def ldap_fts_candidate_query(node: Any, property_types: Dict[str, int]) -> Optional[str]:
    """Build a no-false-negative FTS5 superset for an LDAP filter.

    Attribute names are always part of an object's search payload. Scalar
    values are usable for non-binary AD syntaxes. AND can keep every usable
    child constraint; OR is safe only when every branch can be planned; a
    negative expression cannot independently narrow its parent.
    """
    if isinstance(node, AndNode):
        parts = [
            part for child in node.nodes
            if (part := ldap_fts_candidate_query(child, property_types))
        ]
        return " AND ".join(f"({part})" for part in parts) or None
    if isinstance(node, OrNode):
        parts = [ldap_fts_candidate_query(child, property_types) for child in node.nodes]
        if not parts or any(part is None for part in parts):
            return None
        return " OR ".join(f"({part})" for part in parts)
    if isinstance(node, NotNode):
        return None

    attribute = getattr(node, "attr", "")
    attribute_phrase = _fts_phrase(attribute)
    if isinstance(node, BitwiseMatchNode):
        if attribute.casefold() == "useraccountcontrol":
            try:
                mask = int(node.value.as_str(), 0)
            except ValueError:
                return attribute_phrase
            flag_phrases = [
                phrase for bit, name in UAC_FLAG_BITS.items()
                if mask & bit and (phrase := _fts_phrase(name))
            ]
            if flag_phrases:
                operator = " AND " if node.rule == BitwiseMatchNode.BIT_AND else " OR "
                # BIT_OR can match an unknown requested bit, so known flag
                # names narrow safely only when the whole mask is understood.
                if node.rule == BitwiseMatchNode.BIT_AND or not mask & ~UAC_KNOWN_MASK:
                    return operator.join(flag_phrases)
        return attribute_phrase
    if isinstance(node, (PresenceNode, ComparisonNode)):
        return attribute_phrase

    ads_type = property_types.get(attribute.casefold())
    if attribute.casefold() == "objecttype":
        ads_type = ADSTYPE_OBJECT_CLASS
    if ads_type not in FTS_SAFE_ADS_TYPES:
        return attribute_phrase

    value_phrase: Optional[str] = None
    if isinstance(node, EqualityNode):
        value_phrase = _fts_phrase(node.value.as_str())
    elif isinstance(node, SubstringNode):
        pattern = node.pattern
        segments = [segment for segment in [pattern.initial, *pattern.any, pattern.final] if segment]
        if segments:
            value_phrase = _fts_phrase(max(segments, key=len))

    # The value normally narrows far more than the attribute. Requiring both is
    # still a superset because each is present in every real scalar match.
    if value_phrase and attribute_phrase:
        return f"{attribute_phrase} AND {value_phrase}"
    return value_phrase or attribute_phrase


def summary_filter_detail(headers: Sequence[str], row_json: str) -> Dict[str, Any]:
    """Materialise the compact object-list fields without inflating detail_blob."""
    values = json.loads(row_json)
    detail: Dict[str, Any] = {}
    for name, value in zip(headers, values):
        if name.casefold() in SUMMARY_JSON_ATTRIBUTES and isinstance(value, str) and value[:1] in {"[", "{"}:
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
        detail[name] = value
    flags = str(detail.get("uac_flags", ""))
    if flags:
        detail["userAccountControl"] = {
            "value": sum(UAC_FLAG_VALUES.get(name.strip(), 0) for name in flags.split(","))
        }
    return detail


def can_evaluate_from_summary(node: Any, headers: Sequence[str]) -> bool:
    available = {name.casefold() for name in headers} & SUMMARY_FILTER_ATTRIBUTES

    def supported(current: Any) -> bool:
        if isinstance(current, (AndNode, OrNode)):
            return all(supported(child) for child in current.nodes)
        if isinstance(current, NotNode):
            return supported(current.node)
        attribute = getattr(current, "attr", "").casefold()
        if attribute == "useraccountcontrol":
            if not isinstance(current, BitwiseMatchNode) or "uac_flags" not in available:
                return False
            try:
                mask = int(current.value.as_str(), 0)
            except ValueError:
                return False
            return bool(mask) and not mask & ~UAC_KNOWN_MASK
        return attribute in available

    return supported(node)


# -- distinguished-name helpers --------------------------------------------------------


def split_distinguished_name(value: str) -> List[str]:
    """Split an LDAP DN on unescaped commas, preserving its display form."""
    if "\\" not in value and '"' not in value:
        return [part for part in (piece.strip() for piece in value.split(",")) if part]
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    quoted = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == '"':
            current.append(character)
            quoted = not quoted
        elif character == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def normalize_dn(value: str) -> str:
    return ",".join(part.casefold() for part in split_distinguished_name(value))


def parent_dn(value: str) -> str:
    parts = split_distinguished_name(value)
    return ",".join(parts[1:]) if len(parts) > 1 else ""


def is_naming_context_root(class_names: Sequence[str], object_type: str) -> bool:
    normalized = {str(name).casefold() for name in class_names}
    return "domaindns" in normalized or object_type.casefold() in {"configuration", "dmd"}


# -- per-column filters for the object list -------------------------------------------


def build_field_filters(headers: Sequence[str], filters: Any) -> Tuple[List[str], List[Any]]:
    """Build safe, AND-combined SQLite predicates for per-column filters."""
    if not isinstance(filters, dict):
        raise ValueError("filters must be a JSON object")
    clauses: List[str] = []
    parameters: List[Any] = []
    for raw_index, raw_expression in filters.items():
        try:
            index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid filter column") from exc
        if index < 0 or index >= len(headers):
            raise ValueError("invalid filter column")
        expressions = [item.strip() for item in str(raw_expression).split("|") if item.strip()]
        if not expressions:
            continue
        value_sql = f"json_extract(row_json, '$[{index}]')"
        positive_clauses: List[str] = []
        positive_parameters: List[Any] = []
        negative_clauses: List[str] = []
        negative_parameters: List[Any] = []
        for expression in expressions:
            comparison = next(
                (operator for operator in (">=", "<=", ">", "<") if expression.startswith(operator)), None,
            )
            if comparison:
                operand = expression[len(comparison):].strip()
                try:
                    number = float(operand)
                except ValueError:
                    comparison = None
                else:
                    # Only compare rows whose value is actually numeric, so text
                    # and empty cells (which CAST to 0.0) are excluded.
                    positive_clauses.append(
                        f"(({value_sql} GLOB '[0-9]*' OR {value_sql} GLOB '[-+.][0-9]*') "
                        f"AND CAST({value_sql} AS REAL) {comparison} ?)"
                    )
                    positive_parameters.append(number)
                    continue
            if expression.startswith("!="):
                negative_clauses.append(f"CAST({value_sql} AS TEXT) COLLATE NOCASE != ?")
                negative_parameters.append(expression[2:].strip())
                continue
            if expression.startswith("="):
                positive_clauses.append(f"CAST({value_sql} AS TEXT) COLLATE NOCASE = ?")
                positive_parameters.append(expression[1:].strip())
                continue
            exclude = expression.startswith("!")
            needle = expression[1:].strip() if exclude else expression
            escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            target = negative_clauses if exclude else positive_clauses
            target_parameters = negative_parameters if exclude else positive_parameters
            target.append(
                f"CAST({value_sql} AS TEXT) {'NOT LIKE' if exclude else 'LIKE'} ? ESCAPE '\\' COLLATE NOCASE"
            )
            target_parameters.append(f"%{escaped}%")
        if positive_clauses:
            clauses.append("(" + " OR ".join(positive_clauses) + ")")
            parameters.extend(positive_parameters)
        clauses.extend(negative_clauses)
        parameters.extend(negative_parameters)
    return clauses, parameters
