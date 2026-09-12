"""Report rendering: CSV files, value redaction, and the SQLite audit tables."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..decoders import compact_json, decode_attribute
from .records import ci_get, as_list, as_int, is_sensitive_attribute

MUST_REVIEW_REPORTS = {
    "01_findings.csv", "05_domain_admins.csv", "05b_dangerous_acls.csv",
    "09_asrep_candidates.csv",
    "23_certificate_findings.csv", "25_laps_inventory.csv",
    "26_bitlocker_inventory.csv", "30_unknown_binary.csv",
    "31_sensitive_attribute_schema.csv", "31_sensitive_attribute_values.csv",
    "32_interesting_directory_values.csv", "33_free_text_values.csv",
}

SUMMARY_REPORTS = {
    "07b_users_summary.csv", "07d_account_restrictions.csv",
    "08b_spn_users_summary.csv", "10b_computers_summary.csv",
    "10c_service_inventory.csv",
    "11b_delegation_summary.csv", "11c_rbcd_principals.csv",
    "12b_group_membership.csv",
    "14b_gpo_summary.csv", "18b_dns_name_to_ip.csv",
    "18b_dns_name_to_ip.txt", "21b_ca_summary.csv",
    "22b_certificate_template_summary.csv", "22c_certificate_template_acl.csv",
}


def report_section(filename: str) -> str:
    if filename in MUST_REVIEW_REPORTS:
        return "00_must_review"
    if filename in SUMMARY_REPORTS:
        return "01_summaries"
    prefix = int(filename[:2]) if filename[:2].isdigit() else 99
    if prefix in range(4, 13) or prefix == 24:
        return "02_identity"
    if prefix in {2, 3, 13, 14, 15, 27}:
        return "03_domain_policy"
    if prefix in range(16, 21):
        return "04_network"
    if prefix in {21, 22, 23}:
        return "05_pki"
    if prefix in {28, 29}:
        return "06_schema"
    return "99_other"


def report_output_path(report_dir: Path, filename: str) -> Path:
    return report_dir / report_section(filename) / filename


def report_relative_path(filename: str) -> str:
    return f"reports/{report_section(filename)}/{filename}"


def cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        if "flags" in value and "hex" in value:
            names = ", ".join(str(item) for item in value.get("flags", [])) or "NO_FLAGS"
            return f"{names} [{value['hex']}]"
        if set(value).issuperset({"name", "value"}):
            return f"{value['name']} ({value['value']})"
        if "sid" in value:
            label = value.get("well_known_name")
            return f"{value['sid']} ({label})" if label else str(value["sid"])
        if "guid" in value and len(value) <= 2:
            return str(value["guid"])
        return compact_json(value)
    if isinstance(value, (list, tuple)):
        return "; ".join(cell(item) for item in value)
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def decoded_projection(
    record: Dict[str, Any], fields: Sequence[str], ads_types: Dict[str, int], timezone_name: str
) -> Dict[str, Any]:
    selected: Dict[str, Any] = {}
    for field in fields:
        value = ci_get(record, field, "")
        selected[field] = decode_attribute(field, value, ads_types.get(field.casefold()), timezone_name)
    return selected


def flags_text(attribute: str, value: Any, ads_types: Dict[str, int], timezone_name: str) -> str:
    decoded = decode_attribute(attribute, as_int(value), ads_types.get(attribute.casefold()), timezone_name)
    if isinstance(decoded, dict) and "flags" in decoded:
        return ", ".join(decoded["flags"]) or "NO_FLAGS"
    return cell(decoded)


def value_fingerprint_summary(value: Any) -> Dict[str, Any]:
    values = as_list(value)
    lengths = []
    digests = []
    for item in values:
        data = item if isinstance(item, bytes) else str(item).encode("utf-8", errors="replace")
        lengths.append(len(data))
        digests.append(hashlib.sha256(data).hexdigest())
    return {"redacted": True, "value_count": len(values), "lengths": lengths, "sha256": digests}


def report_value(
    name: str, value: Any, ads_types: Dict[str, int], timezone_name: str, include_sensitive: bool,
) -> Any:
    if is_sensitive_attribute(name):
        if not include_sensitive:
            return value_fingerprint_summary(value)
        return decode_attribute(name, value, ads_types.get(name.casefold()), timezone_name)
    decoded = decode_attribute(name, value, ads_types.get(name.casefold()), timezone_name)
    rendered = cell(decoded)
    if len(rendered) <= 2000:
        return decoded
    fingerprint = value_fingerprint_summary(value)
    fingerprint.update({"redacted": False, "truncated_for_csv": True, "preview": rendered[:1000]})
    return fingerprint


class ReportWriter:
    """Writes CSV reports under ``report_dir`` and records their row counts.

    With ``emit=False`` the rows are only counted, which is what the viewer
    database build uses: every report is available there as a live button, so
    the CSV files are opt-in.
    """

    def __init__(self, report_dir: Path, emit: bool):
        self.report_dir = report_dir
        self.emit = emit
        self.counts: Dict[str, int] = {}

    def write(self, filename: str, rows: Iterable[Dict[str, Any]], fields: Sequence[str]) -> int:
        if not self.emit:
            count = sum(1 for _ in rows)
            self.counts[filename] = count
            return count
        path = report_output_path(self.report_dir, filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({field: cell(row.get(field, "")) for field in fields})
                count += 1
        self.counts[filename] = count
        return count

    def write_text(self, filename: str, lines: List[str]) -> int:
        if self.emit:
            path = report_output_path(self.report_dir, filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8-sig")
        self.counts[filename] = len(lines)
        return len(lines)


# Computed-analysis tables the viewer surfaces as buttons. Each entry is
# (table, columns) where the last column, when it is a distinguished name, lets
# the viewer resolve the row back to its snapshot object.
AUDIT_RESULT_TABLES = {
    "audit_findings": ["severity", "category", "title", "object", "evidence", "recommendation"],
    "audit_dangerous_acls": ["target", "target_reason", "trustee", "trustee_sid", "granted", "ace_type", "access_mask", "object_type_guid", "distinguished_name"],
    "audit_rbcd": ["resource", "resource_type", "allowed_principal", "allowed_principal_sid", "distinguished_name"],
    "audit_privileged_members": ["privileged_group", "group_sid", "account", "account_type", "sam_account_name", "user_principal_name", "enabled", "membership_path", "distinguished_name"],
    "audit_dns_name_to_ip": ["dns_and_ip", "dns_name", "ip_address", "record_type", "ttl_seconds", "aging", "zone", "source", "target", "distinguished_name"],
    "audit_certificate_template_acl": ["template", "ace_type", "trustee_sid", "trustee_name", "access_summary", "rights", "object_type_name", "object_type_guid", "inheritance_flags", "low_privileged", "distinguished_name"],
    "audit_certificate_findings": ["severity", "issue", "template", "published", "low_priv_enrollment", "low_priv_write", "evidence", "distinguished_name"],
    # Rows carrying an ldap_filter column open that query in the viewer on click.
    "audit_custom_attribute_usage": ["attribute", "populated_objects", "object_types", "sensitive", "schema_oid", "attribute_syntax", "sample_values", "ldap_filter"],
    "audit_sensitive_attribute_schema": ["attribute", "populated_objects", "captured_property_definition", "schema_object_present", "confidential_search_flag", "custom_schema", "schema_oid", "attribute_syntax", "value_handling", "ldap_filter"],
}


def write_audit_result_tables(
    db,
    findings: List[Dict[str, str]],
    dangerous_acl_rows: List[Dict[str, Any]],
    rbcd_rows: List[Dict[str, Any]],
    privileged_member_rows: Optional[List[Dict[str, Any]]] = None,
    dns_address_rows: Optional[List[Dict[str, Any]]] = None,
    template_acl_rows: Optional[List[Dict[str, Any]]] = None,
    certificate_finding_rows: Optional[List[Dict[str, Any]]] = None,
    custom_usage_rows: Optional[List[Dict[str, Any]]] = None,
    sensitive_schema_rows: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Store the computed analyses in small tables the viewer reads as buttons.

    They are rebuilt on every run so the viewer always reflects the latest
    enumeration.
    """
    sources = {
        "audit_findings": findings,
        "audit_dangerous_acls": dangerous_acl_rows,
        "audit_rbcd": rbcd_rows,
        "audit_privileged_members": privileged_member_rows or [],
        "audit_dns_name_to_ip": dns_address_rows or [],
        "audit_certificate_template_acl": template_acl_rows or [],
        "audit_certificate_findings": certificate_finding_rows or [],
        "audit_custom_attribute_usage": custom_usage_rows or [],
        "audit_sensitive_attribute_schema": sensitive_schema_rows or [],
    }
    for table, columns in AUDIT_RESULT_TABLES.items():
        column_sql = ",".join(f"{name} TEXT" for name in columns)
        db.execute(f"CREATE TABLE IF NOT EXISTS {table}({column_sql})")
        db.execute(f"DELETE FROM {table}")
        placeholders = ",".join("?" for _ in columns)
        db.executemany(
            f"INSERT INTO {table} VALUES({placeholders})",
            (tuple(cell(row.get(name, "")) for name in columns) for row in sources[table]),
        )
    db.commit()


def add_finding(
    findings: List[Dict[str, str]], severity: str, category: str, title: str,
    target: str, evidence: str, recommendation: str,
) -> None:
    findings.append({
        "severity": severity, "category": category, "title": title,
        "object": target, "evidence": evidence, "recommendation": recommendation,
    })


def add_aggregate_finding(
    findings: List[Dict[str, str]], severity: str, category: str, title: str,
    objects: List[str], evidence: str, recommendation: str,
) -> None:
    if not objects:
        return
    sample = "; ".join(objects[:40])
    remainder = len(objects) - min(len(objects), 40)
    suffix = f"; and {remainder:,} more" if remainder else ""
    add_finding(
        findings, severity, category, title, f"{len(objects):,} objects",
        f"{evidence}. Objects: {sample}{suffix}", recommendation,
    )
