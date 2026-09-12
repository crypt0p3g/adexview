"""Audit orchestration: load the snapshot, run every analysis, write the outputs."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..decoders import DEFAULT_TIMEZONE, decode_attribute, decode_binary, format_datetime
from ..snapshot import SnapshotReader
from .analysis import (
    AUTOENROLL_GUID, CLIENT_AUTH_EKUS, ENROLL_GUID, SECRET_IN_TEXT_PATTERN,
    analyze_additional_security, analyze_certificates, analyze_object_acls, analyze_rbcd,
    analyze_service_inventory, build_domain_admins, build_privileged_group_members,
    dns_node_fqdn, filetime_datetime, low_priv_sid, template_acl_facts,
)
from .records import (
    HIGH_INTEREST_ATTRIBUTES, SENSITIVE_ATTRIBUTES, SENSITIVE_ATTRIBUTE_DISPLAY_NAMES,
    UAC, Directory, as_int, as_list, ci_get, classes, dn, dn_key, has_uac, is_computer,
    is_sensitive_attribute, is_user, load_directory, object_name, short_dn, sid_string,
)
from .reports import (
    ReportWriter, add_finding, cell, decoded_projection, flags_text, report_output_path,
    report_relative_path, report_value, write_audit_result_tables,
)
from ..decoders import parse_security_descriptor

ProgressCallback = Callable[[str, int, int], None]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="adexview audit",
        description="Create an offline AD Explorer snapshot audit bundle.",
    )
    parser.add_argument("--snapshot", required=True, help="AD Explorer .dat snapshot")
    parser.add_argument("--output", required=True, help="Project directory for the outputs")
    parser.add_argument("--timezone", default=DEFAULT_TIMEZONE, help=f"IANA timezone for dates (default: {DEFAULT_TIMEZONE})")
    parser.add_argument("--stale-days", type=int, default=90, help="Inactivity threshold in days (default: 90)")
    parser.add_argument(
        "--output-mode", choices=("csv", "sqlite", "both"), default="both",
        help="Write CSV reports, the viewer database, or both (default: both).",
    )
    parser.add_argument("--database", help="SQLite output path (default: OUTPUT/OUTPUT_NAME.sqlite3).")
    parser.add_argument(
        "--csv-reports", dest="csv_reports", action="store_true",
        help="Also write the CSV report files to reports/ (the viewer shows every report "
             "as a button, so the CSVs are off by default in 'both' mode).",
    )
    sensitive_group = parser.add_mutually_exclusive_group()
    sensitive_group.add_argument(
        "--include-sensitive-values", dest="include_sensitive_values", action="store_true",
        help="Include password/recovery values (the default).",
    )
    sensitive_group.add_argument(
        "--redact-sensitive-values", dest="include_sensitive_values", action="store_false",
        help="Replace password/recovery values with lengths and SHA-256 fingerprints.",
    )
    parser.set_defaults(include_sensitive_values=True)
    return parser.parse_args(argv)


def write_snapshot_sqlite(
    snapshot: Path, timezone_name: str, database_path: Path,
    audit_tables: Optional[Tuple[Any, ...]] = None, status: Optional[Any] = None,
) -> int:
    """Build the viewer's decoded object index, optionally adding the audit tables."""
    from ..index import connect, index_snapshot, initialize

    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(database_path)) as db:
        initialize(db)
        _changed, row_count = index_snapshot(snapshot, db, timezone_name, status=status)
        if audit_tables is not None:
            write_audit_result_tables(db, *audit_tables)
    return row_count


class Audit:
    """One audit run over a loaded directory."""

    def __init__(self, directory: Directory, args: argparse.Namespace, writer: ReportWriter):
        self.directory = directory
        self.records = directory.records
        self.by_sid = directory.by_sid
        self.by_dn = directory.by_dn
        self.ads_types = directory.ads_types
        self.args = args
        self.tz = args.timezone
        self.writer = writer
        self.findings: List[Dict[str, str]] = []
        self.capture_time = directory.reader.header.captured_at
        # Populated by the analyses and stored in the viewer database.
        self.dangerous_acl_rows: List[Dict[str, Any]] = []
        self.rbcd_rows: List[Dict[str, Any]] = []
        self.privileged_member_rows: List[Dict[str, Any]] = []
        self.dns_address_rows: List[Dict[str, Any]] = []
        self.template_acl_rows: List[Dict[str, Any]] = []
        self.cert_finding_rows: List[Dict[str, Any]] = []
        self.custom_usage_rows: List[Dict[str, Any]] = []
        self.sensitive_schema_rows: List[Dict[str, Any]] = []
        self.privileged_dn_set: set = set()

    # -- helpers -------------------------------------------------------------------

    def release(self) -> None:
        """Drop the loaded directory so its memory can be reused by later stages."""
        self.directory = None  # type: ignore[assignment]
        self.records = []
        self.by_sid = {}
        self.by_dn = {}

    def report(self, filename: str, subset: Iterable[Dict[str, Any]], fields: Sequence[str]) -> None:
        rows = [decoded_projection(item, fields, self.ads_types, self.tz) for item in subset]
        self.writer.write(filename, rows, fields)

    def decode(self, attribute: str, value: Any) -> Any:
        return decode_attribute(attribute, value, self.ads_types.get(attribute.casefold()), self.tz)

    def field(self, item: Dict[str, Any], attribute: str) -> Any:
        return self.decode(attribute, ci_get(item, attribute, ""))

    def with_classes(self, *names: str) -> List[Dict[str, Any]]:
        wanted = {name.casefold() for name in names}
        return [item for item in self.records if classes(item) & wanted]

    # -- report groups -------------------------------------------------------------

    def domains(self) -> List[Dict[str, Any]]:
        # DNS application partitions also use domainDNS. objectSid identifies an
        # actual AD domain naming-context head with a domain password policy.
        domains = [
            item for item in self.records
            if "domaindns" in classes(item) and ci_get(item, "objectSid") is not None
        ]
        self.report("02_domain_info.csv", domains, ["distinguishedName", "name", "objectSid", "msDS-Behavior-Version", "nTMixedDomain", "fSMORoleOwner", "ms-DS-MachineAccountQuota", "whenCreated", "whenChanged"])
        self.report("03_password_policy.csv", domains, ["distinguishedName", "minPwdLength", "minPwdAge", "maxPwdAge", "pwdHistoryLength", "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "forceLogoff"])
        self.report("03b_directory_partitions.csv", self.with_classes("crossRef"), ["distinguishedName", "cn", "nCName", "dnsRoot", "nETBIOSName", "systemFlags", "msDS-SDReferenceDomain", "whenCreated", "whenChanged"])
        findings = self.findings
        for domain in domains:
            target = dn(domain)
            min_length = as_int(ci_get(domain, "minPwdLength"))
            if min_length < 14:
                add_finding(findings, "MEDIUM", "Domain policy", "Minimum password length below 14", target, f"minPwdLength={min_length}", "Use long passwords/passphrases and modern banned-password controls.")
            if as_int(ci_get(domain, "lockoutThreshold")) == 0:
                add_finding(findings, "MEDIUM", "Domain policy", "Account lockout is disabled", target, "lockoutThreshold=0", "Configure a lockout or smart-lockout policy appropriate to the environment.")
            raw_properties = ci_get(domain, "pwdProperties")
            if raw_properties is not None:
                properties = as_int(raw_properties)
                if not (properties & 0x1):
                    add_finding(findings, "HIGH", "Domain policy", "Password complexity is disabled", target, f"pwdProperties=0x{properties:08x}", "Enable domain password complexity and use banned-password protections.")
                if properties & 0x10:
                    add_finding(findings, "HIGH", "Domain policy", "Domain policy permits reversible password storage", target, f"pwdProperties=0x{properties:08x}", "Disable reversible password storage and reset affected account passwords.")
            quota = as_int(ci_get(domain, "ms-DS-MachineAccountQuota"))
            if quota > 0:
                add_finding(findings, "LOW", "Domain policy", "Authenticated users can create machine accounts", target, f"ms-DS-MachineAccountQuota={quota}", "Set the quota to 0 where self-service domain join is not required and delegate joins explicitly.")
        return domains

    USER_FIELDS = ["distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "description", "mail", "userAccountControl", "msDS-User-Account-Control-Computed", "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp", "lastLogoff", "logonCount", "badPasswordTime", "badPwdCount", "lockoutTime", "accountExpires", "logonHours", "userWorkstations", "adminCount", "memberOf", "servicePrincipalName", "msDS-SupportedEncryptionTypes", "msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo", "whenCreated", "whenChanged"]

    def users(self) -> List[Dict[str, Any]]:
        users = [item for item in self.records if is_user(item)]
        fields = self.USER_FIELDS
        self.report("07_users.csv", users, fields)
        self.report("08_spn_users.csv", [item for item in users if as_list(ci_get(item, "servicePrincipalName"))], fields)
        self.report("09_asrep_candidates.csv", [item for item in users if has_uac(item, "NO_PREAUTH") and not has_uac(item, "DISABLED")], fields)
        self.report("06_privileged_objects.csv", [item for item in self.records if as_int(ci_get(item, "adminCount")) == 1], fields)

        summary_fields = [
            "account", "upn", "enabled", "privileged", "uac_flags",
            "password_last_set_jst", "last_logon_jst", "account_expires_jst",
            "password_never_expires", "preauthentication_required", "spn_count",
            "spns", "groups", "description", "distinguished_name",
        ]
        summary_rows = []
        for item in users:
            spns = [str(value) for value in as_list(ci_get(item, "servicePrincipalName"))]
            summary_rows.append({
                "account": object_name(item),
                "upn": ci_get(item, "userPrincipalName", ""),
                "enabled": not has_uac(item, "DISABLED"),
                "privileged": as_int(ci_get(item, "adminCount")) == 1,
                "uac_flags": flags_text("userAccountControl", ci_get(item, "userAccountControl"), self.ads_types, self.tz),
                "password_last_set_jst": self.field(item, "pwdLastSet"),
                "last_logon_jst": self.field(item, "lastLogonTimestamp"),
                "account_expires_jst": self.field(item, "accountExpires"),
                "password_never_expires": has_uac(item, "PASSWORD_NEVER_EXPIRES"),
                "preauthentication_required": not has_uac(item, "NO_PREAUTH"),
                "spn_count": len(spns),
                "spns": spns,
                "groups": [short_dn(value) for value in as_list(ci_get(item, "memberOf"))],
                "description": ci_get(item, "description", ""),
                "distinguished_name": dn(item),
            })
        self.writer.write("07b_users_summary.csv", summary_rows, summary_fields)
        self.writer.write("08b_spn_users_summary.csv", [row for row in summary_rows if row["spn_count"]], summary_fields)

        restriction_fields = [
            "account", "enabled", "locked_out", "password_expired",
            "account_expires_jst", "password_expires_jst", "logon_hours",
            "logon_hours_restriction", "allowed_workstations", "workstation_restricted",
            "assigned_authentication_policy", "assigned_authentication_policy_silo",
            "allowed_to_authenticate_from", "allowed_to_authenticate_to",
            "last_logon_jst", "last_logoff_jst", "bad_password_time_jst",
            "bad_password_count", "logon_count", "script_path", "profile_path",
            "home_directory", "home_drive", "terminal_services_settings",
            "unix_login_shell", "unix_home_directory", "uid", "uid_number",
            "gid_number", "shadow_expire", "shadow_last_change",
            "distinguished_name",
        ]
        restriction_rows = []
        for item in users:
            computed_uac = as_int(ci_get(item, "msDS-User-Account-Control-Computed"))
            decoded_hours = self.field(item, "logonHours")
            workstations = [
                value.strip() for value in str(ci_get(item, "userWorkstations", "")).split(",")
                if value.strip()
            ]
            terminal_services = {}
            for name in (
                "terminalServer", "msTSAllowLogon", "msTSHomeDirectory",
                "msTSHomeDrive", "msTSProfilePath", "msNPAllowDialin", "userParameters",
            ):
                raw_value = ci_get(item, name, "")
                if raw_value not in (None, ""):
                    terminal_services[name] = self.decode(name, raw_value)
            restriction_rows.append({
                "account": object_name(item),
                "enabled": not has_uac(item, "DISABLED"),
                "locked_out": bool(computed_uac & UAC["LOCKOUT"]) or as_int(ci_get(item, "lockoutTime")) != 0,
                "password_expired": bool(computed_uac & UAC["PASSWORD_EXPIRED"]) or has_uac(item, "PASSWORD_EXPIRED"),
                "account_expires_jst": self.field(item, "accountExpires"),
                "password_expires_jst": self.field(item, "msDS-UserPasswordExpiryTimeComputed"),
                "logon_hours": decoded_hours,
                "logon_hours_restriction": decoded_hours.get("restriction", "NOT_CONFIGURED") if isinstance(decoded_hours, dict) else "NOT_CONFIGURED",
                "allowed_workstations": workstations or ["ANY"],
                "workstation_restricted": bool(workstations),
                "assigned_authentication_policy": ci_get(item, "msDS-AssignedAuthNPolicy", ""),
                "assigned_authentication_policy_silo": ci_get(item, "msDS-AssignedAuthNPolicySilo", ""),
                "allowed_to_authenticate_from": self.field(item, "msDS-UserAllowedToAuthenticateFrom"),
                "allowed_to_authenticate_to": self.field(item, "msDS-UserAllowedToAuthenticateTo"),
                "last_logon_jst": self.field(item, "lastLogonTimestamp"),
                "last_logoff_jst": self.field(item, "lastLogoff"),
                "bad_password_time_jst": self.field(item, "badPasswordTime"),
                "bad_password_count": ci_get(item, "badPwdCount", ""),
                "logon_count": ci_get(item, "logonCount", ""),
                "script_path": ci_get(item, "scriptPath", ""),
                "profile_path": ci_get(item, "profilePath", ""),
                "home_directory": ci_get(item, "homeDirectory", ""),
                "home_drive": ci_get(item, "homeDrive", ""),
                "terminal_services_settings": terminal_services,
                "unix_login_shell": ci_get(item, "loginShell", ""),
                "unix_home_directory": ci_get(item, "unixHomeDirectory", ""),
                "uid": ci_get(item, "uid", ""),
                "uid_number": ci_get(item, "uidNumber", ""),
                "gid_number": ci_get(item, "gidNumber", ""),
                "shadow_expire": self.field(item, "shadowExpire"),
                "shadow_last_change": self.field(item, "shadowLastChange"),
                "distinguished_name": dn(item),
            })
        self.writer.write("07d_account_restrictions.csv", restriction_rows, restriction_fields)
        return users

    def privileged_and_acls(self, domains: List[Dict[str, Any]]) -> None:
        domain_admins = build_domain_admins(self.records)
        self.privileged_member_rows = build_privileged_group_members(self.records)
        self.privileged_dn_set = {
            str(row["distinguished_name"]).casefold()
            for row in self.privileged_member_rows if row["distinguished_name"]
        }
        da_rows = []
        for item, path in domain_admins:
            row = decoded_projection(item, self.USER_FIELDS, self.ads_types, self.tz)
            row["membershipPath"] = path
            da_rows.append(row)
        self.writer.write("05_domain_admins.csv", da_rows, self.USER_FIELDS + ["membershipPath"])

        self.dangerous_acl_rows = analyze_object_acls(self.records, domains, self.findings, self.by_sid)
        self.writer.write(
            "05b_dangerous_acls.csv", self.dangerous_acl_rows,
            ["target", "target_reason", "trustee", "trustee_sid", "granted",
             "ace_type", "access_mask", "object_type_guid", "distinguished_name"],
        )
        self.rbcd_rows = analyze_rbcd(self.records, self.findings, self.by_sid)
        self.writer.write(
            "11c_rbcd_principals.csv", self.rbcd_rows,
            ["resource", "resource_type", "allowed_principal", "allowed_principal_sid", "distinguished_name"],
        )
        service_rows = analyze_service_inventory(self.records)
        self.writer.write(
            "10c_service_inventory.csv", service_rows,
            ["host", "roles", "object_type", "operating_system", "service_principal_names", "distinguished_name"],
        )

    def account_findings(self, users: List[Dict[str, Any]]) -> None:
        findings = self.findings
        stale_before = self.capture_time - dt.timedelta(days=self.args.stale_days)
        for user in users:
            target = object_name(user)
            if has_uac(user, "DISABLED"):
                continue
            for flag, severity, title in (
                ("PASSWORD_NOT_REQUIRED", "HIGH", "Enabled account does not require a password"),
                ("REVERSIBLE_PASSWORD", "HIGH", "Reversible password encryption is enabled"),
                ("NO_PREAUTH", "HIGH", "Kerberos pre-authentication is not required"),
                ("DES_ONLY", "HIGH", "Account is restricted to DES Kerberos keys"),
                ("PASSWORD_NEVER_EXPIRES", "MEDIUM", "Password never expires"),
                ("UNCONSTRAINED_DELEGATION", "HIGH", "User account is trusted for unconstrained delegation"),
            ):
                if flag == "PASSWORD_NEVER_EXPIRES" and dn_key(user) in self.privileged_dn_set:
                    continue  # Raised with privileged-account context and HIGH severity instead.
                if has_uac(user, flag):
                    add_finding(findings, severity, "Account", title, target, f"userAccountControl includes {flag}", "Review the account requirement and remove the flag where unnecessary.")
            last_seen = filetime_datetime(ci_get(user, "lastLogonTimestamp"))
            if last_seen and last_seen < stale_before:
                add_finding(findings, "LOW", "Account", f"Enabled user inactive for more than {self.args.stale_days} days", target, f"lastLogonTimestamp={last_seen.isoformat()}", "Validate ownership and disable or remove stale accounts.")
            free_text = " ".join(str(ci_get(user, attr, "")) for attr in ("description", "info", "comment"))
            if SECRET_IN_TEXT_PATTERN.search(free_text):
                add_finding(findings, "HIGH", "Data exposure", "Possible secret in a free-text directory attribute", target, free_text[:500], "Remove secrets from AD attributes and rotate any exposed credential.")

    def computers(self) -> List[Dict[str, Any]]:
        computers = [item for item in self.records if is_computer(item)]
        fields = ["distinguishedName", "sAMAccountName", "dNSHostName", "description", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "servicePrincipalName", "msDS-SupportedEncryptionTypes", "whenCreated", "whenChanged"]
        self.report("10_computers.csv", computers, fields)
        self.report("04_domain_controllers.csv", [item for item in computers if has_uac(item, "DOMAIN_CONTROLLER")], fields)
        summary_fields = [
            "computer", "dns_name", "enabled", "domain_controller", "operating_system",
            "operating_system_version", "last_logon_jst", "password_last_set_jst",
            "delegation", "kerberos_encryption", "spn_count", "description", "distinguished_name",
        ]
        summary_rows = []
        for item in computers:
            summary_rows.append({
                "computer": ci_get(item, "sAMAccountName", ""),
                "dns_name": ci_get(item, "dNSHostName", ""),
                "enabled": not has_uac(item, "DISABLED"),
                "domain_controller": has_uac(item, "DOMAIN_CONTROLLER"),
                "operating_system": ci_get(item, "operatingSystem", ""),
                "operating_system_version": ci_get(item, "operatingSystemVersion", ""),
                "last_logon_jst": self.field(item, "lastLogonTimestamp"),
                "password_last_set_jst": self.field(item, "pwdLastSet"),
                "delegation": _delegation_kinds(item) or ["NONE"],
                "kerberos_encryption": flags_text("msDS-SupportedEncryptionTypes", ci_get(item, "msDS-SupportedEncryptionTypes"), self.ads_types, self.tz),
                "spn_count": len(as_list(ci_get(item, "servicePrincipalName"))),
                "description": ci_get(item, "description", ""),
                "distinguished_name": dn(item),
            })
        self.writer.write("10b_computers_summary.csv", summary_rows, summary_fields)
        for computer in computers:
            if has_uac(computer, "UNCONSTRAINED_DELEGATION") and not has_uac(computer, "DOMAIN_CONTROLLER"):
                add_finding(self.findings, "HIGH", "Delegation", "Non-DC computer has unconstrained delegation", object_name(computer), "TRUSTED_FOR_DELEGATION flag is set", "Replace unconstrained delegation with constrained delegation or RBCD and protect privileged credentials.")
        return computers

    def delegation(self) -> None:
        delegation = [
            item for item in self.records
            if has_uac(item, "UNCONSTRAINED_DELEGATION") or as_list(ci_get(item, "msDS-AllowedToDelegateTo"))
            or ci_get(item, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        ]
        self.report("11_delegation.csv", delegation, ["distinguishedName", "objectClass", "sAMAccountName", "dNSHostName", "userAccountControl", "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "whenChanged"])
        rows = [{
            "principal": object_name(item),
            "dns_name": ci_get(item, "dNSHostName", ""),
            "object_type": "computer" if is_computer(item) else "user",
            "delegation_types": _delegation_kinds(item),
            "targets": ci_get(item, "msDS-AllowedToDelegateTo", ""),
            "is_domain_controller": has_uac(item, "DOMAIN_CONTROLLER"),
            "distinguished_name": dn(item),
        } for item in delegation]
        self.writer.write("11b_delegation_summary.csv", rows, ["principal", "dns_name", "object_type", "delegation_types", "targets", "is_domain_controller", "distinguished_name"])

    def groups_and_trusts(self) -> None:
        groups = self.with_classes("group")
        self.report("12_groups.csv", groups, ["distinguishedName", "sAMAccountName", "description", "objectSid", "groupType", "adminCount", "member", "memberOf", "whenCreated", "whenChanged"])
        membership_rows = []
        for group in groups:
            group_sid = sid_string(group)
            privileged_group = as_int(ci_get(group, "adminCount")) == 1 or group_sid.rsplit("-", 1)[-1] in {"512", "518", "519", "544"}
            for member_dn in as_list(ci_get(group, "member")):
                member = self.by_dn.get(str(member_dn).casefold())
                member_classes = classes(member) if member else frozenset()
                membership_rows.append({
                    "group": object_name(group),
                    "group_sid": group_sid,
                    "privileged_group": privileged_group,
                    "member": object_name(member) if member else short_dn(member_dn),
                    "member_type": "group" if "group" in member_classes else ("computer" if "computer" in member_classes else ("foreign_security_principal" if "foreignsecurityprincipal" in member_classes else "user/object")),
                    "nested_group": "group" in member_classes,
                    "member_distinguished_name": member_dn,
                    "group_distinguished_name": dn(group),
                })
        self.writer.write("12b_group_membership.csv", membership_rows, ["group", "group_sid", "privileged_group", "member", "member_type", "nested_group", "member_distinguished_name", "group_distinguished_name"])
        self.report("13_trusts.csv", self.with_classes("trustedDomain"), ["distinguishedName", "trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "securityIdentifier", "whenCreated", "whenChanged"])
        analyze_additional_security(
            self.records, self.findings, self.capture_time, self.args.stale_days,
            self.privileged_dn_set, self.by_sid,
        )

    def group_policy(self) -> None:
        gpos = self.with_classes("groupPolicyContainer")
        self.report("14_gpos.csv", gpos, ["distinguishedName", "displayName", "name", "flags", "versionNumber", "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames", "whenCreated", "whenChanged"])
        link_objects = [item for item in self.records if ci_get(item, "gPLink")]
        self.report("15_gpo_links.csv", link_objects, ["distinguishedName", "objectClass", "name", "gPLink", "gPOptions", "whenCreated", "whenChanged"])
        link_gplinks = [(item, str(ci_get(item, "gPLink", "")).casefold()) for item in link_objects]
        rows = []
        for gpo in gpos:
            guid = str(ci_get(gpo, "name", ""))
            guid_cf = guid.casefold()
            gpo_flags = as_int(ci_get(gpo, "flags"))
            version = as_int(ci_get(gpo, "versionNumber"))
            rows.append({
                "display_name": ci_get(gpo, "displayName", ""),
                "guid": guid,
                "status": {0: "USER_AND_COMPUTER_ENABLED", 1: "USER_DISABLED", 2: "COMPUTER_DISABLED", 3: "ALL_SETTINGS_DISABLED"}.get(gpo_flags, f"UNKNOWN_{gpo_flags}"),
                "computer_version": version & 0xFFFF,
                "user_version": (version >> 16) & 0xFFFF,
                "sysvol_path": ci_get(gpo, "gPCFileSysPath", ""),
                "linked_to": [dn(item) for item, gplink in link_gplinks if guid_cf in gplink],
                "created_jst": self.field(gpo, "whenCreated"),
                "modified_jst": self.field(gpo, "whenChanged"),
                "distinguished_name": dn(gpo),
            })
        self.writer.write("14b_gpo_summary.csv", rows, ["display_name", "guid", "status", "computer_version", "user_version", "sysvol_path", "linked_to", "created_jst", "modified_jst", "distinguished_name"])
        self.report("16_sites.csv", self.with_classes("site"), ["distinguishedName", "cn", "description", "location", "whenCreated", "whenChanged"])
        self.report("17_subnets.csv", self.with_classes("subnet"), ["distinguishedName", "cn", "description", "siteObject", "location", "whenCreated", "whenChanged"])

    def dns(self) -> None:
        dns_rows: List[Dict[str, Any]] = []
        address_rows: List[Dict[str, Any]] = []
        cname_targets: List[Tuple[str, str, Dict[str, Any]]] = []
        for item in self.records:
            blobs = as_list(ci_get(item, "dnsRecord"))
            if not blobs:
                continue
            fqdn, zone = dns_node_fqdn(ci_get(item, "name", ""), dn(item))
            created = self.field(item, "whenCreated")
            changed = self.field(item, "whenChanged")
            for blob in blobs:
                parsed = decode_binary("dnsRecord", blob, timezone_name=self.tz) if isinstance(blob, bytes) else blob
                dns_rows.append({"name": ci_get(item, "name", ""), "fqdn": fqdn, "zone": zone, "distinguishedName": dn(item), "record": parsed, "whenCreated": created, "whenChanged": changed})
                if not isinstance(parsed, dict):
                    continue
                if parsed.get("address"):
                    address_rows.append({
                        "DNSName": fqdn, "IPAddress": parsed["address"],
                        "RecordType": parsed.get("type", ""), "TTLSeconds": parsed.get("ttl_seconds", ""),
                        "Aging": parsed.get("aging_timestamp", ""), "Zone": zone,
                        "Source": "DIRECT", "Target": "", "DistinguishedName": dn(item),
                    })
                if parsed.get("type") == "CNAME" and parsed.get("target"):
                    cname_targets.append((fqdn, str(parsed["target"]).rstrip("."), {"ttl": parsed.get("ttl_seconds", ""), "aging": parsed.get("aging_timestamp", ""), "zone": zone, "dn": dn(item)}))
        self.writer.write("18_dns_records.csv", dns_rows, ["name", "fqdn", "zone", "distinguishedName", "record", "whenCreated", "whenChanged"])
        by_name: Dict[str, List[Dict[str, Any]]] = {}
        for row in address_rows:
            by_name.setdefault(str(row["DNSName"]).casefold(), []).append(row)
        for alias, target, meta in cname_targets:
            for target_row in by_name.get(target.casefold(), []):
                address_rows.append({
                    "DNSName": alias, "IPAddress": target_row["IPAddress"],
                    "RecordType": target_row["RecordType"], "TTLSeconds": meta["ttl"],
                    "Aging": meta["aging"], "Zone": meta["zone"],
                    "Source": "CNAME_RESOLVED", "Target": target, "DistinguishedName": meta["dn"],
                })
        address_rows.sort(key=lambda row: (str(row["DNSName"]).casefold(), str(row["IPAddress"])))
        self.writer.write("18b_dns_name_to_ip.csv", address_rows, ["DNSName", "IPAddress", "RecordType", "TTLSeconds", "Aging", "Zone", "Source", "Target", "DistinguishedName"])
        seen = set()
        lines = []
        for row in address_rows:
            pair = (str(row["DNSName"]), str(row["IPAddress"]))
            if pair not in seen:
                seen.add(pair)
                lines.append(f"{pair[0]} - {pair[1]}")
        self.writer.write_text("18b_dns_name_to_ip.txt", lines)
        self.dns_address_rows = address_rows

    def shares_and_dfs(self) -> None:
        share_rows: List[Dict[str, Any]] = []
        dfs_rows: List[Dict[str, Any]] = []
        share_fields = ["distinguishedName", "name", "uNCName", "description", "whenCreated", "whenChanged"]
        for item in self.records:
            if ci_get(item, "uNCName") or "volume" in classes(item):
                share_rows.append(decoded_projection(item, share_fields, self.ads_types, self.tz))
            for blob in as_list(ci_get(item, "msDFS-TargetListv2")):
                parsed = decode_binary("msDFS-TargetListv2", blob, timezone_name=self.tz) if isinstance(blob, bytes) else blob
                dfs_rows.append({"distinguishedName": dn(item), "name": ci_get(item, "name", ""), "linkPath": ci_get(item, "msDFS-LinkPathv2", ""), "targets": parsed})
                for target in parsed.get("targets", []) if isinstance(parsed, dict) else []:
                    if target.get("path"):
                        share_rows.append({"distinguishedName": dn(item), "name": ci_get(item, "name", ""), "uNCName": target["path"], "description": "DFS target", "whenCreated": "", "whenChanged": ""})
        self.writer.write("19_published_shares.csv", share_rows, share_fields)
        self.writer.write("20_dfs_targets.csv", dfs_rows, ["distinguishedName", "name", "linkPath", "targets"])
        self.report("20a_dfs_namespaces.csv", self.with_classes("fTDfs", "msDFS-Linkv2", "msDFS-NamespaceAnchor", "msDFS-Namespacev2"), ["distinguishedName", "objectClass", "name", "description", "remoteServerName", "uNCName", "msDFS-LinkPathv2", "msDFS-TargetListv2", "msDFS-Commentv2", "msDFS-LastModifiedv2", "whenCreated", "whenChanged"])
        self.report("20b_dfsr_replication_groups.csv", self.with_classes("msDFSR-ReplicationGroup"), ["distinguishedName", "name", "description", "msDFSR-ReplicationGroupGuid", "msDFSR-ReplicationGroupType", "msDFSR-Flags", "msDFSR-MemberReference", "whenCreated", "whenChanged"])
        self.report("20c_dfsr_members.csv", self.with_classes("msDFSR-Member"), ["distinguishedName", "name", "description", "msDFSR-ComputerReference", "msDFSR-MemberReferenceBL", "msDFSR-Options", "whenCreated", "whenChanged"])
        self.report("20d_dfsr_subscriptions.csv", self.with_classes("msDFSR-Subscription"), ["distinguishedName", "name", "description", "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-Enabled", "msDFSR-ReadOnly", "msDFSR-ContentSetGuid", "msDFSR-MemberReference", "whenCreated", "whenChanged"])
        dfsr_all = [item for item in self.records if any(value.startswith("msdfsr-") or value == "dfsconfiguration" for value in classes(item))]
        self.report("20e_dfsr_all_objects.csv", dfsr_all, ["distinguishedName", "objectClass", "name", "description", "msDFSR-ReplicationGroupGuid", "msDFSR-ReplicationGroupType", "msDFSR-ComputerReference", "msDFSR-MemberReference", "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-Enabled", "msDFSR-ReadOnly", "msDFSR-ContentSetGuid", "whenCreated", "whenChanged"])

    def pki(self) -> None:
        ca_rows, template_rows, self.cert_finding_rows = analyze_certificates(self.records, self.findings, self.ads_types, self.tz)
        self.writer.write("21_certificate_authorities.csv", ca_rows, list(ca_rows[0]) if ca_rows else ["distinguishedName", "cn", "dNSHostName", "certificateTemplates", "flags", "cACertificate", "whenCreated", "whenChanged"])
        self.writer.write("22_certificate_templates.csv", template_rows, list(template_rows[0]) if template_rows else ["distinguishedName", "cn", "displayName"])
        self.writer.write("23_certificate_findings.csv", self.cert_finding_rows, ["severity", "issue", "template", "distinguishedName", "published", "low_priv_enrollment", "low_priv_write", "evidence"])

        ca_summary_rows = []
        cas = self.with_classes("pKIEnrollmentService")
        for ca in cas:
            certificates = as_list(self.field(ca, "cACertificate")) or [{}]
            for certificate in certificates:
                cert = certificate if isinstance(certificate, dict) else {}
                public_key = cert.get("public_key", {}) if isinstance(cert.get("public_key"), dict) else {}
                ca_summary_rows.append({
                    "ca_name": ci_get(ca, "cn", ""),
                    "dns_host": ci_get(ca, "dNSHostName", ""),
                    "subject": cert.get("subject", ""),
                    "issuer": cert.get("issuer", ""),
                    "not_before_jst": cert.get("not_before", ""),
                    "not_after_jst": cert.get("not_after", ""),
                    "key_algorithm": public_key.get("algorithm", ""),
                    "key_size": public_key.get("size", ""),
                    "signature_hash": cert.get("signature_hash", ""),
                    "sha256": cert.get("sha256", ""),
                    "published_templates": ci_get(ca, "certificateTemplates", ""),
                    "distinguished_name": dn(ca),
                })
        self.writer.write("21b_ca_summary.csv", ca_summary_rows, ["ca_name", "dns_host", "subject", "issuer", "not_before_jst", "not_after_jst", "key_algorithm", "key_size", "signature_hash", "sha256", "published_templates", "distinguished_name"])

        eku_names = {
            "1.3.6.1.5.5.7.3.1": "Server Authentication",
            "1.3.6.1.5.5.7.3.2": "Client Authentication",
            "1.3.6.1.5.5.7.3.3": "Code Signing",
            "1.3.6.1.5.5.7.3.4": "Secure Email",
            "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
            "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
            "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
            "2.5.29.37.0": "Any Purpose",
        }
        published = {
            str(value).casefold() for ca in cas for value in as_list(ci_get(ca, "certificateTemplates"))
        }
        template_summary_rows = []
        template_acl_rows = []
        for template in self.with_classes("pKICertificateTemplate"):
            template_name = str(ci_get(template, "cn") or ci_get(template, "name") or dn(template))
            ekus = [str(value) for value in as_list(ci_get(template, "pKIExtendedKeyUsage"))]
            name_flags = as_int(ci_get(template, "msPKI-Certificate-Name-Flag")) & 0xFFFFFFFF
            enrollment_flags = as_int(ci_get(template, "msPKI-Enrollment-Flag")) & 0xFFFFFFFF
            descriptor = ci_get(template, "nTSecurityDescriptor")
            acl_facts = template_acl_facts(descriptor)
            template_summary_rows.append({
                "template": template_name,
                "display_name": ci_get(template, "displayName", ""),
                "published": template_name.casefold() in published,
                "ekus": [f"{eku_names.get(oid, 'OID')} ({oid})" for oid in ekus] or ["Any Purpose / no EKU restriction"],
                "authentication_capable": not ekus or bool(set(ekus) & CLIENT_AUTH_EKUS),
                "enrollee_supplies_subject": bool(name_flags & 0x1),
                "manager_approval_required": bool(enrollment_flags & 0x2),
                "authorized_signatures": as_int(ci_get(template, "msPKI-RA-Signature")),
                "minimum_key_size": ci_get(template, "msPKI-Minimal-Key-Size", ""),
                "validity": self.field(template, "pKIExpirationPeriod"),
                "renewal_overlap": self.field(template, "pKIOverlapPeriod"),
                "private_key_flags": flags_text("msPKI-Private-Key-Flag", ci_get(template, "msPKI-Private-Key-Flag"), self.ads_types, self.tz),
                "low_privilege_enrollment": acl_facts["low_priv_enrollment"],
                "dangerous_low_privilege_write": acl_facts["low_priv_write"],
                "created_jst": self.field(template, "whenCreated"),
                "modified_jst": self.field(template, "whenChanged"),
                "distinguished_name": dn(template),
            })
            if not isinstance(descriptor, bytes):
                continue
            try:
                parsed_descriptor = parse_security_descriptor(descriptor)
            except Exception:
                parsed_descriptor = {}
            for ace in (parsed_descriptor.get("dacl") or {}).get("aces", []):
                trustee = ace.get("trustee", {}) if isinstance(ace.get("trustee"), dict) else {}
                trustee_sid = trustee.get("sid", "")
                rights = set(ace.get("rights", []))
                object_guid = str(ace.get("object_type_guid", "")).casefold()
                if "CONTROL_ACCESS" in rights and object_guid == ENROLL_GUID:
                    access_summary = "ENROLL"
                elif "CONTROL_ACCESS" in rights and object_guid == AUTOENROLL_GUID:
                    access_summary = "AUTOENROLL"
                elif rights & {"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"} or ("WRITE_PROPERTY" in rights and object_guid not in {ENROLL_GUID, AUTOENROLL_GUID}):
                    access_summary = "DANGEROUS_WRITE"
                elif rights and rights.issubset({"LIST_CHILDREN", "READ_PROPERTY", "LIST_OBJECT", "READ_CONTROL", "GENERIC_READ"}):
                    access_summary = "READ"
                else:
                    access_summary = "OTHER"
                template_acl_rows.append({
                    "template": template_name,
                    "ace_type": ace.get("type", ""),
                    "trustee_sid": trustee_sid,
                    "trustee_name": trustee.get("well_known_name", ""),
                    "access_summary": access_summary,
                    "rights": ace.get("rights", []),
                    "object_type_name": {ENROLL_GUID: "Certificate-Enrollment", AUTOENROLL_GUID: "Certificate-Autoenrollment"}.get(object_guid, ""),
                    "object_type_guid": ace.get("object_type_guid", ""),
                    "inheritance_flags": ace.get("flags", []),
                    "low_privileged": low_priv_sid(str(trustee_sid)),
                    "distinguished_name": dn(template),
                })
        self.writer.write("22b_certificate_template_summary.csv", template_summary_rows, [
            "template", "display_name", "published", "ekus", "authentication_capable",
            "enrollee_supplies_subject", "manager_approval_required", "authorized_signatures",
            "minimum_key_size", "validity", "renewal_overlap", "private_key_flags",
            "low_privilege_enrollment", "dangerous_low_privilege_write", "created_jst",
            "modified_jst", "distinguished_name",
        ])
        self.writer.write("22c_certificate_template_acl.csv", template_acl_rows, ["template", "ace_type", "trustee_sid", "trustee_name", "access_summary", "rights", "object_type_name", "object_type_guid", "inheritance_flags", "low_privileged", "distinguished_name"])
        self.template_acl_rows = template_acl_rows

    def service_accounts_and_secrets(self) -> None:
        self.report("24_managed_service_accounts.csv", self.with_classes("msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"), ["distinguishedName", "objectClass", "sAMAccountName", "servicePrincipalName", "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval", "msDS-SupportedEncryptionTypes", "pwdLastSet", "whenCreated", "whenChanged"])
        laps_fields = ["distinguishedName", "sAMAccountName", "dNSHostName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"]
        secret_fields = {"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"}
        laps_rows = []
        for item in self.records:
            if ci_get(item, "ms-Mcs-AdmPwdExpirationTime") is None and ci_get(item, "msLAPS-PasswordExpirationTime") is None:
                continue
            row = decoded_projection(item, [field for field in laps_fields if field not in secret_fields], self.ads_types, self.tz)
            for field in secret_fields:
                row[field] = report_value(field, ci_get(item, field, ""), self.ads_types, self.tz, self.args.include_sensitive_values)
            laps_rows.append(row)
        self.writer.write("25_laps_inventory.csv", laps_rows, laps_fields)
        self.report("26_bitlocker_inventory.csv", self.with_classes("msFVE-RecoveryInformation"), ["distinguishedName", "name", "msFVE-RecoveryGuid", "msFVE-VolumeGuid", "msFVE-RecoveryPassword", "whenCreated", "whenChanged"])
        self.report("27_quotas.csv", [item for item in self.records if "msds-quotacontrol" in classes(item) or ci_get(item, "msDS-DefaultQuota") is not None], ["distinguishedName", "name", "msDS-QuotaTrustee", "msDS-DefaultQuota", "msDS-QuotaEffective", "msDS-QuotaUsed", "whenCreated", "whenChanged"])

    def schema_and_attribute_scan(self, reader: SnapshotReader, notify: Callable[..., None]) -> None:
        schema_attrs = self.with_classes("attributeSchema")
        schema_fields = ["distinguishedName", "lDAPDisplayName", "attributeID", "attributeSyntax", "oMSyntax", "isSingleValued", "systemOnly", "isDefunct", "searchFlags", "systemFlags", "schemaIDGUID", "attributeSecurityGUID", "isMemberOfPartialAttributeSet", "whenCreated", "whenChanged"]
        self.report("28_schema_attributes.csv", schema_attrs, schema_fields)
        # FLAG_SCHEMA_BASE_OBJECT (0x10) distinguishes the base AD schema from
        # later Microsoft, vendor, and organisation-specific schema extensions.
        custom_schema = [item for item in schema_attrs if not (as_int(ci_get(item, "systemFlags")) & 0x10)]
        self.report("29_custom_schema_attributes.csv", custom_schema, schema_fields)

        schema_by_name = {
            str(ci_get(item, "lDAPDisplayName", "")).casefold(): item
            for item in schema_attrs if ci_get(item, "lDAPDisplayName")
        }
        custom_schema_names = {
            str(ci_get(item, "lDAPDisplayName", "")).casefold()
            for item in custom_schema if ci_get(item, "lDAPDisplayName")
        }
        available = set(self.ads_types)
        sensitive_value_rows: List[Dict[str, Any]] = []
        interesting_value_rows: List[Dict[str, Any]] = []
        free_text_rows: List[Dict[str, Any]] = []
        sensitive_populated: Counter = Counter()
        unknown_rows: List[Dict[str, Any]] = []
        # Per custom attribute: how many objects populate it and a few samples,
        # so the viewer can show which schema extensions are actually in use.
        custom_usage: Dict[str, Dict[str, Any]] = {}
        # Read only reportable attributes plus every type that the snapshot
        # reader represents as bytes, so unknown-binary coverage is preserved
        # without materialising ordinary directory strings a second time.
        binary_ads_types = {8, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28}
        free_text_names = {"description", "info", "comment", "notes"}
        core_names = {"distinguishedname", "objectclass", "name", "samaccountname"}
        scan_attributes = [
            prop.name for prop in reader.properties
            if prop.name.casefold() in core_names | free_text_names | HIGH_INTEREST_ATTRIBUTES | custom_schema_names
            or is_sensitive_attribute(prop.name)
            or prop.ads_type in binary_ads_types
        ]
        total = max(1, reader.header.num_objects)
        interval = max(1, total // 100)
        notify("Scanning sensitive and custom attributes", 0, total)
        print("[enum 3/5] Scanning interesting, custom, sensitive, and binary attributes…", file=sys.stderr, flush=True)
        for object_index, entry in enumerate(reader.iter_entries(), start=1):
            raw = entry.to_dict(scan_attributes, decode=False)
            item_classes = classes(raw)
            is_schema_definition = bool(item_classes & {"attributeschema", "classschema"})
            item_type = "computer" if "computer" in item_classes else "user" if "user" in item_classes else "; ".join(sorted(item_classes))
            item_name = object_name(raw)
            item_dn = dn(raw)
            for name, value in raw.items():
                low_name = name.casefold()
                sensitive = is_sensitive_attribute(name)
                custom = low_name in custom_schema_names
                high_interest = low_name in HIGH_INTEREST_ATTRIBUTES
                free_text = low_name in free_text_names
                if sensitive or high_interest or free_text or (custom and not is_schema_definition):
                    schema = schema_by_name.get(low_name, {})
                    attribute_row = {
                        "object": item_name,
                        "object_type": item_type,
                        "distinguished_name": item_dn,
                        "attribute": name,
                        "classification": (
                            "SENSITIVE" if sensitive else
                            "EXTENSION_OR_CUSTOM_SCHEMA" if custom else
                            "HIGH_INTEREST" if high_interest else "STANDARD"
                        ),
                        "schema_oid": ci_get(schema, "attributeID", ""),
                        "attribute_syntax": ci_get(schema, "attributeSyntax", ""),
                        "ads_type": self.ads_types.get(low_name, ""),
                        "value_count": len(as_list(value)),
                        "value": report_value(name, value, self.ads_types, self.tz, self.args.include_sensitive_values),
                    }
                    if custom and not is_schema_definition:
                        usage = custom_usage.get(low_name)
                        if usage is None:
                            usage = custom_usage[low_name] = {
                                "attribute": name, "populated_objects": 0, "object_types": Counter(),
                                "schema_oid": attribute_row["schema_oid"], "attribute_syntax": attribute_row["attribute_syntax"],
                                "samples": [], "sensitive": sensitive,
                            }
                        usage["populated_objects"] += 1
                        usage["object_types"][item_type] += 1
                        if len(usage["samples"]) < 3:
                            sample = cell(attribute_row["value"])
                            usage["samples"].append(sample[:120] + ("…" if len(sample) > 120 else ""))
                    if sensitive:
                        sensitive_populated[low_name] += 1
                        sensitive_value_rows.append({**attribute_row, "custom_schema": custom})
                    if sensitive or high_interest or (custom and not is_schema_definition):
                        interesting_value_rows.append(attribute_row)
                    if free_text:
                        free_text_rows.append(attribute_row)
                for binary in as_list(value):
                    if not isinstance(binary, bytes):
                        continue
                    parsed = decode_binary(name, binary, self.ads_types.get(low_name), self.tz)
                    if isinstance(parsed, dict) and parsed.get("type") == "UNPARSED_BINARY":
                        unknown_rows.append({
                            "distinguishedName": item_dn,
                            "attribute": name,
                            "expected_type": parsed.get("expected_type", ""),
                            "length": parsed.get("length", 0),
                            "sha256": parsed.get("sha256", ""),
                            "hex_preview": str(parsed.get("hex", ""))[:256],
                            "parse_error": parsed.get("parse_error", ""),
                        })
            if object_index == 1 or object_index % interval == 0 or object_index == total:
                percent = min(100, object_index * 100 // total)
                notify("Scanning sensitive and custom attributes", object_index, total)
                print(f"\r[enum 3/5] Attribute scan: {object_index:,}/{total:,} ({percent}%)", end="", file=sys.stderr, flush=True)
        print(file=sys.stderr, flush=True)

        attribute_fields = ["object", "object_type", "distinguished_name", "attribute", "classification", "schema_oid", "attribute_syntax", "ads_type", "value_count", "value"]
        self.writer.write("31_sensitive_attribute_values.csv", sensitive_value_rows, attribute_fields + ["custom_schema"])
        self.writer.write("32_interesting_directory_values.csv", interesting_value_rows, attribute_fields)
        self.writer.write("33_free_text_values.csv", free_text_rows, attribute_fields)

        sensitive_schema_names = set(SENSITIVE_ATTRIBUTES)
        sensitive_schema_names.update(name for name in schema_by_name if is_sensitive_attribute(name))
        sensitive_schema_names.update(name for name in available if is_sensitive_attribute(name))
        schema_rows = []
        for low_name in sorted(sensitive_schema_names):
            schema = schema_by_name.get(low_name, {})
            search_flags = as_int(ci_get(schema, "searchFlags"))
            schema_rows.append({
                "attribute": ci_get(schema, "lDAPDisplayName", "") or SENSITIVE_ATTRIBUTE_DISPLAY_NAMES.get(low_name, low_name),
                "captured_property_definition": low_name in available,
                "schema_object_present": bool(schema),
                "schema_oid": ci_get(schema, "attributeID", ""),
                "attribute_syntax": ci_get(schema, "attributeSyntax", ""),
                "system_only": ci_get(schema, "systemOnly", ""),
                "confidential_search_flag": bool(search_flags & 0x80),
                "custom_schema": low_name in custom_schema_names,
                "populated_objects": sensitive_populated[low_name],
                "value_handling": "INCLUDED AS CAPTURED" if self.args.include_sensitive_values else "REDACTED; LENGTH AND SHA-256 ONLY",
                "ldap_filter": f"({ci_get(schema, 'lDAPDisplayName', '') or SENSITIVE_ATTRIBUTE_DISPLAY_NAMES.get(low_name, low_name)}=*)" if low_name in available else "",
            })
        self.writer.write("31_sensitive_attribute_schema.csv", schema_rows, ["attribute", "captured_property_definition", "schema_object_present", "schema_oid", "attribute_syntax", "system_only", "confidential_search_flag", "custom_schema", "populated_objects", "value_handling", "ldap_filter"])
        self.sensitive_schema_rows = schema_rows
        self.writer.write("30_unknown_binary.csv", unknown_rows, ["distinguishedName", "attribute", "expected_type", "length", "sha256", "hex_preview", "parse_error"])

        usage_rows = []
        for usage in sorted(custom_usage.values(), key=lambda item: (-item["populated_objects"], item["attribute"].casefold())):
            usage_rows.append({
                "attribute": usage["attribute"],
                "populated_objects": usage["populated_objects"],
                "object_types": "; ".join(f"{kind} ({count})" for kind, count in usage["object_types"].most_common(4)),
                "sensitive": usage["sensitive"],
                "schema_oid": usage["schema_oid"],
                "attribute_syntax": usage["attribute_syntax"],
                "sample_values": " | ".join(usage["samples"]),
                "ldap_filter": f"({usage['attribute']}=*)",
            })
        # Custom attributes defined in the schema but never populated are listed
        # too, so the table doubles as a complete inventory of the extension.
        used = set(custom_usage)
        for item in sorted(custom_schema, key=lambda item: str(ci_get(item, "lDAPDisplayName", "")).casefold()):
            display = str(ci_get(item, "lDAPDisplayName", ""))
            if not display or display.casefold() in used or display.casefold() not in available:
                continue
            usage_rows.append({
                "attribute": display, "populated_objects": 0, "object_types": "", "sensitive": is_sensitive_attribute(display),
                "schema_oid": ci_get(item, "attributeID", ""), "attribute_syntax": ci_get(item, "attributeSyntax", ""),
                "sample_values": "", "ldap_filter": f"({display}=*)",
            })
        self.writer.write("34_custom_attribute_usage.csv", usage_rows, ["attribute", "populated_objects", "object_types", "sensitive", "schema_oid", "attribute_syntax", "sample_values", "ldap_filter"])
        self.custom_usage_rows = usage_rows


def _delegation_kinds(item: Dict[str, Any]) -> List[str]:
    kinds = []
    if has_uac(item, "UNCONSTRAINED_DELEGATION"):
        kinds.append("UNCONSTRAINED_DC_DEFAULT" if has_uac(item, "DOMAIN_CONTROLLER") else "UNCONSTRAINED")
    if as_list(ci_get(item, "msDS-AllowedToDelegateTo")):
        kinds.append("CONSTRAINED")
    if ci_get(item, "msDS-AllowedToActOnBehalfOfOtherIdentity"):
        kinds.append("RBCD")
    if has_uac(item, "PROTOCOL_TRANSITION"):
        kinds.append("PROTOCOL_TRANSITION")
    return kinds


def _snapshot_metadata(reader: SnapshotReader, snapshot: Path, args: argparse.Namespace, database_path: Path) -> Dict[str, Any]:
    return {
        "snapshot": str(snapshot),
        "server": reader.header.server,
        "description": reader.header.description,
        "captured_jst": format_datetime(reader.header.captured_at, args.timezone),
        "captured_utc": reader.header.captured_at.isoformat(),
        "objects": reader.header.num_objects,
        "attributes": reader.header.num_attributes,
        "timezone": args.timezone,
        "sensitive_values_included": args.include_sensitive_values,
        "output_mode": args.output_mode,
        "database": str(database_path) if args.output_mode != "csv" else "",
    }


def _write_summary(output: Path, snapshot: Path, metadata: Dict[str, Any], findings: List[Dict[str, str]], counts: Dict[str, int]) -> Counter:
    finding_counts = Counter(item["severity"] for item in findings)
    lines = [
        f"# AD Explorer snapshot audit: {output.name}", "",
        f"- Snapshot: `{snapshot}`",
        f"- Captured: {metadata['captured_jst']}",
        f"- Server: {metadata['server'] or 'N/A'}",
        f"- Objects: {metadata['objects']}",
        f"- Findings: {len(findings)} (HIGH {finding_counts['HIGH']}, MEDIUM {finding_counts['MEDIUM']}, LOW {finding_counts['LOW']})",
        f"- Sensitive values included: {metadata['sensitive_values_included']}", "",
        "## Start here", "",
    ]
    for label, name in (
        ("Security findings", "01_findings.csv"),
        ("Readable user inventory", "07b_users_summary.csv"),
        ("Account logon and workstation restrictions", "07d_account_restrictions.csv"),
        ("Readable SPN-user inventory", "08b_spn_users_summary.csv"),
        ("Readable computer inventory", "10b_computers_summary.csv"),
        ("Delegation summary", "11b_delegation_summary.csv"),
        ("Flattened group membership", "12b_group_membership.csv"),
        ("GPO status and links", "14b_gpo_summary.csv"),
        ("DNS name-to-IP text map", "18b_dns_name_to_ip.txt"),
        ("Legacy DFS namespaces and targets", "20a_dfs_namespaces.csv"),
        ("DFSR replication groups", "20b_dfsr_replication_groups.csv"),
        ("DFSR subscriptions and local paths", "20d_dfsr_subscriptions.csv"),
        ("CA certificate summary", "21b_ca_summary.csv"),
        ("Certificate-template summary", "22b_certificate_template_summary.csv"),
        ("Certificate-template ACLs", "22c_certificate_template_acl.csv"),
        ("Sensitive-attribute schema checklist", "31_sensitive_attribute_schema.csv"),
        ("Populated sensitive attributes", "31_sensitive_attribute_values.csv"),
        ("Extension/custom and high-interest values", "32_interesting_directory_values.csv"),
        ("Descriptions, comments, notes, and info", "33_free_text_values.csv"),
    ):
        lines.append(f"- [{label}]({report_relative_path(name)})")
    lines.extend(["", "## Report inventory", ""])
    lines.extend(f"- `{report_relative_path(name)}`: {count} rows" for name, count in sorted(counts.items()))
    lines.extend([
        "", "## Scope limitations", "",
        "- Published AD shares and DFS targets are reported. Host-local SMB shares are not stored in an AD Explorer snapshot.",
        "- AD CS checks cover directory-visible templates and PKI-object ACLs (ESC1-ESC5-like). CA registry permissions/settings and HTTP enrollment endpoints (including ESC6-ESC8 conditions) require separate validation.",
        "- LAPS ACL findings identify obvious exposure to well-known low-privilege groups. Validate custom delegated password-reader and decryption groups against the organization's intended support model.",
        "- Key credentials can be legitimate Windows Hello/key-trust data; findings on sensitive principals require correlation with enrollment and device records.",
        "- `lastLogonTimestamp` is replicated but approximate; `lastLogon` is specific to the captured domain controller.",
        "- Sensitive password/recovery values are included by default. Use `--redact-sensitive-values` before producing a shareable bundle.",
        "- Review `30_unknown_binary.csv`; unfamiliar or vendor-specific blobs are retained with hashes and previews.",
    ])
    (output / "00_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
    return finding_counts


def main(
    argv: Optional[Sequence[str]] = None,
    progress: Optional[ProgressCallback] = None,
    index_status: Optional[Any] = None,
) -> int:
    args = parse_args(argv)

    def notify(stage: str, completed: int = 0, total: int = 0) -> None:
        if progress:
            progress(stage, completed, total)

    snapshot = Path(args.snapshot).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    database_path = Path(args.database).expanduser().resolve() if args.database else output / f"{output.name}.sqlite3"
    emit_csv = bool(args.csv_reports) or args.output_mode == "csv"
    report_dir = output / "reports"
    writer = ReportWriter(report_dir, emit_csv)

    if args.output_mode == "sqlite":
        print(f"[enum sqlite] Reading snapshot metadata: {snapshot}", file=sys.stderr, flush=True)
        with SnapshotReader(snapshot, parse_object_offsets=False) as reader:
            metadata = _snapshot_metadata(reader, snapshot, args, database_path)
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8-sig")
        row_count = write_snapshot_sqlite(snapshot, args.timezone, database_path, status=index_status)
        print(f"SQLite-only index complete: {database_path}")
        print(f"Decoded objects: {row_count:,}")
        return 0

    notify("Opening snapshot for security audit")
    print(f"[enum 1/5] Opening snapshot: {snapshot}", file=sys.stderr, flush=True)
    with SnapshotReader(snapshot) as reader:
        total_objects = max(1, reader.header.num_objects)

        def load_progress(index: int, total: int) -> None:
            notify("Loading objects for security audit", index, total)
            print(f"\r[enum 1/5] Loading directory objects: {index:,}/{total:,} ({min(100, index * 100 // total)}%)", end="", file=sys.stderr, flush=True)

        notify("Loading objects for security audit", 0, total_objects)
        directory = load_directory(reader, progress=load_progress)
        print(file=sys.stderr, flush=True)
        notify("Building security and inventory reports", total_objects, total_objects)
        print("[enum 2/5] Building focused security and inventory reports…", file=sys.stderr, flush=True)
        metadata = _snapshot_metadata(reader, snapshot, args, database_path)
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8-sig")

        audit = Audit(directory, args, writer)
        domains = audit.domains()
        users = audit.users()
        audit.privileged_and_acls(domains)
        audit.account_findings(users)
        audit.computers()
        audit.delegation()
        audit.groups_and_trusts()
        audit.group_policy()
        audit.dns()
        audit.shares_and_dfs()
        audit.pki()
        audit.service_accounts_and_secrets()
        audit.schema_and_attribute_scan(reader, notify)

        notify("Finalizing audit findings", total_objects, total_objects)
        print("[enum 4/5] Finalizing findings and report index…", file=sys.stderr, flush=True)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = audit.findings
        findings.sort(key=lambda item: (severity_order.get(item["severity"], 9), item["category"], item["title"], item["object"]))
        writer.write("01_findings.csv", findings, ["severity", "category", "title", "object", "evidence", "recommendation"])
        finding_counts = _write_summary(output, snapshot, metadata, findings, writer.counts)

        if args.output_mode == "both":
            notify("Building searchable database", 0, total_objects)
            print("[enum sqlite] Indexing decoded snapshot objects…", file=sys.stderr, flush=True)
            dns_rows = [{
                "dns_and_ip": f"{row.get('DNSName', '')} - {row.get('IPAddress', '')}",
                "dns_name": row.get("DNSName", ""), "ip_address": row.get("IPAddress", ""),
                "record_type": row.get("RecordType", ""), "ttl_seconds": row.get("TTLSeconds", ""),
                "aging": row.get("Aging", ""), "zone": row.get("Zone", ""),
                "source": row.get("Source", ""), "target": row.get("Target", ""),
                "distinguished_name": row.get("DistinguishedName", ""),
            } for row in audit.dns_address_rows]
            certificate_findings = [
                {**row, "distinguished_name": row.get("distinguishedName", "")} for row in audit.cert_finding_rows
            ]
            # Release the audit records before the index build allocates.
            audit.release()
            del directory, users, domains
            write_snapshot_sqlite(
                snapshot, args.timezone, database_path,
                audit_tables=(
                    findings, audit.dangerous_acl_rows, audit.rbcd_rows,
                    audit.privileged_member_rows, dns_rows, audit.template_acl_rows,
                    certificate_findings, audit.custom_usage_rows, audit.sensitive_schema_rows,
                ),
                status=index_status,
            )
    print(f"Audit complete: {output}")
    print(f"Findings: HIGH={finding_counts['HIGH']} MEDIUM={finding_counts['MEDIUM']} LOW={finding_counts['LOW']}")
    notify("Audit and database complete", total_objects, total_objects)
    print("[enum 5/5] Audit reports complete.", file=sys.stderr, flush=True)
    return 0
