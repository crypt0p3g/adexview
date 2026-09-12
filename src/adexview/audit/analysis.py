"""Security analyses that produce findings and evidence tables.

Every function takes plain record dictionaries (or audit :class:`Record`
objects) so the checks can be unit-tested with hand-built fixtures.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from ..decoders import FILETIME_EPOCH, describe_sid, parse_security_descriptor, parse_sid
from .records import (
    as_int, as_list, build_by_dn, ci_get, classes, dn, dn_key, has_uac, is_computer,
    is_user, object_name, sid_string,
)
from .reports import add_aggregate_finding, add_finding, cell, decoded_projection

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
    "2.5.29.37.0",
}
ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Extended-right and property GUIDs whose grant to a non-privileged principal
# enables a concrete AD attack. All lower-case to match decoded ACE GUIDs.
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_WRITE_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"
GUID_WRITE_ALLOWED_TO_ACT = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

# Full-control write rights: any one lets the trustee take over the object.
DANGEROUS_FULL_RIGHTS = {"GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER"}

# Trustees that legitimately hold control over privileged objects.
EXPECTED_PRIVILEGED_SIDS = {
    "S-1-5-18",       # LOCAL SYSTEM
    "S-1-5-9",        # Enterprise Domain Controllers
    "S-1-3-0",        # CREATOR OWNER
    "S-1-5-10",       # SELF (principal self)
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-32-548",   # BUILTIN\Account Operators
    "S-1-5-32-549",   # BUILTIN\Server Operators
    "S-1-5-32-550",   # BUILTIN\Print Operators
    "S-1-5-32-551",   # BUILTIN\Backup Operators
    "S-1-5-32-552",   # BUILTIN\Replicator
}
# Domain-relative RIDs of admin-tier principals (Domain Admins, Enterprise
# Admins, Schema Admins, Administrator, controllers, key admins, RODCs).
EXPECTED_PRIVILEGED_RIDS = {
    "500", "512", "516", "518", "519", "520", "521", "526", "527", "498",
}
# Domain-relative RIDs of the privileged groups that are attack targets.
PRIVILEGED_GROUP_RIDS = {"512", "516", "518", "519", "520", "521", "526", "527"}

TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
TRUST_ATTRIBUTE_USES_RC4 = 0x00000080
TRUST_DIRECTION_OUTBOUND = 0x00000002  # The primary domain trusts the named domain.
KERBEROS_AES_MASK = 0x00000008 | 0x00000010 | 0x00000200
KERBEROS_DES_MASK = 0x00000001 | 0x00000002
LAPS_ENCRYPTED_PROPERTY_SET_GUID = "f3531ec6-6330-4f8e-8d39-7a671fbac605"

SECRET_IN_TEXT_PATTERN = re.compile(r"(?i)\b(pass(word|wd)?|secret|token|credential|api[-_ ]?key)\b")


def is_expected_privileged_trustee(sid: str) -> bool:
    """Whether an ACE granted to ``sid`` is expected on a privileged object."""
    if not sid:
        return True  # unparseable trustee: do not raise a finding on noise
    if sid in EXPECTED_PRIVILEGED_SIDS:
        return True
    return sid.rsplit("-", 1)[-1] in EXPECTED_PRIVILEGED_RIDS


def low_priv_sid(sid: str) -> bool:
    if sid in {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}:
        return True
    return sid.endswith("-513") or sid.endswith("-515")


def sid_display(sid: str, by_sid: Dict[str, Dict[str, Any]]) -> str:
    """Resolve a SID to a readable name via well-known names then the snapshot."""
    known = describe_sid(sid)
    if known:
        return known
    principal = by_sid.get(sid)
    if principal is not None:
        return object_name(principal)
    return ""


def filetime_datetime(value: Any) -> Optional[dt.datetime]:
    raw = as_int(value)
    if raw in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    try:
        return FILETIME_EPOCH + dt.timedelta(microseconds=raw // 10)
    except (OverflowError, ValueError):
        return None


def dns_node_fqdn(name: Any, distinguished_name: str) -> Tuple[str, str]:
    """Return (fqdn, zone) for a dnsNode DN."""
    node = str(name or "")
    dns_prefix = distinguished_name.split(",CN=MicrosoftDNS", 1)[0]
    dc_values = re.findall(r"(?:^|,)DC=([^,]+)", dns_prefix, flags=re.IGNORECASE)
    if dc_values:
        node = dc_values[0]
    zone = dc_values[1] if len(dc_values) > 1 else ""
    if zone.casefold() == "rootdnsservers":
        return ("." if node == "@" else node.rstrip("."), zone)
    if node == "@":
        return zone.rstrip("."), zone
    if not zone or node.casefold().endswith("." + zone.casefold()) or node.casefold() == zone.casefold():
        return node.rstrip("."), zone
    return f"{node}.{zone}".rstrip("."), zone


def _guid_text(value: Any) -> str:
    """Return a normalized schema/ACE GUID without assuming decoded input."""
    if isinstance(value, bytes) and len(value) == 16:
        try:
            return str(uuid.UUID(bytes_le=value)).casefold()
        except ValueError:
            return ""
    text = str(value or "").strip("{}")
    try:
        return str(uuid.UUID(text)).casefold()
    except ValueError:
        return text.casefold()


def _schema_attribute_guids(records: List[Dict[str, Any]]) -> Dict[str, str]:
    return {
        str(ci_get(item, "lDAPDisplayName", "")).casefold(): _guid_text(ci_get(item, "schemaIDGUID"))
        for item in records
        if "attributeschema" in classes(item) and ci_get(item, "lDAPDisplayName")
    }


def _sid_values(record: Dict[str, Any], attribute: str) -> List[str]:
    result = []
    for value in as_list(ci_get(record, attribute, [])):
        if isinstance(value, bytes):
            try:
                result.append(parse_sid(value))
            except ValueError:
                continue
        elif value:
            result.append(str(value))
    return result


def _allowed_aces(descriptor: Any):
    """Yield (sid, rights, object_type_guid, ace) for every allowed ACE in a descriptor."""
    if not isinstance(descriptor, bytes):
        return
    try:
        parsed = parse_security_descriptor(descriptor)
    except Exception:
        return
    for ace in (parsed.get("dacl") or {}).get("aces", []):
        if not str(ace.get("type", "")).startswith("ACCESS_ALLOWED"):
            continue
        trustee = ace.get("trustee", {})
        sid = trustee.get("sid", "") if isinstance(trustee, dict) else ""
        yield sid, set(ace.get("rights", [])), str(ace.get("object_type_guid", "")).casefold(), ace


def _last_activity(record: Dict[str, Any]) -> Optional[dt.datetime]:
    values = [
        filetime_datetime(ci_get(record, "lastLogonTimestamp")),
        filetime_datetime(ci_get(record, "pwdLastSet")),
    ]
    present = [value for value in values if value is not None]
    return max(present) if present else None


# -- group membership ---------------------------------------------------------------


def build_domain_admins(records: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], str]]:
    by_dn = build_by_dn(records)
    da_groups = [
        item for item in records
        if "group" in classes(item) and sid_string(item).endswith("-512")
    ]
    output: Dict[str, Tuple[Dict[str, Any], str]] = {}

    def walk(group: Dict[str, Any], path: List[str], visited: Set[str]) -> None:
        group_dn = dn_key(group)
        if group_dn in visited:
            return
        visited.add(group_dn)
        for member_dn in as_list(ci_get(group, "member", [])):
            member = by_dn.get(str(member_dn).casefold())
            if not member:
                continue
            next_path = path + [object_name(member)]
            if "group" in classes(member):
                walk(member, next_path, visited)
            else:
                output[dn_key(member)] = (member, " -> ".join(next_path))
        visited.discard(group_dn)

    for group in da_groups:
        walk(group, [object_name(group)], set())
    for item in records:
        if is_user(item) and as_int(ci_get(item, "primaryGroupID")) == 512:
            output.setdefault(dn_key(item), (item, "primaryGroupID=512"))
    return sorted(output.values(), key=lambda pair: object_name(pair[0]).casefold())


def build_privileged_group_members(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten the three principal AD administrative groups recursively."""
    by_dn = build_by_dn(records)
    targets: List[Tuple[Dict[str, Any], str]] = []
    for item in records:
        if "group" not in classes(item):
            continue
        sid = sid_string(item)
        if sid.endswith("-512"):
            targets.append((item, "Domain Admins"))
        elif sid.endswith("-519"):
            targets.append((item, "Enterprise Admins"))
        elif sid == "S-1-5-32-544":
            targets.append((item, "Administrators"))

    output: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(root: Dict[str, Any], label: str, member: Dict[str, Any], path: List[str]) -> None:
        member_classes = classes(member)
        output[(sid_string(root), dn_key(member))] = {
            "privileged_group": label,
            "group_sid": sid_string(root),
            "account": object_name(member),
            "account_type": (
                "group" if "group" in member_classes else
                "computer" if "computer" in member_classes else
                "user" if "user" in member_classes else "object"
            ),
            "sam_account_name": ci_get(member, "sAMAccountName", ""),
            "user_principal_name": ci_get(member, "userPrincipalName", ""),
            "enabled": not has_uac(member, "DISABLED") if member_classes & {"user", "computer"} else "",
            "membership_path": " -> ".join(path),
            "distinguished_name": dn(member),
        }

    def walk(root, label, group, path, visited: Set[str]) -> None:
        group_dn = dn_key(group)
        if group_dn in visited:
            return
        visited.add(group_dn)
        for member_dn in as_list(ci_get(group, "member", [])):
            member = by_dn.get(str(member_dn).casefold())
            if not member:
                continue
            next_path = [*path, object_name(member)]
            add(root, label, member, next_path)
            if "group" in classes(member):
                walk(root, label, member, next_path, visited)
        visited.discard(group_dn)

    for group, label in targets:
        walk(group, label, group, [label], set())

    # Primary-group membership is not present in a group's member attribute.
    for member in records:
        if not is_user(member):
            continue
        primary = as_int(ci_get(member, "primaryGroupID"))
        label = {512: "Domain Admins", 519: "Enterprise Admins"}.get(primary)
        if not label:
            continue
        root = next((group for group, name in targets if name == label), None)
        if root:
            add(root, label, member, [label, "primaryGroupID", object_name(member)])

    return sorted(
        output.values(),
        key=lambda row: (row["privileged_group"].casefold(), row["account"].casefold()),
    )


# -- trust, crypto, LAPS, key-credential and privileged-account hygiene ----------------


def analyze_additional_security(
    records: List[Dict[str, Any]], findings: List[Dict[str, str]],
    capture_time: dt.datetime, stale_days: int,
    privileged_dns: Set[str], by_sid: Dict[str, Dict[str, Any]],
) -> None:
    """Add snapshot-verifiable trust, crypto, LAPS, key, and admin findings.

    The checks deliberately avoid claiming CA registry/HTTP conditions or
    malicious key credentials, because an AD Explorer snapshot cannot prove
    those facts. Aggregate hygiene findings keep large domains usable.
    """
    if capture_time.tzinfo is None:
        capture_time = capture_time.replace(tzinfo=dt.timezone.utc)
    cutoff = capture_time - dt.timedelta(days=stale_days)
    schema_guids = _schema_attribute_guids(records)
    privileged_dns = {value.casefold() for value in privileged_dns if value}

    # External trusts that allow the named domain to authenticate to the local
    # domain need the quarantine bit for SID filtering. Forest/internal trusts
    # follow different SID-filtering rules and are not inferred as unsafe here.
    for trust in (item for item in records if "trusteddomain" in classes(item)):
        attributes = as_int(ci_get(trust, "trustAttributes")) & 0xFFFFFFFF
        direction = as_int(ci_get(trust, "trustDirection"))
        trust_type = as_int(ci_get(trust, "trustType"))
        target = str(ci_get(trust, "trustPartner") or object_name(trust))
        external = trust_type == 2 and not attributes & (
            TRUST_ATTRIBUTE_FOREST_TRANSITIVE | TRUST_ATTRIBUTE_WITHIN_FOREST
        )
        if external and direction & TRUST_DIRECTION_OUTBOUND and not attributes & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN:
            add_finding(
                findings, "HIGH", "Trust", "External inbound authentication lacks the SID-filtering quarantine flag",
                target,
                f"trustDirection={direction}; trustType={trust_type}; trustAttributes=0x{attributes:08x}",
                "Validate the trust direction and enable SID filtering (quarantine) unless a documented migration exception requires SIDHistory.",
            )
        if attributes & TRUST_ATTRIBUTE_USES_RC4:
            add_finding(
                findings, "MEDIUM", "Trust", "Domain trust is configured to use RC4",
                target, f"trustAttributes includes USES_RC4_ENCRYPTION (0x{attributes:08x})",
                "Confirm both sides support AES and remove the RC4 trust attribute after compatibility testing.",
            )

    # SIDHistory is useful during migrations but can carry privileged SIDs.
    ordinary_sid_history: List[str] = []
    for item in records:
        history = _sid_values(item, "sIDHistory")
        if not history:
            continue
        privileged_history = any(sid.rsplit("-", 1)[-1] in EXPECTED_PRIVILEGED_RIDS for sid in history)
        item_privileged = dn_key(item) in privileged_dns or as_int(ci_get(item, "adminCount")) == 1
        if privileged_history or item_privileged:
            add_finding(
                findings, "HIGH", "Trust", "Privileged SIDHistory requires validation",
                object_name(item), f"sIDHistory={'; '.join(history)}",
                "Confirm every historical SID is required for a controlled migration and remove obsolete privileged SIDHistory values.",
            )
        else:
            ordinary_sid_history.append(f"{object_name(item)} ({'; '.join(history)})")
    add_aggregate_finding(
        findings, "MEDIUM", "Trust", "Directory objects retain SIDHistory",
        ordinary_sid_history, "SIDHistory can extend access across migrations",
        "Validate the migration requirement and remove SIDHistory after dependent ACLs are translated.",
    )

    users = [item for item in records if is_user(item)]
    computers = [item for item in records if is_computer(item)]
    enabled_services = [
        item for item in [*users, *computers]
        if not has_uac(item, "DISABLED") and (
            is_computer(item) or as_list(ci_get(item, "servicePrincipalName"))
        )
    ]
    no_aes, des_enabled = [], []
    for item in enabled_services:
        encryption = as_int(ci_get(item, "msDS-SupportedEncryptionTypes")) & 0xFFFFFFFF
        name = object_name(item)
        if not encryption & KERBEROS_AES_MASK:
            no_aes.append(f"{name} (0x{encryption:08x})")
        if encryption & KERBEROS_DES_MASK or has_uac(item, "DES_ONLY"):
            des_enabled.append(f"{name} (0x{encryption:08x})")
    add_aggregate_finding(
        findings, "MEDIUM", "Kerberos", "Enabled Kerberos service principals lack AES support",
        no_aes, "msDS-SupportedEncryptionTypes has no AES bit; zero or absent values default to RC4 for service tickets",
        "Enable AES keys, rotate the account password after AES support is enabled, and monitor RC4 ticket issuance before disabling RC4.",
    )
    add_aggregate_finding(
        findings, "HIGH", "Kerberos", "Kerberos service principals permit DES",
        des_enabled, "DES encryption bits or the DES-only account flag are present",
        "Remove DES support and rotate affected account keys.",
    )

    stale_computers, stale_dcs = [], []
    for computer in computers:
        if has_uac(computer, "DISABLED"):
            continue
        activity = _last_activity(computer)
        if activity is None or activity >= cutoff:
            continue
        label = f"{object_name(computer)} (last activity {activity.date().isoformat()})"
        (stale_dcs if has_uac(computer, "DOMAIN_CONTROLLER") else stale_computers).append(label)
    add_aggregate_finding(
        findings, "LOW", "Computer", f"Enabled computers inactive for more than {stale_days} days",
        stale_computers, "Both lastLogonTimestamp and machine-password activity are old",
        "Validate ownership, then disable and eventually remove retired computer accounts.",
    )
    add_aggregate_finding(
        findings, "HIGH", "Computer", f"Enabled domain controllers inactive for more than {stale_days} days",
        stale_dcs, "Both lastLogonTimestamp and machine-password activity are old",
        "Verify whether these domain controllers still exist; demote or metadata-clean stale controllers through the supported procedure.",
    )

    # Only assess coverage when a LAPS schema is present in the snapshot.
    schema_names = set(schema_guids)
    legacy_laps = "ms-mcs-admpwdexpirationtime" in schema_names or any(
        ci_get(item, "ms-Mcs-AdmPwdExpirationTime") is not None for item in computers
    )
    windows_laps = "mslaps-passwordexpirationtime" in schema_names or any(
        ci_get(item, "msLAPS-PasswordExpirationTime") is not None for item in computers
    )
    if legacy_laps or windows_laps:
        uncovered, expired, unencrypted = [], [], []
        laps_material = []
        for computer in computers:
            if has_uac(computer, "DISABLED") or has_uac(computer, "DOMAIN_CONTROLLER"):
                continue
            expiry_values = [
                ci_get(computer, "ms-Mcs-AdmPwdExpirationTime"),
                ci_get(computer, "msLAPS-PasswordExpirationTime"),
            ]
            material = {
                name: ci_get(computer, name)
                for name in ("ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword")
                if ci_get(computer, name) not in (None, "", [], b"")
            }
            managed = any(as_int(value) > 0 for value in expiry_values) or bool(material)
            if not managed:
                uncovered.append(object_name(computer))
                continue
            if material:
                laps_material.append((computer, material))
            expiries = [value for value in (filetime_datetime(v) for v in expiry_values) if value is not None]
            if expiries and max(expiries) < capture_time:
                expired.append(object_name(computer))
            if windows_laps and "msLAPS-Password" in material and "msLAPS-EncryptedPassword" not in material:
                unencrypted.append(object_name(computer))
        add_aggregate_finding(
            findings, "LOW", "LAPS", "Enabled computers are not covered by deployed LAPS",
            uncovered, "No LAPS expiration or password material is populated",
            "Apply the LAPS policy and computer self-permissions to all supported workstation and member-server OUs.",
        )
        add_aggregate_finding(
            findings, "MEDIUM", "LAPS", "LAPS password rotation is overdue",
            expired, "The recorded password-expiration time predates the snapshot",
            "Investigate policy processing and rotate the affected local administrator passwords.",
        )
        add_aggregate_finding(
            findings, "MEDIUM", "LAPS", "Windows LAPS stores clear-text rather than encrypted passwords",
            unencrypted, "msLAPS-Password is populated without msLAPS-EncryptedPassword",
            "At Windows Server 2016 domain functional level or later, enable Windows LAPS password encryption and restrict decryption principals.",
        )

        # Detect only obvious broad exposure to well-known low-privilege groups.
        laps_guids = {
            value for name, value in schema_guids.items()
            if name in {"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword"} and value
        }
        laps_guids.add(LAPS_ENCRYPTED_PROPERTY_SET_GUID)
        exposed: Dict[str, List[str]] = {}
        for computer, _material in laps_material:
            for sid, rights, guid, _ace in _allowed_aces(ci_get(computer, "nTSecurityDescriptor")):
                if not low_priv_sid(sid):
                    continue
                readable = "GENERIC_ALL" in rights or (
                    "CONTROL_ACCESS" in rights and guid in ({""} | laps_guids)
                ) or ("READ_PROPERTY" in rights and guid in laps_guids)
                if readable:
                    exposed.setdefault(sid, []).append(object_name(computer))
        for sid, names in exposed.items():
            display = sid_display(sid, by_sid) or describe_sid(sid) or "low-privileged principal"
            add_aggregate_finding(
                findings, "HIGH", "LAPS", "Low-privileged principal can read LAPS password material",
                names, f"{display} ({sid}) has a broad or LAPS-specific read right",
                "Remove broad password-read rights and delegate retrieval only to approved support or tier-0 groups.",
            )

    # Key credentials can be legitimate Windows Hello keys. Surface them only
    # on tier-0/service identities, and detect unexpected writers on tier-0.
    key_guid = schema_guids.get("msds-keycredentiallink", "")
    for item in [*users, *computers]:
        values = as_list(ci_get(item, "msDS-KeyCredentialLink"))
        sensitive = (
            dn_key(item) in privileged_dns
            or as_int(ci_get(item, "adminCount")) == 1
            or has_uac(item, "DOMAIN_CONTROLLER")
            or (is_user(item) and bool(as_list(ci_get(item, "servicePrincipalName"))))
        )
        if values and sensitive:
            add_finding(
                findings, "MEDIUM", "Key credentials", "Key credentials are configured on a sensitive principal",
                object_name(item), f"msDS-KeyCredentialLink contains {len(values)} value(s)",
                "Validate each key owner/device against Windows Hello or key-trust enrollment records and remove unknown keys.",
            )
        if dn_key(item) not in privileged_dns and as_int(ci_get(item, "adminCount")) != 1:
            continue
        if not key_guid:
            continue
        for sid, rights, guid, _ace in _allowed_aces(ci_get(item, "nTSecurityDescriptor")):
            if is_expected_privileged_trustee(sid):
                continue
            if "WRITE_PROPERTY" in rights and guid == key_guid:
                display = sid_display(sid, by_sid) or "unresolved principal"
                add_finding(
                    findings, "HIGH", "Key credentials", "Unexpected principal can write key credentials on a privileged account",
                    object_name(item), f"{display} ({sid}) has WriteProperty on msDS-KeyCredentialLink",
                    "Remove the ACE and investigate the account for shadow credentials and unauthorized certificate/key authentication.",
                )

    # High-signal privileged-account hygiene.
    for user in users:
        if has_uac(user, "DISABLED") or dn_key(user) not in privileged_dns:
            continue
        target = object_name(user)
        if as_list(ci_get(user, "servicePrincipalName")):
            add_finding(
                findings, "HIGH", "Privileged account", "Privileged user has service principal names",
                target, f"SPNs={cell(ci_get(user, 'servicePrincipalName'))}",
                "Remove unnecessary SPNs or replace the identity with a dedicated, least-privileged gMSA and rotate the password.",
            )
        if has_uac(user, "PASSWORD_NEVER_EXPIRES"):
            add_finding(
                findings, "HIGH", "Privileged account", "Privileged user password never expires",
                target, "userAccountControl includes PASSWORD_NEVER_EXPIRES",
                "Move automation to a gMSA where possible; otherwise enforce rotation and strong privileged-access controls.",
            )
        if not has_uac(user, "NOT_DELEGATED"):
            add_finding(
                findings, "MEDIUM", "Privileged account", "Privileged user is not marked sensitive and cannot be delegated",
                target, "userAccountControl does not include NOT_DELEGATED",
                "Set 'Account is sensitive and cannot be delegated' after validating application compatibility.",
            )
        activity = _last_activity(user)
        if activity is not None and activity < cutoff:
            add_finding(
                findings, "MEDIUM", "Privileged account", f"Privileged account inactive for more than {stale_days} days",
                target, f"last activity={activity.isoformat()}",
                "Confirm ownership and disable or remove obsolete privileged access.",
            )


# -- AD CS ---------------------------------------------------------------------------


def template_acl_facts(descriptor: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"low_priv_enrollment": [], "low_priv_write": []}
    for sid, rights, guid, _ace in _allowed_aces(descriptor):
        if not low_priv_sid(sid):
            continue
        identity = f"{sid} ({describe_sid(sid) or 'low-privileged principal'})"
        if "GENERIC_ALL" in rights or ("CONTROL_ACCESS" in rights and guid in {"", ENROLL_GUID, AUTOENROLL_GUID}):
            result["low_priv_enrollment"].append(identity)
        dangerous = rights & DANGEROUS_FULL_RIGHTS
        property_write = "WRITE_PROPERTY" in rights and guid not in {ENROLL_GUID, AUTOENROLL_GUID}
        if dangerous or property_write:
            result["low_priv_write"].append(identity)
    return result


def analyze_certificates(
    records: List[Dict[str, Any]], findings: List[Dict[str, str]], ads_types: Dict[str, int], timezone_name: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    cas = [item for item in records if "pkienrollmentservice" in classes(item)]
    templates = [item for item in records if "pkicertificatetemplate" in classes(item)]
    published = {str(name).casefold() for ca in cas for name in as_list(ci_get(ca, "certificateTemplates", []))}
    cert_findings: List[Dict[str, Any]] = []

    for template in templates:
        name = str(ci_get(template, "cn") or ci_get(template, "name") or dn(template))
        name_flags = as_int(ci_get(template, "msPKI-Certificate-Name-Flag")) & 0xFFFFFFFF
        enrollment_flags = as_int(ci_get(template, "msPKI-Enrollment-Flag")) & 0xFFFFFFFF
        signatures = as_int(ci_get(template, "msPKI-RA-Signature"))
        minimum_key_size = as_int(ci_get(template, "msPKI-Minimal-Key-Size"))
        ekus = {str(value) for value in as_list(ci_get(template, "pKIExtendedKeyUsage", []))}
        acl = template_acl_facts(ci_get(template, "nTSecurityDescriptor"))
        is_published = name.casefold() in published
        supplies_subject = bool(name_flags & 0x1)
        pending = bool(enrollment_flags & 0x2)
        client_auth = not ekus or bool(ekus & CLIENT_AUTH_EKUS)
        base = {
            "template": name,
            "distinguishedName": dn(template),
            "published": is_published,
            "low_priv_enrollment": acl["low_priv_enrollment"],
            "low_priv_write": acl["low_priv_write"],
        }

        def issue(kind: str, severity: str, evidence: str, title: str, recommendation: str) -> None:
            row = dict(base, issue=kind, severity=severity, evidence=evidence)
            cert_findings.append(row)
            add_finding(findings, severity, "AD CS", title, name, evidence, recommendation)

        if is_published and acl["low_priv_enrollment"] and supplies_subject and client_auth and not pending and signatures == 0:
            issue("ESC1-like", "HIGH", "Published; low-priv enrollment; enrollee supplies subject; authentication EKU; no approval/signature requirement",
                  "Potential ESC1 certificate template", "Restrict enrollment, disable supplied subject/SAN, require approval, or remove authentication EKUs.")
        if is_published and acl["low_priv_enrollment"] and (not ekus or "2.5.29.37.0" in ekus):
            issue("ESC2-like", "HIGH", "Published; low-priv enrollment; Any Purpose or no EKU restriction",
                  "Potential ESC2 certificate template", "Limit EKUs and enrollment permissions.")
        if is_published and acl["low_priv_enrollment"] and "1.3.6.1.4.1.311.20.2.1" in ekus:
            issue("ESC3-like", "HIGH", "Published certificate-request-agent template permits low-priv enrollment",
                  "Potential ESC3 enrollment-agent template", "Restrict enrollment-agent template access and issuance requirements.")
        if acl["low_priv_write"]:
            issue("ESC4-like", "HIGH", f"Low-privileged principals have dangerous template rights: {acl['low_priv_write']}",
                  "Potential ESC4 template ACL", "Remove write, owner, and DACL rights from low-privileged principals.")
        if is_published and 0 < minimum_key_size < 2048:
            issue("Weak key size", "MEDIUM", f"Published template permits a minimum RSA key size of {minimum_key_size} bits",
                  "Published certificate template permits weak RSA keys", "Raise the minimum RSA key size to at least 2048 bits after checking client compatibility.")

    ca_fields = ["distinguishedName", "cn", "dNSHostName", "certificateTemplates", "flags", "cACertificate", "whenCreated", "whenChanged"]
    template_fields = ["distinguishedName", "cn", "displayName", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size", "pKIExpirationPeriod", "pKIOverlapPeriod", "nTSecurityDescriptor", "whenCreated", "whenChanged"]
    return (
        [decoded_projection(item, ca_fields, ads_types, timezone_name) for item in cas],
        [decoded_projection(item, template_fields, ads_types, timezone_name) for item in templates],
        cert_findings,
    )


# -- ACLs, DCSync, RBCD ----------------------------------------------------------------


def ace_abuse_labels(rights: Set[str], guid: str) -> List[str]:
    """Human labels for the attack an allowed ACE grants, or [] if benign.

    ``rights`` are decoded access-mask names; ``guid`` is the ACE object-type
    GUID (case-folded, empty for a non-object ACE, which grants the right over
    every property/extended right).
    """
    labels: List[str] = []
    if "GENERIC_ALL" in rights:
        labels.append("GenericAll")
    if "WRITE_DACL" in rights:
        labels.append("WriteDacl")
    if "WRITE_OWNER" in rights:
        labels.append("WriteOwner")
    if "GENERIC_WRITE" in rights:
        labels.append("GenericWrite")
    if "CONTROL_ACCESS" in rights:
        if guid == GUID_DS_REPL_GET_CHANGES_ALL:
            labels.append("DCSync (Get-Changes-All)")
        elif guid == GUID_DS_REPL_GET_CHANGES:
            labels.append("Replication Get-Changes")
        elif guid == GUID_DS_REPL_GET_CHANGES_FILTERED:
            labels.append("Replication Get-Changes-In-Filtered-Set")
        elif guid == GUID_FORCE_CHANGE_PASSWORD:
            labels.append("ForceChangePassword")
        elif guid == "":
            labels.append("AllExtendedRights")
    if "WRITE_PROPERTY" in rights:
        if guid == GUID_WRITE_MEMBER:
            labels.append("AddMember")
        elif guid == GUID_WRITE_SPN:
            labels.append("WriteSPN")
        elif guid == GUID_WRITE_ALLOWED_TO_ACT:
            labels.append("Write-AllowedToActOnBehalfOfOtherIdentity (RBCD)")
        elif guid == "":
            labels.append("WriteAllProperties")
    return labels


def analyze_object_acls(
    records: List[Dict[str, Any]],
    domains: List[Dict[str, Any]],
    findings: List[Dict[str, str]],
    by_sid: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Report ACEs that let a non-privileged principal control a privileged object.

    Targets are the domain naming-context heads, AdminSDHolder, the privileged
    groups, every adminCount=1 object, Group Policy containers and PKI
    configuration objects. For each, the DACL is decoded and any allowed ACE
    granting a takeover right to a principal outside the expected admin set is
    surfaced as evidence.
    """
    domain_dns = {dn_key(item) for item in domains}
    targets: List[Tuple[Dict[str, Any], str]] = []
    for item in records:
        item_classes = classes(item)
        reasons: List[str] = []
        item_dn = dn_key(item)
        if item_dn in domain_dns:
            reasons.append("domain naming context")
        if str(ci_get(item, "name", "")).casefold() == "adminsdholder":
            reasons.append("AdminSDHolder")
        if as_int(ci_get(item, "adminCount")) == 1:
            reasons.append("adminCount=1")
        if "group" in item_classes and sid_string(item).rsplit("-", 1)[-1] in PRIVILEGED_GROUP_RIDS:
            reasons.append("privileged group")
        if "grouppolicycontainer" in item_classes:
            reasons.append("group policy object")
        if (
            "cn=public key services,cn=services,cn=configuration," in item_dn
            and "pkicertificatetemplate" not in item_classes
        ):
            reasons.append("AD CS PKI object (ESC5-like)")
        if reasons:
            targets.append((item, ", ".join(dict.fromkeys(reasons))))

    rows: List[Dict[str, Any]] = []
    for item, reason in targets:
        is_domain = "domain naming context" in reason
        pki_object = "AD CS PKI object" in reason
        repl_by_trustee: Dict[str, Set[str]] = {}
        for sid, rights, guid, ace in _allowed_aces(ci_get(item, "nTSecurityDescriptor")):
            trustee_record = by_sid.get(sid)
            expected_pki_publisher = pki_object and sid.rsplit("-", 1)[-1] == "517"
            expected_dc = trustee_record is not None and is_computer(trustee_record) and has_uac(trustee_record, "DOMAIN_CONTROLLER")
            if is_expected_privileged_trustee(sid) or expected_pki_publisher or expected_dc:
                continue
            labels = ace_abuse_labels(rights, guid)
            if not labels:
                continue
            name = sid_display(sid, by_sid) or "unresolved principal"
            rows.append({
                "target": object_name(item),
                "target_reason": reason,
                "trustee": name,
                "trustee_sid": sid,
                "granted": ", ".join(labels),
                "ace_type": ace.get("type", ""),
                "access_mask": ace.get("mask", ""),
                "object_type_guid": ace.get("object_type_guid", ""),
                "distinguished_name": dn(item),
            })
            if is_domain:
                repl_by_trustee.setdefault(sid, set()).update(labels)
            else:
                add_finding(
                    findings, "HIGH", "AD CS" if pki_object else "ACL",
                    "Potential ESC5: non-privileged principal can control a PKI object"
                    if pki_object else "Non-privileged principal can control a privileged object",
                    object_name(item),
                    f"{name} ({sid or 'unresolved'}) is granted {', '.join(labels)} on {reason}",
                    "Remove the ACE or restrict it to PKI/tier-0 administrators; review certificate trust impact."
                    if pki_object else
                    "Remove the ACE or restrict it to tier-0 administrators; review how the principal obtained it.",
                )
        for sid, labels in repl_by_trustee.items():
            name = sid_display(sid, by_sid) or "unresolved principal"
            dcsync = "DCSync (Get-Changes-All)" in labels and (
                "Replication Get-Changes" in labels or "GenericAll" in labels
            )
            if dcsync or "GenericAll" in labels:
                add_finding(
                    findings, "HIGH", "ACL",
                    "Non-privileged principal can DCSync the domain",
                    object_name(item),
                    f"{name} ({sid or 'unresolved'}) holds {', '.join(sorted(labels))} on the domain, enabling replication of secrets",
                    "Remove directory-replication and full-control rights from all but domain controllers and tier-0 admins.",
                )
            else:
                add_finding(
                    findings, "MEDIUM", "ACL",
                    "Non-privileged principal holds directory replication rights",
                    object_name(item),
                    f"{name} ({sid or 'unresolved'}) holds {', '.join(sorted(labels))} on the domain",
                    "Confirm the grant is required; DCSync needs both Get-Changes and Get-Changes-All.",
                )
    rows.sort(key=lambda row: (row["target"].casefold(), row["trustee"].casefold(), row["granted"]))
    return rows


def analyze_rbcd(
    records: List[Dict[str, Any]],
    findings: List[Dict[str, str]],
    by_sid: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Decode msDS-AllowedToActOnBehalfOfOtherIdentity to list who can impersonate."""
    rows: List[Dict[str, Any]] = []
    for item in records:
        descriptor = ci_get(item, "msDS-AllowedToActOnBehalfOfOtherIdentity")
        if not isinstance(descriptor, bytes):
            continue
        principals = list(dict.fromkeys(
            sid for sid, _rights, _guid, _ace in _allowed_aces(descriptor) if sid
        ))
        if not principals:
            continue
        names = []
        for sid in principals:
            display = sid_display(sid, by_sid)
            names.append(f"{display} ({sid})" if display else sid)
            rows.append({
                "resource": object_name(item),
                "resource_type": next(iter(classes(item) & {"computer", "user"}), "object"),
                "allowed_principal": display or "unresolved principal",
                "allowed_principal_sid": sid,
                "distinguished_name": dn(item),
            })
        add_finding(
            findings, "MEDIUM", "Delegation",
            "Resource-based constrained delegation configured",
            object_name(item),
            f"Principals allowed to act on behalf of this object: {'; '.join(names)}",
            "Confirm the RBCD is intended; clear msDS-AllowedToActOnBehalfOfOtherIdentity if not, and ensure the allowed principals are trusted.",
        )
    rows.sort(key=lambda row: (row["resource"].casefold(), row["allowed_principal"].casefold()))
    return rows


# -- service inventory --------------------------------------------------------------

# Service roles inferred from the SPN class prefix (the part before the first
# '/'). Ordered so more specific prefixes win over generic ones.
SERVICE_SPN_ROLES = [
    ("mssqlsvc", "Microsoft SQL Server"),
    ("exchangemdb", "Microsoft Exchange"),
    ("exchangerfr", "Microsoft Exchange"),
    ("exchangeab", "Microsoft Exchange"),
    ("smtpsvc", "SMTP"),
    ("imap", "IMAP mail"),
    ("pop", "POP mail"),
    ("termsrv", "Remote Desktop / Terminal Services"),
    ("wsman", "WinRM (WS-Management)"),
    ("http", "HTTP / web (IIS, ADFS, WSMan, SCCM)"),
    ("adfs", "Active Directory Federation Services"),
    ("dns", "DNS server"),
    ("ftp", "FTP server"),
    ("dhcpserver", "DHCP server"),
    ("gc", "Global catalog"),
    ("ldap", "LDAP / domain controller"),
    ("kadmin", "Kerberos KDC"),
    ("vmwarevc", "VMware vCenter"),
    ("msserverclustermgmtapi", "Failover Cluster"),
    ("msservercluster", "Failover Cluster"),
    ("hyper-v replica service", "Hyper-V Replica"),
    ("microsoft virtual console service", "Hyper-V"),
    ("wsmprovhost", "WinRM host"),
    ("sap", "SAP"),
    ("oracle", "Oracle"),
    ("aradminsvc", "Application server"),
]

# Service Connection Point keywords (matched in cn/name) to a product.
SERVICE_SCP_KEYWORDS = [
    ("sms", "Microsoft Configuration Manager (SCCM/SMS)"),
    ("system management", "Microsoft Configuration Manager (SCCM/SMS)"),
    ("microsoft sms", "Microsoft Configuration Manager (SCCM/SMS)"),
    ("wsus", "Windows Server Update Services"),
    ("certification authorities", "AD Certificate Services"),
    ("enrollment services", "AD Certificate Services"),
    ("adfs", "Active Directory Federation Services"),
    ("exchange", "Microsoft Exchange"),
    ("sql", "Microsoft SQL Server"),
]


def service_roles_for(item: Dict[str, Any]) -> List[str]:
    """Roles inferred for one object from its SPNs and (for SCPs) its name."""
    roles: List[str] = []
    for spn in as_list(ci_get(item, "servicePrincipalName")):
        prefix = str(spn).split("/", 1)[0].casefold()
        for needle, role in SERVICE_SPN_ROLES:
            if prefix == needle or prefix.startswith(needle):
                roles.append(role)
                break
    if "serviceconnectionpoint" in classes(item):
        haystack = f"{ci_get(item, 'cn', '')} {ci_get(item, 'name', '')} {dn(item)}".casefold()
        for needle, role in SERVICE_SCP_KEYWORDS:
            if needle in haystack:
                roles.append(role)
    return list(dict.fromkeys(roles))


def analyze_service_inventory(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fingerprint infrastructure services from SPNs and Service Connection Points."""
    rows: List[Dict[str, Any]] = []
    for item in records:
        roles = service_roles_for(item)
        if not roles:
            continue
        rows.append({
            "host": str(ci_get(item, "dNSHostName") or ci_get(item, "sAMAccountName") or object_name(item)),
            "roles": "; ".join(roles),
            "object_type": next(iter(classes(item) & {"computer", "serviceconnectionpoint", "user"}), "object"),
            "operating_system": str(ci_get(item, "operatingSystem", "")),
            "service_principal_names": "; ".join(str(spn) for spn in as_list(ci_get(item, "servicePrincipalName"))),
            "distinguished_name": dn(item),
        })
    rows.sort(key=lambda row: (row["roles"].casefold(), row["host"].casefold()))
    return rows
