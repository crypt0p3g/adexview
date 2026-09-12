"""Attribute-aware decoders for AD Explorer snapshot values.

The snapshot reader deliberately keeps filter-facing values simple.  This
module is used when values are materialised for humans and by the audit
reporter.  Decoders preserve the original numeric value and add a readable
interpretation instead of making lossy conversions.
"""

from __future__ import annotations

import base64
import datetime as dt
import functools
import hashlib
import ipaddress
import json
import re
import struct
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo


DEFAULT_TIMEZONE = "Asia/Tokyo"
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


FILETIME_ATTRIBUTES = {
    "accountexpires",
    "badpasswordtime",
    "creationtime",
    "lastlogoff",
    "lastlogon",
    "lastlogontimestamp",
    "lockouttime",
    "ms-mcs-admpwdexpirationtime",
    "msds-userpasswordexpirytimecomputed",
    "mslaps-passwordexpirationtime",
    "pwdlastset",
}

DURATION_ATTRIBUTES = {
    "forceLogoff".lower(),
    "lockoutduration",
    "lockoutobservationwindow",
    "maxpwdage",
    "minpwdage",
    "pkiexpirationperiod",
    "pkioverlapperiod",
}

UTC_TIME_ATTRIBUTES = {
    "createtimestamp",
    "modifytimestamp",
    "whenchanged",
    "whencreated",
}

SID_ATTRIBUTES = {
    "objectsid",
    "sidhistory",
    "tokengroups",
    "tokengroupsglobalanduniversal",
    "tokengroupsnogcacceptable",
    "msds-quota-trustee",
}

GUID_ATTRIBUTES = {
    "attributeidguid",
    "attributesecurityguid",
    "invocationid",
    "ms-ds-consistencyguid",
    "msdfsgenerationguidv2",
    "msfve-recoveryguid",
    "msfve-volumeguid",
    "netbootguid",
    "objectguid",
    "schemaidguid",
}

SECURITY_DESCRIPTOR_ATTRIBUTES = {
    "msds-allowedtoactonbehalfofotheridentity",
    "msds-groupmsamembership",
    "msds-userallowedtoauthenticatefrom",
    "msds-userallowedtoauthenticateto",
    "ntsecuritydescriptor",
}

CERTIFICATE_ATTRIBUTES = {
    "cacertificate",
    "crosscertificatepair",
    "msexcharchivecert",
    "msexchusercertificate",
    "usercertificate",
    "usersmimecertificate",
}

CRL_ATTRIBUTES = {
    "authorityrevocationlist",
    "certificaterevocationlist",
    "deltarevocationlist",
}

FLAG_MAPS: Dict[str, Dict[int, str]] = {
    "instancetype": {
        0x00000001: "IS_NC_HEAD",
        0x00000002: "REPLICA_NOT_INSTANTIATED",
        0x00000004: "WRITE",
        0x00000008: "NC_ABOVE",
        0x00000010: "NC_COMING",
        0x00000020: "NC_GOING",
    },
    "pwdproperties": {
        0x00000001: "DOMAIN_PASSWORD_COMPLEX",
        0x00000002: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
        0x00000004: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
        0x00000008: "DOMAIN_LOCKOUT_ADMINS",
        0x00000010: "DOMAIN_PASSWORD_STORE_CLEARTEXT",
        0x00000020: "DOMAIN_REFUSE_PASSWORD_CHANGE",
    },
    "useraccountcontrol": {
        0x00000001: "SCRIPT",
        0x00000002: "ACCOUNTDISABLE",
        0x00000008: "HOMEDIR_REQUIRED",
        0x00000010: "LOCKOUT",
        0x00000020: "PASSWD_NOTREQD",
        0x00000040: "PASSWD_CANT_CHANGE",
        0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
        0x00000100: "TEMP_DUPLICATE_ACCOUNT",
        0x00000200: "NORMAL_ACCOUNT",
        0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
        0x00001000: "WORKSTATION_TRUST_ACCOUNT",
        0x00002000: "SERVER_TRUST_ACCOUNT",
        0x00010000: "DONT_EXPIRE_PASSWORD",
        0x00020000: "MNS_LOGON_ACCOUNT",
        0x00040000: "SMARTCARD_REQUIRED",
        0x00080000: "TRUSTED_FOR_DELEGATION",
        0x00100000: "NOT_DELEGATED",
        0x00200000: "USE_DES_KEY_ONLY",
        0x00400000: "DONT_REQUIRE_PREAUTH",
        0x00800000: "PASSWORD_EXPIRED",
        0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
        0x04000000: "PARTIAL_SECRETS_ACCOUNT",
    },
    "grouptype": {
        0x00000001: "BUILTIN_LOCAL_GROUP",
        0x00000002: "GLOBAL_GROUP",
        0x00000004: "DOMAIN_LOCAL_GROUP",
        0x00000008: "UNIVERSAL_GROUP",
        0x80000000: "SECURITY_ENABLED",
    },
    "trustattributes": {
        0x00000001: "NON_TRANSITIVE",
        0x00000002: "UPLEVEL_ONLY",
        0x00000004: "QUARANTINED_DOMAIN_SID_FILTERING",
        0x00000008: "FOREST_TRANSITIVE",
        0x00000010: "CROSS_ORGANIZATION",
        0x00000020: "WITHIN_FOREST",
        0x00000040: "TREAT_AS_EXTERNAL",
        0x00000080: "USES_RC4_ENCRYPTION",
        0x00000200: "CROSS_ORG_NO_TGT_DELEGATION",
        0x00000400: "PIM_TRUST",
    },
    "msds-supportedencryptiontypes": {
        0x01: "DES_CRC",
        0x02: "DES_MD5",
        0x04: "RC4_HMAC",
        0x08: "AES128_CTS_HMAC_SHA1",
        0x10: "AES256_CTS_HMAC_SHA1",
        0x20: "FAST_SUPPORTED",
        0x40: "COMPOUND_IDENTITY_SUPPORTED",
        0x80: "CLAIMS_SUPPORTED",
        0x100: "RESOURCE_SID_COMPRESSION_DISABLED",
        0x200: "AES256_CTS_HMAC_SHA256",
    },
    "mspki-certificate-name-flag": {
        0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
        0x00010000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
        0x00400000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
        0x00800000: "SUBJECT_ALT_REQUIRE_SPN",
        0x01000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
        0x02000000: "SUBJECT_ALT_REQUIRE_UPN",
        0x04000000: "SUBJECT_ALT_REQUIRE_EMAIL",
        0x08000000: "SUBJECT_ALT_REQUIRE_DNS",
        0x10000000: "SUBJECT_REQUIRE_DNS_AS_CN",
        0x20000000: "SUBJECT_REQUIRE_EMAIL",
        0x40000000: "SUBJECT_REQUIRE_COMMON_NAME",
        0x80000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    },
    "mspki-enrollment-flag": {
        0x00000001: "INCLUDE_SYMMETRIC_ALGORITHMS",
        0x00000002: "PEND_ALL_REQUESTS",
        0x00000004: "PUBLISH_TO_KRA_CONTAINER",
        0x00000008: "PUBLISH_TO_DS",
        0x00000010: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
        0x00000020: "AUTO_ENROLLMENT",
        0x00000040: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
        0x00000100: "USER_INTERACTION_REQUIRED",
        0x00000400: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
        0x00000800: "ALLOW_ENROLL_ON_BEHALF_OF",
        0x00001000: "ADD_OCSP_NOCHECK",
        0x00002000: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
        0x00004000: "NOREVOCATIONINFOINISSUEDCERTS",
        0x00008000: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
        0x00010000: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
        0x00020000: "ISSUANCE_POLICIES_FROM_REQUEST",
        0x00040000: "SKIP_AUTO_RENEWAL",
    },
    "mspki-private-key-flag": {
        0x00000001: "REQUIRE_PRIVATE_KEY_ARCHIVAL",
        0x00000010: "EXPORTABLE_KEY",
        0x00000020: "STRONG_KEY_PROTECTION_REQUIRED",
        0x00000040: "REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM",
        0x00000080: "REQUIRE_SAME_KEY_RENEWAL",
        0x00000100: "USE_LEGACY_PROVIDER",
        0x00001000: "ATTEST_NONE",
        0x00002000: "ATTEST_REQUIRED",
        0x00004000: "ATTEST_PREFERRED",
        0x00008000: "ATTESTATION_WITHOUT_POLICY",
        0x00010000: "EK_TRUST_ON_USE",
        0x00020000: "EK_VALIDATE_CERT",
        0x00040000: "EK_VALIDATE_KEY",
        0x00100000: "HELLO_LOGON_KEY",
    },
    "searchflags": {
        0x0001: "INDEXED",
        0x0002: "INDEX_CONTAINER",
        0x0004: "ANR",
        0x0008: "PRESERVE_ON_DELETE",
        0x0010: "COPY_ON_COPY",
        0x0020: "TUPLE_INDEX",
        0x0040: "SUBTREE_INDEX",
        0x0080: "CONFIDENTIAL",
        0x0100: "RODC_FILTERED_ATTRIBUTE",
        0x0200: "EXTENDED_LINK_TRACKING",
        0x0400: "BASE_ONLY",
        0x0800: "PARTITION_SECRET",
    },
    "systemflags": {
        0x00000001: "DISALLOW_DELETE",
        0x00000002: "CONFIG_ALLOW_RENAME",
        0x00000004: "CONFIG_ALLOW_MOVE",
        0x00000010: "SCHEMA_BASE_OBJECT",
        0x00000020: "ATTR_IS_RDN",
        0x02000000: "DOMAIN_DISALLOW_RENAME",
        0x04000000: "DOMAIN_DISALLOW_MOVE",
        0x08000000: "CR_NTDS_NC",
        0x10000000: "CR_NTDS_DOMAIN",
        0x20000000: "ATTR_NOT_REPLICATED",
        0x40000000: "PARENT_NOT_REPLICATED",
    },
}
FLAG_MAPS["msds-user-account-control-computed"] = FLAG_MAPS["useraccountcontrol"]

ENUM_MAPS: Dict[str, Dict[int, str]] = {
    "domaincontrollerfunctionality": {
        0: "WINDOWS_2000", 1: "WINDOWS_2003_INTERIM", 2: "WINDOWS_2003",
        3: "WINDOWS_2008", 4: "WINDOWS_2008_R2", 5: "WINDOWS_2012",
        6: "WINDOWS_2012_R2", 7: "WINDOWS_2016", 10: "WINDOWS_SERVER_2025",
    },
    "domainfunctionality": {
        0: "WINDOWS_2000", 1: "WINDOWS_2003_INTERIM", 2: "WINDOWS_2003",
        3: "WINDOWS_2008", 4: "WINDOWS_2008_R2", 5: "WINDOWS_2012",
        6: "WINDOWS_2012_R2", 7: "WINDOWS_2016", 10: "WINDOWS_SERVER_2025",
    },
    "forestfunctionality": {
        0: "WINDOWS_2000", 1: "WINDOWS_2003_INTERIM", 2: "WINDOWS_2003",
        3: "WINDOWS_2008", 4: "WINDOWS_2008_R2", 5: "WINDOWS_2012",
        6: "WINDOWS_2012_R2", 7: "WINDOWS_2016", 10: "WINDOWS_SERVER_2025",
    },
    "msds-behavior-version": {
        0: "WINDOWS_2000", 1: "WINDOWS_2003_INTERIM", 2: "WINDOWS_2003",
        3: "WINDOWS_2008", 4: "WINDOWS_2008_R2", 5: "WINDOWS_2012",
        6: "WINDOWS_2012_R2", 7: "WINDOWS_2016", 10: "WINDOWS_SERVER_2025",
    },
    "primarygroupid": {
        512: "Domain Admins", 513: "Domain Users", 514: "Domain Guests",
        515: "Domain Computers", 516: "Domain Controllers",
        517: "Cert Publishers", 518: "Schema Admins", 519: "Enterprise Admins",
        520: "Group Policy Creator Owners", 521: "Read-only Domain Controllers",
        525: "Protected Users", 526: "Key Admins", 527: "Enterprise Key Admins",
    },
    "ntmixeddomain": {0: "NATIVE", 1: "MIXED"},
    "gpoptions": {0: "INHERITANCE_ENABLED", 1: "BLOCK_INHERITANCE"},
    "mspki-template-schema-version": {1: "V1", 2: "V2", 3: "V3", 4: "V4"},
    "trustdirection": {0: "DISABLED", 1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"},
    "trusttype": {1: "DOWNLEVEL", 2: "UPLEVEL", 3: "MIT", 4: "DCE"},
    "samaccounttype": {
        0x10000000: "SAM_DOMAIN_OBJECT",
        0x10000001: "SAM_GROUP_OBJECT",
        0x10000002: "SAM_NON_SECURITY_GROUP_OBJECT",
        0x20000000: "SAM_ALIAS_OBJECT",
        0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
        0x30000000: "SAM_USER_OBJECT",
        0x30000001: "SAM_MACHINE_ACCOUNT",
        0x30000002: "SAM_TRUST_ACCOUNT",
    },
}

WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-3-0": "Creator Owner",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "Local System",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Builtin Administrators",
    "S-1-5-32-545": "Builtin Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}

SID_RID_NAMES = {
    500: "Administrator",
    501: "Guest",
    502: "KRBTGT",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    525: "Protected Users",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}


@functools.lru_cache(maxsize=64)
def _timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo(DEFAULT_TIMEZONE)


def format_datetime(value: dt.datetime, timezone_name: str = DEFAULT_TIMEZONE) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    local = value.astimezone(_timezone(timezone_name))
    # Equivalent to strftime("%Y-%m-%d %H:%M:%S %Z") but several times faster,
    # which matters when every timestamp of every object is rendered.
    return (
        f"{local.year:04d}-{local.month:02d}-{local.day:02d} "
        f"{local.hour:02d}:{local.minute:02d}:{local.second:02d} {local.tzname() or ''}"
    ).rstrip()


def filetime_to_string(value: int, timezone_name: str = DEFAULT_TIMEZONE) -> str:
    if value in (0, 0x7FFFFFFFFFFFFFFF):
        return "Never"
    try:
        return format_datetime(FILETIME_EPOCH + dt.timedelta(microseconds=value // 10), timezone_name)
    except (OverflowError, ValueError):
        return f"Invalid FILETIME ({value})"


def epoch_to_string(value: int, timezone_name: str = DEFAULT_TIMEZONE) -> str:
    if not value:
        return "Never"
    try:
        return format_datetime(dt.datetime.fromtimestamp(value, tz=dt.timezone.utc), timezone_name)
    except (OverflowError, OSError, ValueError):
        return f"Invalid timestamp ({value})"


def duration_to_string(value: int) -> str:
    ticks = abs(int(value))
    seconds, remainder = divmod(ticks, 10_000_000)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    if remainder:
        parts.append(f"{remainder * 100}ns")
    return " ".join(parts)


def parse_sid(data: bytes) -> str:
    if len(data) < 8:
        raise ValueError("SID is shorter than its header")
    revision, count = data[0], data[1]
    needed = 8 + count * 4
    if len(data) < needed:
        raise ValueError("SID is truncated")
    authority = int.from_bytes(data[2:8], "big")
    subs = [struct.unpack_from("<I", data, 8 + index * 4)[0] for index in range(count)]
    return f"S-{revision}-{authority}" + "".join(f"-{item}" for item in subs)


def describe_sid(sid: str) -> str:
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    try:
        rid = int(sid.rsplit("-", 1)[1])
    except (ValueError, IndexError):
        return ""
    return SID_RID_NAMES.get(rid, "")


def sid_value(data: bytes) -> Dict[str, str]:
    sid = parse_sid(data)
    result = {"sid": sid}
    name = describe_sid(sid)
    if name:
        result["well_known_name"] = name
    return result


def decode_flags(value: int, mapping: Dict[int, str]) -> Dict[str, Any]:
    unsigned = int(value) & 0xFFFFFFFF
    names = [name for bit, name in mapping.items() if unsigned & bit]
    known_mask = 0
    for bit in mapping:
        known_mask |= bit
    result: Dict[str, Any] = {"value": int(value), "hex": f"0x{unsigned:08x}", "flags": names}
    unknown = unsigned & ~known_mask
    if unknown:
        result["unknown_bits"] = f"0x{unknown:08x}"
    return result


ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x02: "SYSTEM_AUDIT",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
    0x07: "SYSTEM_AUDIT_OBJECT",
    0x09: "ACCESS_ALLOWED_CALLBACK",
    0x0A: "ACCESS_DENIED_CALLBACK",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
    0x11: "SYSTEM_MANDATORY_LABEL",
}

ACE_FLAG_MAP = {
    0x01: "OBJECT_INHERIT",
    0x02: "CONTAINER_INHERIT",
    0x04: "NO_PROPAGATE_INHERIT",
    0x08: "INHERIT_ONLY",
    0x10: "INHERITED_OBJECT_ACE",
    0x40: "SUCCESSFUL_ACCESS_AUDIT",
    0x80: "FAILED_ACCESS_AUDIT",
}

ACCESS_MASK_MAP = {
    0x00000001: "CREATE_CHILD",
    0x00000002: "DELETE_CHILD",
    0x00000004: "LIST_CHILDREN",
    0x00000008: "SELF_WRITE",
    0x00000010: "READ_PROPERTY",
    0x00000020: "WRITE_PROPERTY",
    0x00000040: "DELETE_TREE",
    0x00000080: "LIST_OBJECT",
    0x00000100: "CONTROL_ACCESS",
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DACL",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x02000000: "MAXIMUM_ALLOWED",
    0x10000000: "GENERIC_ALL",
    0x20000000: "GENERIC_EXECUTE",
    0x40000000: "GENERIC_WRITE",
    0x80000000: "GENERIC_READ",
}


def _parse_sid_at(data: bytes, offset: int) -> Tuple[Dict[str, str], int]:
    if offset + 8 > len(data):
        raise ValueError("SID offset is outside descriptor")
    count = data[offset + 1]
    end = offset + 8 + count * 4
    return sid_value(data[offset:end]), end


def _decode_guid_le(data: bytes) -> str:
    return str(uuid.UUID(bytes_le=data))


def _parse_acl(data: bytes, offset: int) -> Dict[str, Any]:
    if offset == 0:
        return {}
    if offset + 8 > len(data):
        raise ValueError("ACL header is truncated")
    revision, _, acl_size, ace_count, _ = struct.unpack_from("<BBHHH", data, offset)
    end_acl = min(len(data), offset + acl_size)
    position = offset + 8
    aces: List[Dict[str, Any]] = []
    for _index in range(ace_count):
        if position + 4 > end_acl:
            break
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, position)
        if ace_size < 8 or position + ace_size > end_acl:
            break
        ace_end = position + ace_size
        mask = struct.unpack_from("<I", data, position + 4)[0]
        ace: Dict[str, Any] = {
            "type": ACE_TYPE_NAMES.get(ace_type, f"ACE_TYPE_{ace_type}"),
            "flags": [name for bit, name in ACE_FLAG_MAP.items() if ace_flags & bit],
            "mask": f"0x{mask:08x}",
            "rights": [name for bit, name in ACCESS_MASK_MAP.items() if mask & bit],
        }
        sid_offset = position + 8
        if ace_type in {0x05, 0x06, 0x07, 0x0B, 0x0C} and position + 12 <= ace_end:
            object_flags = struct.unpack_from("<I", data, position + 8)[0]
            sid_offset = position + 12
            if object_flags & 0x1 and sid_offset + 16 <= ace_end:
                ace["object_type_guid"] = _decode_guid_le(data[sid_offset : sid_offset + 16])
                sid_offset += 16
            if object_flags & 0x2 and sid_offset + 16 <= ace_end:
                ace["inherited_object_type_guid"] = _decode_guid_le(data[sid_offset : sid_offset + 16])
                sid_offset += 16
        try:
            trustee, _ = _parse_sid_at(data[:ace_end], sid_offset)
            ace["trustee"] = trustee
        except (ValueError, struct.error):
            ace["trustee"] = {"error": "unparseable SID"}
        aces.append(ace)
        position = ace_end
    return {"revision": revision, "size": acl_size, "ace_count": ace_count, "aces": aces}


@functools.lru_cache(maxsize=4096)
def parse_security_descriptor(data: bytes) -> Dict[str, Any]:
    if len(data) < 20:
        raise ValueError("security descriptor is shorter than 20 bytes")
    revision, _, control, owner_off, group_off, sacl_off, dacl_off = struct.unpack_from(
        "<BBHLLLL", data, 0
    )
    result: Dict[str, Any] = {
        "type": "SECURITY_DESCRIPTOR_RELATIVE",
        "revision": revision,
        "control": f"0x{control:04x}",
    }
    for label, offset in (("owner", owner_off), ("group", group_off)):
        if offset:
            try:
                result[label], _ = _parse_sid_at(data, offset)
            except ValueError as exc:
                result[label] = {"error": str(exc)}
    if dacl_off:
        result["dacl"] = _parse_acl(data, dacl_off)
    else:
        result["dacl"] = None
    if sacl_off:
        result["sacl"] = _parse_acl(data, sacl_off)
    return result


DNS_TYPES = {
    0: "ZERO",
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    24: "SIG",
    25: "KEY",
    28: "AAAA",
    33: "SRV",
    39: "DNAME",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    65281: "WINS",
    65282: "WINSR",
}


def _dns_counted_name(data: bytes, offset: int) -> Tuple[str, int]:
    if offset + 2 > len(data):
        return "", len(data)
    total_length = data[offset]
    label_count = data[offset + 1]
    position = offset + 2
    labels: List[str] = []
    limit = min(len(data), offset + 1 + total_length)
    for _ in range(label_count):
        if position >= limit:
            break
        length = data[position]
        position += 1
        label = data[position : position + length]
        labels.append(label.decode("utf-8", errors="replace"))
        position += length
    return ".".join(labels), max(position, limit)


def _dns_txt(data: bytes, offset: int) -> List[str]:
    if offset >= len(data):
        return []
    count = data[offset]
    position = offset + 1
    result = []
    for _ in range(count):
        if position >= len(data):
            break
        length = data[position]
        position += 1
        result.append(data[position : position + length].decode("utf-8", errors="replace"))
        position += length
    return result


def parse_dns_record(data: bytes, timezone_name: str = DEFAULT_TIMEZONE) -> Dict[str, Any]:
    if len(data) < 24:
        raise ValueError("DNS record is shorter than its 24-byte header")
    data_length, record_type = struct.unpack_from("<HH", data, 0)
    serial = struct.unpack_from("<I", data, 8)[0]
    ttl = struct.unpack_from(">I", data, 12)[0]
    timestamp_hours = struct.unpack_from("<I", data, 20)[0]
    payload = data[24 : 24 + data_length]
    result: Dict[str, Any] = {
        "type": DNS_TYPES.get(record_type, f"TYPE_{record_type}"),
        "type_id": record_type,
        "serial": serial,
        "ttl_seconds": ttl,
        "rank": data[5],
        "flags": f"0x{struct.unpack_from('<H', data, 6)[0]:04x}",
    }
    if timestamp_hours:
        created = FILETIME_EPOCH + dt.timedelta(hours=timestamp_hours)
        result["aging_timestamp"] = format_datetime(created, timezone_name)
    else:
        result["aging_timestamp"] = "Static"
    if record_type == 1 and len(payload) >= 4:
        result["address"] = str(ipaddress.IPv4Address(payload[:4]))
    elif record_type == 28 and len(payload) >= 16:
        result["address"] = str(ipaddress.IPv6Address(payload[:16]))
    elif record_type in {2, 5, 12, 39}:
        result["target"], _ = _dns_counted_name(payload, 0)
    elif record_type == 15 and len(payload) >= 2:
        result["preference"] = struct.unpack_from(">H", payload, 0)[0]
        result["exchange"], _ = _dns_counted_name(payload, 2)
    elif record_type == 33 and len(payload) >= 6:
        result["priority"], result["weight"], result["port"] = struct.unpack_from(
            ">HHH", payload, 0
        )
        result["target"], _ = _dns_counted_name(payload, 6)
    elif record_type == 6 and len(payload) >= 20:
        (result["soa_serial"], result["refresh"], result["retry"], result["expire"], result["minimum_ttl"]) = struct.unpack_from(
            ">IIIII", payload, 0
        )
        result["primary_server"], pos = _dns_counted_name(payload, 20)
        result["zone_admin"], _ = _dns_counted_name(payload, pos)
    elif record_type == 16:
        result["text"] = _dns_txt(payload, 0)
    elif payload:
        result["payload"] = _binary_fallback(payload, "DNS payload")
    return result


def parse_dfs_target_list(data: bytes) -> Dict[str, Any]:
    text = data.decode("utf-16", errors="strict").rstrip("\x00")
    root = ET.fromstring(text)
    targets = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1].lower() == "target":
            targets.append(
                {
                    "path": (node.text or "").strip(),
                    "state": node.get("state"),
                    "priority_class": node.get("priorityClass"),
                    "priority_rank": node.get("priorityRank"),
                }
            )
    return {"type": "DFS_TARGET_LIST", "targets": targets}


def _decode_oid_content(data: bytes) -> str:
    """Decode BER OID content octets (oMObjectClass omits tag and length)."""
    if not data:
        raise ValueError("empty OID")
    values: List[int] = []
    current = 0
    for byte in data:
        current = (current << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            values.append(current)
            current = 0
    if current or not values:
        raise ValueError("truncated BER OID")
    first = min(values[0] // 40, 2)
    second = values[0] - first * 40
    return ".".join(str(item) for item in [first, second, *values[1:]])


def _pki_key_usage(data: bytes) -> Dict[str, Any]:
    first = data[0] if data else 0
    second = data[1] if len(data) > 1 else 0
    mapping = [
        (first, 0x80, "DIGITAL_SIGNATURE"),
        (first, 0x40, "NON_REPUDIATION_CONTENT_COMMITMENT"),
        (first, 0x20, "KEY_ENCIPHERMENT"),
        (first, 0x10, "DATA_ENCIPHERMENT"),
        (first, 0x08, "KEY_AGREEMENT"),
        (first, 0x04, "KEY_CERT_SIGN"),
        (first, 0x02, "CRL_SIGN"),
        (first, 0x01, "ENCIPHER_ONLY"),
        (second, 0x80, "DECIPHER_ONLY"),
    ]
    return {
        "type": "X509_KEY_USAGE",
        "hex": data.hex(),
        "usages": [name for value, mask, name in mapping if value & mask],
    }


def _crl_value(data: bytes, timezone_name: str) -> Dict[str, Any]:
    if data in {b"", b"\x00"}:
        return {"type": "X509_CRL_PLACEHOLDER", "value": data.hex()}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        crl = x509.load_der_x509_crl(data)
        result: Dict[str, Any] = {
            "type": "X509_CRL",
            "issuer": crl.issuer.rfc4514_string(),
            "last_update": format_datetime(crl.last_update_utc, timezone_name),
            "next_update": format_datetime(crl.next_update_utc, timezone_name) if crl.next_update_utc else None,
            "revoked_certificate_count": len(crl),
            "signature_algorithm_oid": crl.signature_algorithm_oid.dotted_string,
            "sha256": crl.fingerprint(hashes.SHA256()).hex(),
        }
        try:
            result["signature_hash"] = crl.signature_hash_algorithm.name
        except Exception:
            pass
        return result
    except Exception as exc:
        fallback = _binary_fallback(data, "X.509 CRL")
        fallback["parse_error"] = str(exc)
        return fallback


def _certificate_value(data: bytes, timezone_name: str) -> Dict[str, Any]:
    if data in {b"", b"\x00"}:
        return {"type": "X509_CERTIFICATE_PLACEHOLDER", "value": data.hex()}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

        cert = x509.load_der_x509_certificate(data)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key = {"algorithm": "RSA", "size": pub.key_size}
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key = {"algorithm": "EC", "curve": pub.curve.name, "size": pub.key_size}
        elif isinstance(pub, dsa.DSAPublicKey):
            key = {"algorithm": "DSA", "size": pub.key_size}
        else:
            key = {"algorithm": type(pub).__name__}
        result: Dict[str, Any] = {
            "type": "X509_CERTIFICATE",
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": f"{cert.serial_number:x}",
            "not_before": format_datetime(cert.not_valid_before_utc, timezone_name),
            "not_after": format_datetime(cert.not_valid_after_utc, timezone_name),
            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "public_key": key,
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
        try:
            result["signature_hash"] = cert.signature_hash_algorithm.name
        except Exception:
            pass
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            result["is_ca"] = constraints.ca
            result["path_length"] = constraints.path_length
        except x509.ExtensionNotFound:
            pass
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            result["extended_key_usage"] = [oid.dotted_string for oid in eku]
        except x509.ExtensionNotFound:
            pass
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            result["subject_alt_names"] = [str(item.value) for item in san]
        except x509.ExtensionNotFound:
            pass
        return result
    except Exception as exc:
        fallback = _binary_fallback(data, "X.509 certificate")
        fallback["parse_error"] = str(exc)
        return fallback


def _binary_fallback(data: bytes, expected_type: str = "unknown") -> Dict[str, Any]:
    return {
        "type": "UNPARSED_BINARY",
        "expected_type": expected_type,
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "base64": base64.b64encode(data).decode("ascii"),
        "hex": data.hex(),
    }


def _try_text(data: bytes) -> Optional[Dict[str, str]]:
    """Recognise binary values that are really text.

    Almost any even-length byte string decodes as UTF-16 into printable CJK
    code points, so UTF-16 is only accepted when the high byte of most code
    units is zero (Latin text) and UTF-8 only when the bytes decode strictly.
    Anything else stays an unparsed binary with a hash and hex preview.
    """
    if not data:
        return None
    if len(data) % 2 == 0 and len(data) >= 4:
        high_bytes = data[1::2]
        if high_bytes.count(0) >= len(high_bytes) * 0.6:
            try:
                text = data.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                text = ""
            if text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) > 0.9:
                return {"type": "TEXT_BINARY", "encoding": "utf-16-le", "value": text}
    try:
        text = data.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    if text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) > 0.9:
        return {"type": "TEXT_BINARY", "encoding": "utf-8", "value": text}
    return None


def decode_logon_hours(data: bytes, timezone_name: str = DEFAULT_TIMEZONE) -> Dict[str, Any]:
    """Decode AD's 168-bit UTC weekly logon schedule into local-time ranges."""
    if len(data) != 21:
        fallback = _binary_fallback(data, "21-byte logonHours schedule")
        fallback["parse_error"] = f"expected 21 bytes, received {len(data)}"
        return fallback

    allowed_indexes = [
        hour for hour in range(168)
        if data[hour // 8] & (1 << (hour % 8))
    ]
    intervals: Dict[str, List[Tuple[int, int]]] = {
        day: [] for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    }
    reference_sunday = dt.datetime(2024, 1, 7, tzinfo=dt.timezone.utc)
    timezone = _timezone(timezone_name)
    for hour in allowed_indexes:
        start = (reference_sunday + dt.timedelta(hours=hour)).astimezone(timezone)
        end = (reference_sunday + dt.timedelta(hours=hour + 1)).astimezone(timezone)
        start_minute = start.hour * 60 + start.minute
        end_minute = end.hour * 60 + end.minute
        start_day = start.strftime("%A")
        end_day = end.strftime("%A")
        if start_day == end_day and end_minute > start_minute:
            intervals[start_day].append((start_minute, end_minute))
        else:
            intervals[start_day].append((start_minute, 1440))
            if end_minute:
                intervals[end_day].append((0, end_minute))

    def format_minute(value: int) -> str:
        if value == 1440:
            return "24:00"
        return f"{value // 60:02d}:{value % 60:02d}"

    schedule: Dict[str, List[str]] = {}
    for day, ranges in intervals.items():
        merged: List[List[int]] = []
        for start, end in sorted(set(ranges)):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        if merged:
            schedule[day] = [
                f"{format_minute(start)}-{format_minute(end)}" for start, end in merged
            ]
    return {
        "type": "LOGON_HOURS",
        "timezone": timezone_name,
        "allowed_hours": len(allowed_indexes),
        "restriction": "UNRESTRICTED" if len(allowed_indexes) == 168 else "NO_LOGON_ALLOWED" if not allowed_indexes else "RESTRICTED",
        "schedule": schedule,
        "raw_hex": data.hex(),
    }


def decode_binary(
    attr_name: str,
    data: bytes,
    ads_type: Optional[int] = None,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> Any:
    low = attr_name.lower()
    try:
        if low == "logonhours":
            return decode_logon_hours(data, timezone_name)
        if low == "omobjectclass":
            return {"type": "BER_OBJECT_IDENTIFIER", "oid": _decode_oid_content(data), "hex": data.hex()}
        if low == "pkikeyusage":
            return _pki_key_usage(data)
        if low in CRL_ATTRIBUTES:
            return _crl_value(data, timezone_name)
        if low in {"wellknownobjects", "otherwellknownobjects"} and len(data) == 16:
            return {"type": "WELL_KNOWN_OBJECT_GUID", "guid": str(uuid.UUID(bytes_le=data))}
        if low == "msds-hasinstantiatedncs" and len(data) == 4:
            value = struct.unpack("<I", data)[0]
            return {"type": "INSTANCE_TYPE", **decode_flags(value, FLAG_MAPS["instancetype"])}
        if low == "samdomainupdates":
            return {
                "type": "SAM_DOMAIN_UPDATE_BITMAP",
                "hex": data.hex(),
                "set_bits": [index for index in range(len(data) * 8) if data[index // 8] & (1 << (index % 8))],
            }
        if low == "dsasignature" and len(data) >= 24:
            return {
                "type": "DSA_SIGNATURE_STATE",
                "version": struct.unpack_from("<I", data, 0)[0],
                "declared_length": struct.unpack_from("<I", data, 4)[0],
                "invocation_id": str(uuid.UUID(bytes_le=data[-16:])),
                "hex": data.hex(),
            }
        if low in SID_ATTRIBUTES or low.endswith("sid"):
            return sid_value(data)
        if low in GUID_ATTRIBUTES or (len(data) == 16 and low.endswith("guid")):
            return {"guid": str(uuid.UUID(bytes_le=data))}
        if low == "dnsrecord":
            return parse_dns_record(data, timezone_name)
        if low == "msdfs-targetlistv2":
            return parse_dfs_target_list(data)
        if low in SECURITY_DESCRIPTOR_ATTRIBUTES or ads_type == 25:
            return parse_security_descriptor(data)
        if low in CERTIFICATE_ATTRIBUTES:
            return _certificate_value(data, timezone_name)
        if low in DURATION_ATTRIBUTES and len(data) == 8:
            raw = struct.unpack("<q", data)[0]
            return duration_to_string(raw)
        text = _try_text(data)
        if text:
            return text
    except Exception as exc:
        fallback = _binary_fallback(data, attr_name)
        fallback["parse_error"] = str(exc)
        return fallback
    return _binary_fallback(data, attr_name)


def decode_attribute(
    attr_name: str,
    value: Any,
    ads_type: Optional[int] = None,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> Any:
    return _decode_lower(attr_name, attr_name.lower(), value, ads_type, timezone_name)


def _decode_lower(attr_name: str, low: str, value: Any, ads_type: Optional[int], timezone_name: str) -> Any:
    kind = type(value)
    if kind is str:
        if low == "userworkstations":
            workstations = [item.strip() for item in value.split(",") if item.strip()]
            return {"restricted": bool(workstations), "count": len(workstations), "workstations": workstations}
        return value
    if kind is int:
        if low in FILETIME_ATTRIBUTES:
            return filetime_to_string(value, timezone_name)
        if low in UTC_TIME_ATTRIBUTES or ads_type == 9:
            return epoch_to_string(value, timezone_name)
        if low in DURATION_ATTRIBUTES:
            return duration_to_string(value)
        if low in FLAG_MAPS:
            return decode_flags(value, FLAG_MAPS[low])
        if low in ENUM_MAPS:
            return {"value": value, "name": ENUM_MAPS[low].get(value, "UNKNOWN")}
        if low in {"shadowexpire", "shadowlastchange"}:
            if value < 0:
                return "Never"
            date_value = dt.date(1970, 1, 1) + dt.timedelta(days=value)
            return f"{date_value.isoformat()} ({value} days since Unix epoch)"
        if low == "versionnumber":
            return {"value": value, "user_version": (value >> 16) & 0xFFFF, "computer_version": value & 0xFFFF}
        return value
    if kind is list or kind is tuple:
        return [_decode_lower(attr_name, low, item, ads_type, timezone_name) for item in value]
    if kind is bytes:
        return decode_binary(attr_name, value, ads_type, timezone_name)
    if isinstance(value, dt.datetime):
        return format_datetime(value, timezone_name)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _decode_lower(attr_name, low, int(value), ads_type, timezone_name)
    if isinstance(value, bytes):
        return decode_binary(attr_name, bytes(value), ads_type, timezone_name)
    return value


def decode_record(
    record: Dict[str, Any],
    ads_types: Optional[Dict[str, int]] = None,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> Dict[str, Any]:
    ads_types = ads_types or {}
    get_type = ads_types.get
    return {
        name: _decode_lower(name, low, value, get_type(low), timezone_name)
        for name, value in record.items()
        for low in (name.lower(),)
    }


def json_default(value: Any) -> Any:
    """Preserve non-JSON decoder values instead of failing on nested data."""
    if isinstance(value, bytes):
        return _binary_fallback(value)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def compact_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=json_default,
    )


# Keys whose values are raw binary renderings; never worth full-text indexing.
_SEARCH_BINARY_KEYS = frozenset({"hex", "base64", "der", "raw", "bytes"})


def _is_security_descriptor(value: Dict[str, Any]) -> bool:
    if value.get("type") == "SECURITY_DESCRIPTOR_RELATIVE":
        return True
    return "dacl" in value and ("owner" in value or "group" in value)


def _trustee_tokens(entity: Any, out: List[str]) -> None:
    if isinstance(entity, dict):
        sid = entity.get("sid")
        if isinstance(sid, str) and sid:
            out.append(sid)
        name = entity.get("well_known_name")
        if isinstance(name, str) and name:
            out.append(name)


def _security_descriptor_tokens(sd: Dict[str, Any], out: List[str]) -> None:
    """Index the real identities in a descriptor, not its per-ACE expansion.

    Owner, group, and every ACE trustee (SID plus well-known name) stay
    searchable. The bulky, repetitive parts an operator does not substring
    search - per-ACE access-mask name lists, control/inheritance flags, and
    object-type GUIDs - are deliberately omitted so the full-text index does
    not carry the descriptor's expanded form.
    """
    _trustee_tokens(sd.get("owner"), out)
    _trustee_tokens(sd.get("group"), out)
    for acl_key in ("dacl", "sacl"):
        acl = sd.get(acl_key)
        if not isinstance(acl, dict):
            continue
        for ace in acl.get("aces", []) or []:
            if isinstance(ace, dict):
                _trustee_tokens(ace.get("trustee"), out)


def _search_tokens(value: Any, out: List[str]) -> None:
    kind = type(value)
    if kind is str:
        if value:
            out.append(value)
    elif kind is list:
        for item in value:
            if type(item) is str:
                if item:
                    out.append(item)
            else:
                _search_tokens(item, out)
    elif kind is dict:
        if _is_security_descriptor(value):
            _security_descriptor_tokens(value, out)
            return
        for key, item in value.items():
            if key not in _SEARCH_BINARY_KEYS:
                _search_tokens(item, out)
    elif kind is int:
        out.append(str(value))
    elif kind is bool:
        out.append("true" if value else "false")
    elif value is None or kind is bytes:
        return
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _search_tokens(item, out)
    elif isinstance(value, (int, float)):
        out.append(str(value))
    else:
        out.append(str(value))


def build_search_text(decoded: Dict[str, Any], attribute_names: Sequence[str]) -> str:
    """Build the compact full-text payload for one decoded object.

    Includes attribute names plus the object's real, human-searchable values
    (strings, SIDs, GUIDs, well-known names, flag names, numbers). Security
    descriptor internals and raw base64/hex binary renderings are excluded so
    the index stays small; the full decoded object is still stored verbatim in
    the compressed detail blob and shown unchanged in the detail view.
    Duplicate tokens are collapsed, which does not affect substring matching.
    """
    tokens: List[str] = list(attribute_names)
    _search_tokens(decoded, tokens)
    return "\n".join(dict.fromkeys(token for token in tokens if token))
