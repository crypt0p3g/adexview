"""In-memory directory records for the audit, with cheap case-insensitive access.

Records are plain ``dict`` subclasses keyed by the snapshot's canonical
attribute names. Case-insensitive lookups resolve through the shared
:class:`Schema` table in O(1) instead of scanning every key, and per-record
facts the analyses ask for repeatedly (object classes, folded DN, SID) are
cached on the record. Security descriptors are not held in memory at all: they
are read from the memory-mapped snapshot on demand, which keeps the resident
size of a large domain to the attributes the checks actually use.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from ..decoders import parse_sid
from ..snapshot import SnapshotReader

AUDIT_ATTRIBUTES = [
    "distinguishedName", "objectClass", "objectCategory", "objectGUID", "objectSid",
    "name", "cn", "displayName", "description", "info", "comment", "whenCreated",
    "whenChanged", "uSNCreated", "uSNChanged", "sAMAccountName", "userPrincipalName",
    "mail", "proxyAddresses", "member", "memberOf", "primaryGroupID", "adminCount",
    "userAccountControl", "sAMAccountType", "pwdLastSet", "lastLogon",
    "lastLogonTimestamp", "badPasswordTime", "badPwdCount", "accountExpires",
    "lastLogoff", "logonCount", "lockoutTime", "logonHours", "userWorkstations",
    "msDS-User-Account-Control-Computed", "msDS-UserPasswordExpiryTimeComputed",
    "servicePrincipalName", "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-AssignedAuthNPolicy", "msDS-AssignedAuthNPolicySilo",
    "msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo",
    "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval", "dNSHostName",
    "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
    "groupType", "sIDHistory", "gPLink", "gPOptions", "flags", "versionNumber",
    "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames",
    "fSMORoleOwner", "ms-DS-MachineAccountQuota", "minPwdLength", "minPwdAge",
    "maxPwdAge", "pwdHistoryLength", "lockoutThreshold", "lockoutDuration",
    "lockOutObservationWindow", "forceLogoff", "pwdProperties", "nextRid",
    "msDS-Behavior-Version", "nTMixedDomain", "wellKnownObjects", "otherWellKnownObjects",
    "rIDManagerReference", "msDS-AllUsersTrustQuota", "msDS-AllUsersQuota",
    "msDS-DefaultComputer", "msDS-DefaultUser", "nCName", "dnsRoot", "nETBIOSName",
    "msDS-SDReferenceDomain", "trustPartner", "trustDirection",
    "trustType", "trustAttributes", "flatName", "securityIdentifier", "siteObject",
    "location", "cost", "replInterval", "siteList", "options", "dnsRecord",
    "dNSTombstoned", "dnsProperty", "msDFS-TargetListv2", "msDFS-LinkPathv2",
    "remoteServerName", "uNCName", "keywords", "certificateTemplates", "cACertificate",
    "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature", "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size",
    "pKIExpirationPeriod", "pKIOverlapPeriod", "nTSecurityDescriptor",
    "msPKI-Template-Schema-Version", "msPKI-Template-Minor-Revision",
    "ms-Mcs-AdmPwdExpirationTime", "ms-Mcs-AdmPwd",
    "msLAPS-PasswordExpirationTime", "msLAPS-Password",
    "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
    "msDS-KeyCredentialLink",
    "msFVE-RecoveryGuid", "msFVE-VolumeGuid", "msDS-QuotaTrustee",
    "msDS-DefaultQuota", "msDS-QuotaEffective", "msDS-QuotaUsed", "lDAPDisplayName",
    "attributeID", "attributeSyntax", "oMSyntax", "isSingleValued", "systemOnly",
    "isDefunct", "searchFlags", "systemFlags", "schemaIDGUID", "attributeSecurityGUID",
    "isMemberOfPartialAttributeSet", "defaultSecurityDescriptor", "lastKnownParent",
    "msDS-LastKnownRDN", "isDeleted", "pKT", "msDFS-Commentv2",
    "msDFS-LastModifiedv2", "msDFS-SchemaMajorVersion", "msDFS-SchemaMinorVersion",
    "msDFS-NamespaceIdentityGUIDv2", "msDFS-Propertiesv2", "msDFSR-Flags",
    "msDFSR-ReplicationGroupGuid", "msDFSR-ReplicationGroupType", "msDFSR-FileFilter",
    "msDFSR-DirectoryFilter", "msDFSR-ComputerReference", "msDFSR-ComputerReferenceBL",
    "msDFSR-MemberReference", "msDFSR-MemberReferenceBL", "msDFSR-Version",
    "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-Enabled", "msDFSR-Options",
    "msDFSR-ContentSetGuid", "msDFSR-ReadOnly",
    "scriptPath", "profilePath", "homeDirectory", "homeDrive", "userParameters",
    "terminalServer", "msTSAllowLogon", "msTSHomeDirectory", "msTSHomeDrive",
    "msTSProfilePath", "msNPAllowDialin", "loginShell", "unixHomeDirectory",
    "uid", "uidNumber", "gidNumber", "gecos", "shadowExpire", "shadowLastChange",
]

# Large per-object blobs the checks only need for a small set of objects. They
# are fetched from the snapshot on demand rather than held for every record.
LAZY_ATTRIBUTES = frozenset({"ntsecuritydescriptor", "cacertificate"})

SENSITIVE_ATTRIBUTES = {
    "authpassword", "ctscpasswordhistory", "dbcspwd", "lmpwdhistory",
    "ms-mcs-admpwd", "ms-mcs-admpwdhistory", "msds-keycredentiallink",
    "msds-managedpassword", "msds-managedpasswordpreviousid",
    "msfve-recoverypassword", "mskds-rootkeydata", "mslaps-encryptedpassword",
    "mslaps-encryptedpasswordhistory", "mslaps-encrypteddsrmpassword",
    "mslaps-password", "mslaps-passwordhistory", "mspki-credentialroamingtokens",
    "mspkiaccountcredentials", "mssfu30password", "mortextpassword",
    "ntpwdhistory", "os400password", "privatekey", "supplementalcredentials",
    "unicodepwd", "unixuserpassword", "userpassword",
}

SENSITIVE_ATTRIBUTE_DISPLAY_NAMES = {
    name.casefold(): name for name in (
        "authPassword", "ctscPasswordHistory", "dBCSPwd", "lmPwdHistory",
        "morTextPassword", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdHistory",
        "msDS-KeyCredentialLink", "msDS-ManagedPassword",
        "msDS-ManagedPasswordPreviousId", "msFVE-RecoveryPassword",
        "msKds-RootKeyData", "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword",
        "msLAPS-Password", "msLAPS-PasswordHistory",
        "msPKI-CredentialRoamingTokens", "msPKIAccountCredentials",
        "msSFU30Password", "ntPwdHistory", "os400Password", "privateKey",
        "supplementalCredentials", "unicodePwd", "unixUserPassword",
        "userPassword",
    )
}

SECRET_NAME_PATTERN = re.compile(
    r"(?i)(password|passwd|(^|[-_])pwd($|[-_])|secret|credential|private.?key|recoverypassword)"
)

BENIGN_SECRET_LIKE_ATTRIBUTES = {
    "badpasswordtime", "badpwdcount", "lockouttime", "machinepasswordchangeinterval",
    "maxpwdage", "minpwdage", "msds-expirepasswordsonsmartcardonlyaccounts",
    "msds-failedinteractivelogoncountatlastsuccessfullogon", "msds-managedpasswordid",
    "msds-managedpasswordinterval", "msds-maximumpasswordage", "msds-minimumpasswordage",
    "msds-minimumpasswordlength", "msds-passwordcomplexityenabled",
    "msds-passwordhistorylength", "msds-passwordreversibleencryptionenabled",
    "msds-passwordsettingsprecedence", "msds-userpasswordexpirytimecomputed",
    "mskds-secretagreementalgorithmid", "mskds-secretagreementparam",
    "mspki-private-key-flag", "mskds-privatekeylength", "pwdhistorylength",
    "pwdlastset", "pwdproperties", "secretary",
}

HIGH_INTEREST_ATTRIBUTES = {
    "altsecurityidentities", "description", "gplink", "homedirectory", "homedrive",
    "info", "logonhours", "loginshell", "msds-allowedtoactonbehalfofotheridentity",
    "msds-allowedtodelegateto", "msds-keycredentiallink", "profilepath", "scriptpath",
    "msds-assignedauthnpolicy", "msds-assignedauthnpolicysilo",
    "msds-userallowedtoauthenticatefrom", "msds-userallowedtoauthenticateto",
    "serviceprincipalname", "sidhistory", "userparameters", "userworkstations",
}

UAC = {
    "LOCKOUT": 0x0010,
    "DISABLED": 0x0002,
    "PASSWORD_NOT_REQUIRED": 0x0020,
    "REVERSIBLE_PASSWORD": 0x0080,
    "DOMAIN_CONTROLLER": 0x2000,
    "PASSWORD_NEVER_EXPIRES": 0x10000,
    "SMARTCARD_REQUIRED": 0x40000,
    "UNCONSTRAINED_DELEGATION": 0x80000,
    "NOT_DELEGATED": 0x100000,
    "DES_ONLY": 0x200000,
    "NO_PREAUTH": 0x400000,
    "PROTOCOL_TRANSITION": 0x1000000,
    "PASSWORD_EXPIRED": 0x800000,
}

_MISSING = object()


class Schema:
    """Shared per-snapshot lookup tables for :class:`Record`."""

    __slots__ = ("reader", "canonical", "ads_types")

    def __init__(self, reader: Optional[SnapshotReader]):
        self.reader = reader
        properties = reader.properties if reader is not None else ()
        self.canonical: Dict[str, str] = {prop.name.casefold(): prop.name for prop in properties}
        self.ads_types: Dict[str, int] = {prop.name.casefold(): prop.ads_type for prop in properties}


class Record(dict):
    """One directory object loaded for the audit."""

    __slots__ = ("schema", "offset", "_classes", "_dn_key", "_sid", "_lazy")

    def __init__(self, schema: Schema, offset: int, values: Dict[str, Any]):
        super().__init__(values)
        self.schema = schema
        self.offset = offset
        self._classes: Optional[FrozenSet[str]] = None
        self._dn_key: Optional[str] = None
        self._sid: Optional[str] = None
        self._lazy: Optional[Dict[str, Any]] = None

    def lazy_value(self, name: str) -> Any:
        """Fetch one of the LAZY_ATTRIBUTES straight from the snapshot."""
        low = name.casefold()
        if self._lazy is not None and low in self._lazy:
            return self._lazy[low]
        reader = self.schema.reader
        value: Any = None
        if reader is not None and low in self.schema.canonical:
            try:
                values = reader.entry_at_offset(self.offset).get_attribute_values(
                    self.schema.canonical[low], raw=True,
                )
            except (KeyError, ValueError):
                values = []
            if values:
                value = values[0] if len(values) == 1 else values
        if self._lazy is None:
            self._lazy = {}
        self._lazy[low] = value
        return value


def ci_get(record: Dict[str, Any], name: str, default: Any = None) -> Any:
    """Case-insensitive attribute lookup that is O(1) for audit records."""
    value = record.get(name, _MISSING)
    if value is not _MISSING:
        return value
    low = name.casefold()
    if isinstance(record, Record):
        canonical = record.schema.canonical.get(low)
        if canonical is not None and canonical != name:
            value = record.get(canonical, _MISSING)
            if value is not _MISSING:
                return value
        if low in LAZY_ATTRIBUTES:
            value = record.lazy_value(name)
            return default if value is None else value
        return default
    for key, value in record.items():
        if key.casefold() == low:
            return value
    return default


def as_list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def classes(record: Dict[str, Any]) -> FrozenSet[str]:
    if isinstance(record, Record):
        cached = record._classes
        if cached is None:
            cached = record._classes = frozenset(
                str(item).casefold() for item in as_list(ci_get(record, "objectClass", []))
            )
        return cached
    return frozenset(str(item).casefold() for item in as_list(ci_get(record, "objectClass", [])))


def is_user(record: Dict[str, Any]) -> bool:
    item_classes = classes(record)
    return "user" in item_classes and "computer" not in item_classes


def is_computer(record: Dict[str, Any]) -> bool:
    return "computer" in classes(record)


def has_uac(record: Dict[str, Any], flag: str) -> bool:
    return bool(as_int(ci_get(record, "userAccountControl")) & UAC[flag])


def dn(record: Dict[str, Any]) -> str:
    return str(ci_get(record, "distinguishedName", ""))


def dn_key(record: Dict[str, Any]) -> str:
    """Case-folded DN, cached for audit records."""
    if isinstance(record, Record):
        cached = record._dn_key
        if cached is None:
            cached = record._dn_key = dn(record).casefold()
        return cached
    return dn(record).casefold()


def object_name(record: Dict[str, Any]) -> str:
    return str(
        ci_get(record, "sAMAccountName") or ci_get(record, "displayName")
        or ci_get(record, "name") or dn(record)
    )


def sid_string(record: Dict[str, Any], attribute: str = "objectSid") -> str:
    if attribute == "objectSid" and isinstance(record, Record) and record._sid is not None:
        return record._sid
    value = ci_get(record, attribute, "")
    if isinstance(value, bytes):
        try:
            text = parse_sid(value)
        except ValueError:
            text = ""
    else:
        text = str(value)
    if attribute == "objectSid" and isinstance(record, Record):
        record._sid = text
    return text


def short_dn(value: Any) -> str:
    text = str(value or "")
    first = text.split(",", 1)[0]
    return first.split("=", 1)[1] if "=" in first else text


def is_sensitive_attribute(name: str) -> bool:
    low = name.casefold()
    if low in SENSITIVE_ATTRIBUTES:
        return True
    return bool(SECRET_NAME_PATTERN.search(low)) and low not in BENIGN_SECRET_LIKE_ATTRIBUTES


class Directory:
    """Every audited object plus the indexes the analyses share."""

    def __init__(self, reader: SnapshotReader, records: List[Record]):
        self.reader = reader
        self.records = records
        self.by_dn: Dict[str, Record] = {}
        self.by_sid: Dict[str, Record] = {}
        for item in records:
            key = dn_key(item)
            if key:
                self.by_dn[key] = item
            sid = sid_string(item)
            if sid:
                self.by_sid[sid] = item

    @property
    def ads_types(self) -> Dict[str, int]:
        return self.reader.ads_types


def load_directory(
    reader: SnapshotReader,
    attributes: Sequence[str] = AUDIT_ATTRIBUTES,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Directory:
    """Load the audit attribute selection for every object into memory."""
    schema = Schema(reader)
    available = set(schema.canonical)
    selected = [
        name for name in dict.fromkeys(attributes)
        if name.casefold() in available and name.casefold() not in LAZY_ATTRIBUTES
    ]
    wanted = reader.get_property_indices(selected)
    total = max(1, reader.header.num_objects)
    interval = max(1, total // 100)
    records: List[Record] = []
    # Class names, categories and operating-system strings repeat across most
    # objects; sharing one string object per distinct value keeps a large
    # directory's resident size down.
    shared: Dict[str, str] = {}
    shared_lists: Dict[Tuple[str, ...], List[str]] = {}
    shared_names = {"objectClass", "objectCategory", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack"}
    for index, entry in enumerate(reader.iter_entries(), start=1):
        values = {}
        for name, items in entry.raw_items(wanted):
            if name in shared_names:
                if len(items) == 1:
                    values[name] = shared.setdefault(items[0], items[0])
                else:
                    key = tuple(items)
                    values[name] = shared_lists.setdefault(key, [shared.setdefault(item, item) for item in items])
            else:
                values[name] = _collapse(items)
        records.append(Record(schema, entry.offset, values))
        if progress and (index == 1 or index % interval == 0 or index == total):
            progress(index, total)
    return Directory(reader, records)


def _collapse(values: List[Any]) -> Any:
    if not values:
        return []
    if len(values) == 1:
        return values[0]
    return values


def build_by_dn(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {dn_key(item): item for item in records if dn(item)}


def build_by_sid(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {sid: item for item in records if (sid := sid_string(item))}
