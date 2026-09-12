"""Saved LDAP queries, their result columns, and the computed audit reports."""

from __future__ import annotations

from typing import Any, Dict, List

SENSITIVE_QUERY_ATTRIBUTES = [
    "authPassword", "ctscPasswordHistory", "dBCSPwd", "lmPwdHistory",
    "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdHistory", "msDS-KeyCredentialLink",
    "msDS-ManagedPassword", "msDS-ManagedPasswordPreviousId",
    "msDS-ExecuteScriptPassword",
    "msFVE-RecoveryPassword", "msKds-RootKeyData", "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword",
    "msLAPS-Password", "msLAPS-PasswordHistory",
    "msPKI-CredentialRoamingTokens", "msPKIAccountCredentials",
    "msSFU30Password", "morTextPassword", "ntPwdHistory", "os400Password",
    "privateKey", "supplementalCredentials", "unicodePwd", "unixUserPassword",
    "userPassword",
]

AUDIT_QUERY_PRESETS: List[Dict[str, Any]] = [
    {"report": "02_domain_info.csv / 03_password_policy.csv", "name": "Domain and password policy", "filter": "(&(objectClass=domainDNS)(objectSid=*))"},
    {"report": "03b_directory_partitions.csv", "name": "Directory partitions", "filter": "(objectClass=crossRef)"},
    {"report": "04_domain_controllers.csv", "name": "Domain controllers", "filter": "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"},
    {"report": "06_privileged_objects.csv", "name": "Admin-count protected objects", "filter": "(adminCount=1)"},
    {"report": "07_users.csv", "name": "Users", "filter": "(&(objectClass=user)(!(objectClass=computer)))"},
    {"report": "08_spn_users.csv", "name": "SPN-enabled user accounts", "filter": "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*))"},
    {"report": "09_asrep_candidates.csv", "name": "Enabled AS-REP roastable users", "filter": "(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"},
    {"report": "10_computers.csv", "name": "Computers", "filter": "(objectClass=computer)"},
    {"report": "10c_service_inventory.csv", "name": "Service inventory (SQL, Exchange, SCCM, ADFS, WinRM…)", "filter": "(|(servicePrincipalName=MSSQLSvc*)(servicePrincipalName=exchangeMDB*)(servicePrincipalName=exchangeRFR*)(servicePrincipalName=TERMSRV*)(servicePrincipalName=WSMAN*)(servicePrincipalName=adfs*)(servicePrincipalName=DNS*)(servicePrincipalName=ftp*)(servicePrincipalName=DHCPServer*)(objectClass=serviceConnectionPoint))"},
    {"report": "11_delegation.csv", "name": "Delegation source objects", "filter": "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"},
    {"report": "12_groups.csv", "name": "Groups", "filter": "(objectClass=group)"},
    {"report": "13_trusts.csv", "name": "Domain trusts", "filter": "(objectClass=trustedDomain)"},
    {"report": "14_gpos.csv", "name": "Group Policy objects", "filter": "(objectClass=groupPolicyContainer)"},
    {"report": "15_gpo_links.csv", "name": "Objects with GPO links", "filter": "(gPLink=*)"},
    {"report": "16_sites.csv", "name": "AD sites", "filter": "(objectClass=site)"},
    {"report": "17_subnets.csv", "name": "AD subnets", "filter": "(objectClass=subnet)"},
    {"report": "18_dns_records.csv", "name": "DNS nodes", "filter": "(objectClass=dnsNode)"},
    {"report": "19_published_shares.csv", "name": "Published share source objects", "filter": "(|(uNCName=*)(objectClass=volume)(msDFS-TargetListv2=*))"},
    {"report": "20_dfs_targets.csv", "name": "DFS targets", "filter": "(msDFS-TargetListv2=*)"},
    {"report": "20a_dfs_namespaces.csv", "name": "DFS namespaces", "filter": "(|(objectClass=fTDfs)(objectClass=msDFS-Linkv2)(objectClass=msDFS-NamespaceAnchor)(objectClass=msDFS-Namespacev2))"},
    {"report": "20b_dfsr_replication_groups.csv", "name": "DFSR replication groups", "filter": "(objectClass=msDFSR-ReplicationGroup)"},
    {"report": "20c_dfsr_members.csv", "name": "DFSR members", "filter": "(objectClass=msDFSR-Member)"},
    {"report": "20d_dfsr_subscriptions.csv", "name": "DFSR subscriptions", "filter": "(objectClass=msDFSR-Subscription)"},
    {"report": "20e_dfsr_all_objects.csv", "name": "All DFSR objects", "filter": "(|(objectClass=msDFSR-*)(objectClass=dfsConfiguration))"},
    {"report": "21_certificate_authorities.csv", "name": "Enterprise certificate authorities", "filter": "(objectClass=pKIEnrollmentService)"},
    {"report": "22_certificate_templates.csv", "name": "Certificate templates", "filter": "(objectClass=pKICertificateTemplate)"},
    {"report": "24_managed_service_accounts.csv", "name": "Managed service accounts", "filter": "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))"},
    {"report": "25_laps_inventory.csv", "name": "LAPS-managed computers", "filter": "(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))"},
    {"report": "26_bitlocker_inventory.csv", "name": "BitLocker recovery objects", "filter": "(objectClass=msFVE-RecoveryInformation)"},
    {"report": "27_quotas.csv", "name": "Directory quotas", "filter": "(|(objectClass=msDS-QuotaControl)(msDS-DefaultQuota=*))"},
    {"report": "28_schema_attributes.csv", "name": "Schema attributes", "filter": "(objectClass=attributeSchema)"},
    {"report": "29_custom_schema_attributes.csv", "name": "Extension and custom schema attributes", "filter": "(&(objectClass=attributeSchema)(!(systemFlags:1.2.840.113556.1.4.803:=16)))"},
    {"report": "31_sensitive_attribute_values.csv", "name": "Known sensitive attributes", "filter": "(|" + "".join(f"({name}=*)" for name in SENSITIVE_QUERY_ATTRIBUTES) + ")"},
    {"report": "31_sensitive_attribute_schema.csv", "name": "Sensitive-looking schema attributes", "filter": "(&(objectClass=attributeSchema)(|(lDAPDisplayName=*password*)(lDAPDisplayName=*passwd*)(lDAPDisplayName=*pwd*)(lDAPDisplayName=*secret*)(lDAPDisplayName=*credential*)(lDAPDisplayName=*private*key*)(lDAPDisplayName=*recovery*password*)))"},
    {"report": "33_free_text_values.csv", "name": "Objects with descriptions, comments, notes, or info", "filter": "(|(description=*)(info=*)(comment=*)(notes=*))"},
]

# Computed analyses stored by the audit in small SQLite tables; the viewer
# shows each as a button. Keys are the API names, values the table names.
COMPUTED_REPORTS = {
    "findings": "audit_findings",
    "dangerous_acls": "audit_dangerous_acls",
    "rbcd": "audit_rbcd",
    "certificate_template_acl": "audit_certificate_template_acl",
    "privileged_members": "audit_privileged_members",
    "dns_name_to_ip": "audit_dns_name_to_ip",
    "certificate_findings": "audit_certificate_findings",
    "custom_attribute_usage": "audit_custom_attribute_usage",
    "sensitive_attribute_schema": "audit_sensitive_attribute_schema",
}

USER_FIELDS = [
    "sAMAccountName", "displayName", "userPrincipalName", "mail", "description",
    "userAccountControl", "msDS-User-Account-Control-Computed",
    "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp",
    "lastLogoff", "logonCount", "badPasswordTime", "badPwdCount", "lockoutTime",
    "accountExpires", "logonHours", "userWorkstations", "adminCount", "memberOf",
    "servicePrincipalName", "msDS-SupportedEncryptionTypes", "msDS-AssignedAuthNPolicy",
    "msDS-AssignedAuthNPolicySilo", "whenCreated", "whenChanged", "distinguishedName",
]
COMPUTER_FIELDS = [
    "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "description",
    "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "servicePrincipalName",
    "msDS-SupportedEncryptionTypes", "whenCreated", "whenChanged", "distinguishedName",
]
DEFAULT_PRESET_FIELDS = [
    "name", "objectClass", "description", "whenCreated", "whenChanged", "distinguishedName",
]
SCHEMA_FIELDS = ["distinguishedName", "lDAPDisplayName", "attributeID", "attributeSyntax", "oMSyntax", "isSingleValued", "systemOnly", "isDefunct", "searchFlags", "systemFlags", "schemaIDGUID", "attributeSecurityGUID", "isMemberOfPartialAttributeSet", "whenCreated", "whenChanged"]
AUDIT_PRESET_FIELDS = {
    "02_domain_info.csv / 03_password_policy.csv": ["distinguishedName", "name", "objectSid", "msDS-Behavior-Version", "nTMixedDomain", "fSMORoleOwner", "ms-DS-MachineAccountQuota", "minPwdLength", "minPwdAge", "maxPwdAge", "pwdHistoryLength", "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "forceLogoff", "whenCreated", "whenChanged"],
    "03b_directory_partitions.csv": ["distinguishedName", "cn", "nCName", "dnsRoot", "nETBIOSName", "systemFlags", "msDS-SDReferenceDomain", "whenCreated", "whenChanged"],
    "07_users.csv": USER_FIELDS,
    "08_spn_users.csv": USER_FIELDS,
    "09_asrep_candidates.csv": USER_FIELDS,
    "06_privileged_objects.csv": USER_FIELDS,
    "10_computers.csv": COMPUTER_FIELDS,
    "10c_service_inventory.csv": ["distinguishedName", "objectClass", "dNSHostName", "sAMAccountName", "operatingSystem", "servicePrincipalName", "whenChanged"],
    "04_domain_controllers.csv": COMPUTER_FIELDS,
    "11_delegation.csv": ["distinguishedName", "objectClass", "sAMAccountName", "dNSHostName", "userAccountControl", "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "whenChanged"],
    "12_groups.csv": ["distinguishedName", "sAMAccountName", "description", "objectSid", "groupType", "adminCount", "managedBy", "member", "memberOf", "whenCreated", "whenChanged"],
    "13_trusts.csv": ["distinguishedName", "trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "securityIdentifier", "whenCreated", "whenChanged"],
    "14_gpos.csv": ["distinguishedName", "displayName", "name", "flags", "versionNumber", "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames", "whenCreated", "whenChanged"],
    "15_gpo_links.csv": ["distinguishedName", "objectClass", "name", "gPLink", "gPOptions", "whenCreated", "whenChanged"],
    "16_sites.csv": ["distinguishedName", "cn", "description", "location", "whenCreated", "whenChanged"],
    "17_subnets.csv": ["distinguishedName", "cn", "description", "siteObject", "location", "whenCreated", "whenChanged"],
    "18_dns_records.csv": ["distinguishedName", "name", "dnsRecord", "whenCreated", "whenChanged"],
    "19_published_shares.csv": ["distinguishedName", "name", "uNCName", "description", "whenCreated", "whenChanged"],
    "20_dfs_targets.csv": ["distinguishedName", "name", "msDFS-LinkPathv2", "msDFS-TargetListv2"],
    "20a_dfs_namespaces.csv": ["distinguishedName", "objectClass", "name", "description", "remoteServerName", "uNCName", "msDFS-LinkPathv2", "msDFS-TargetListv2", "msDFS-Commentv2", "msDFS-LastModifiedv2", "whenCreated", "whenChanged"],
    "20b_dfsr_replication_groups.csv": ["distinguishedName", "name", "description", "msDFSR-ReplicationGroupGuid", "msDFSR-ReplicationGroupType", "msDFSR-Flags", "msDFSR-MemberReference", "whenCreated", "whenChanged"],
    "20c_dfsr_members.csv": ["distinguishedName", "name", "description", "msDFSR-ComputerReference", "msDFSR-MemberReferenceBL", "msDFSR-Options", "whenCreated", "whenChanged"],
    "20d_dfsr_subscriptions.csv": ["distinguishedName", "name", "description", "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-Enabled", "msDFSR-ReadOnly", "msDFSR-ContentSetGuid", "msDFSR-MemberReference", "whenCreated", "whenChanged"],
    "20e_dfsr_all_objects.csv": ["distinguishedName", "objectClass", "name", "description", "msDFSR-ReplicationGroupGuid", "msDFSR-ReplicationGroupType", "msDFSR-ComputerReference", "msDFSR-MemberReference", "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-Enabled", "msDFSR-ReadOnly", "msDFSR-ContentSetGuid", "whenCreated", "whenChanged"],
    "21_certificate_authorities.csv": ["distinguishedName", "cn", "dNSHostName", "certificateTemplates", "flags", "cACertificate", "whenCreated", "whenChanged"],
    "22_certificate_templates.csv": ["distinguishedName", "cn", "displayName", "pKIExtendedKeyUsage", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag", "msPKI-Minimal-Key-Size", "pKIExpirationPeriod", "pKIOverlapPeriod", "msPKI-RA-Signature", "nTSecurityDescriptor", "whenCreated", "whenChanged"],
    "24_managed_service_accounts.csv": ["distinguishedName", "objectClass", "sAMAccountName", "servicePrincipalName", "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval", "msDS-SupportedEncryptionTypes", "pwdLastSet", "whenCreated", "whenChanged"],
    "25_laps_inventory.csv": ["distinguishedName", "sAMAccountName", "dNSHostName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"],
    "26_bitlocker_inventory.csv": ["distinguishedName", "name", "msFVE-RecoveryGuid", "msFVE-VolumeGuid", "msFVE-RecoveryPassword", "whenCreated", "whenChanged"],
    "27_quotas.csv": ["distinguishedName", "name", "msDS-QuotaTrustee", "msDS-DefaultQuota", "msDS-QuotaEffective", "msDS-QuotaUsed", "whenCreated", "whenChanged"],
    "28_schema_attributes.csv": SCHEMA_FIELDS,
    "29_custom_schema_attributes.csv": SCHEMA_FIELDS,
    "31_sensitive_attribute_values.csv": ["distinguishedName", "objectClass", "sAMAccountName", "name", *SENSITIVE_QUERY_ATTRIBUTES],
    "31_sensitive_attribute_schema.csv": ["lDAPDisplayName", "attributeID", "attributeSyntax", "oMSyntax", "isSingleValued", "systemOnly", "searchFlags", "systemFlags", "whenChanged", "distinguishedName"],
    "33_free_text_values.csv": ["name", "objectClass", "sAMAccountName", "description", "info", "comment", "notes", "whenChanged", "distinguishedName"],
}

# Conservative SQL supersets, evaluated on the summary row_json (no blob decode),
# used to narrow a preset scan to plausible candidates before the exact LDAP
# filter runs. Column indices: [2]=objectType, [3]=objectClass, [7]=SPN. Each
# clause MUST include every real match (it may include extras; the LDAP filter
# still refines), so presets whose attribute is not in the summary get none.
_OT = "json_extract(row_json,'$[2]')"
_OC = "json_extract(row_json,'$[3]')"
_SPN = "json_extract(row_json,'$[7]')"
PRESET_PREFILTERS = {
    "07_users.csv": f"{_OT}='user'",
    "08_spn_users.csv": f"{_OT}='user' AND {_SPN}<>''",
    "09_asrep_candidates.csv": f"{_OT}='user'",
    "10_computers.csv": f"{_OT}='computer'",
    "04_domain_controllers.csv": f"{_OT}='computer'",
    "12_groups.csv": f"{_OT}='group'",
    "18_dns_records.csv": f"{_OT}='dnsnode'",
    "11_delegation.csv": f"{_OT} IN ('user','computer')",
    "10c_service_inventory.csv": f"({_SPN}<>'' OR {_OC} LIKE '%serviceConnectionPoint%')",
    "25_laps_inventory.csv": f"{_OT}='computer'",
    "24_managed_service_accounts.csv": f"{_OC} LIKE '%ManagedServiceAccount%'",
    "13_trusts.csv": f"{_OC} LIKE '%trustedDomain%'",
    "14_gpos.csv": f"{_OC} LIKE '%groupPolicyContainer%'",
    "16_sites.csv": f"{_OC} LIKE '%site%'",
    "17_subnets.csv": f"{_OC} LIKE '%subnet%'",
    "21_certificate_authorities.csv": f"{_OC} LIKE '%pKIEnrollmentService%'",
    "22_certificate_templates.csv": f"{_OC} LIKE '%pKICertificateTemplate%'",
    "26_bitlocker_inventory.csv": f"{_OC} LIKE '%msFVE-RecoveryInformation%'",
    "28_schema_attributes.csv": f"{_OC} LIKE '%attributeSchema%'",
    "29_custom_schema_attributes.csv": f"{_OC} LIKE '%attributeSchema%'",
}

# Keep the immediately useful identity/state columns visible and move the long
# DN to the end consistently across every live report.
for _report, _fields in AUDIT_PRESET_FIELDS.items():
    if "distinguishedName" in _fields and _fields[-1] != "distinguishedName":
        AUDIT_PRESET_FIELDS[_report] = [
            *(_field for _field in _fields if _field != "distinguishedName"),
            "distinguishedName",
        ]
for _preset in AUDIT_QUERY_PRESETS:
    _preset["attributes"] = AUDIT_PRESET_FIELDS.get(_preset["report"], DEFAULT_PRESET_FIELDS)
    _preset["prefilter"] = PRESET_PREFILTERS.get(_preset["report"])
